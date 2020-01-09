#include <linux/sched.h>
#include <linux/page-flags.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <linux/slab.h>
#include <linux/rmap.h>
#include <linux/mm.h>
#include "../../mm/internal.h"

#ifdef CONFIG_TOCTTOU_PROTECTION

struct mutex tocttou_global_mutex;

void inline init_tocttou_mutex()
{
	mutex_init(&tocttou_global_mutex);
}
EXPORT_SYMBOL(init_tocttou_mutex);

void inline lock_tocttou_mutex()
{
	mutex_lock(&tocttou_global_mutex);
}
EXPORT_SYMBOL(lock_tocttou_mutex);

void inline unlock_tocttou_mutex()
{
	mutex_unlock(&tocttou_global_mutex);
}
EXPORT_SYMBOL(unlock_tocttou_mutex);

static bool page_mark_one(struct page *page, struct vm_area_struct *vma,
		     unsigned long address, void *arg)
{
	struct page_vma_mapped_walk pvmw = {
		.page = page,
		.vma = vma,
		.address = address,
	};

	if (is_cow_mapping(vma->vm_flags)) return true;
	// Find the PTE which maps the address
	//
	while (page_vma_mapped_walk(&pvmw)) {
		pte_t * ppte = pvmw.pte;

		set_pte_at(vma->vm_mm, pvmw.address, ppte, pte_userprotect(*ppte));

		// Flush the TLB for every page
		//
		flush_tlb_page(vma, address);
		barrier();
	}
	return true;
}

static bool page_unmark_one(struct page *page, struct vm_area_struct *vma,
		     unsigned long address, void *arg)
{
	struct tocttou_page_data *markings = page->markings;
	struct page_vma_mapped_walk pvmw = {
		.page = page,
		.vma = vma,
		.address = address,
	};


	BUG_ON(!markings);
	// Find the PTE which maps the address
	//
	while (page_vma_mapped_walk(&pvmw)) {
		struct permission_refs_node *iter;
		pte_t * ppte = pvmw.pte;

		if (pte_user(*ppte)) continue;

		set_pte_at(vma->vm_mm, pvmw.address, pvmw.pte, pte_mkuser(*pvmw.pte));

		// Flush the TLB for every page
		//
		flush_tlb_page(vma, address);
		barrier();
	}
	return true;
}

void lock_page_from_va(unsigned long vaddr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;
	struct page *target_page;
	struct tocttou_marked_node *new_node;
	struct tocttou_marked_node *iter;
	struct list_head *temp;
	struct tocttou_page_data *markings;
	unsigned total;
	unsigned retried = 0;

	struct rmap_walk_control rwc = {
		.rmap_one = page_mark_one,
		.arg = (void *)&total,
		.anon_lock = page_lock_anon_vma_read,
	};

	// Page walk to find the page frame
	// TO DO: Replace with the visitor
	//

retry:
    if (retried) {
		BUG();
		return;
	}

    pgd = pgd_offset(current->mm, vaddr);
	if (!pgd_present(*pgd)) {
		printk(KERN_ERR "Retry: %lx %lx\n", (unsigned long) task_pid_nr(current), vaddr);
		mm_populate(vaddr, PAGE_SIZE);
		retried = 1;
		goto retry;
	}
		

	p4d = p4d_offset(pgd, vaddr);
	if (!p4d_present(*p4d)) {
		printk(KERN_ERR "Retry: %lx %lx\n", (unsigned long) task_pid_nr(current), vaddr);
		mm_populate(vaddr, PAGE_SIZE);
		retried = 1;
		goto retry;
	}

	pud = pud_offset(p4d, vaddr);
	if (!pud_present(*pud)) {
		printk(KERN_ERR "Retry: %lx %lx\n", (unsigned long) task_pid_nr(current), vaddr);
		mm_populate(vaddr, PAGE_SIZE);
		retried = 1;
		goto retry;
	}

	pmd = pmd_offset(pud, vaddr);
	if (!pmd_present(*pmd)) {
		printk(KERN_ERR "Retry: %lx %lx\n", (unsigned long) task_pid_nr(current), vaddr);
		mm_populate(vaddr, PAGE_SIZE);
		retried = 1;
		goto retry;
	}

	ptep = pte_offset_map(pmd, vaddr);
	if (!pte_present(*ptep)) {
		pte_unmap(ptep);
		printk(KERN_ERR "Retry: %lx %lx\n", (unsigned long) task_pid_nr(current), vaddr);
		mm_populate(vaddr, PAGE_SIZE);
		retried = 1;
		goto retry;
	}

	pte = *ptep;

	// Here is our page frame
	//
	target_page = pte_page(pte);

	// pte_unmap(ptep);

	temp = &current->marked_pages_list;

	if (!pte_user(*ptep)) {
	// Check if we have already locked this page
	//
		list_for_each_entry(iter, temp, other_nodes) {
			if (iter->marked_page == target_page) {
				return;
			}
		}
	}

	new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);

	BUG_ON(!new_node);

	new_node->marked_page = target_page;

	activate_page(target_page);

	lock_tocttou_mutex();
	
	// Allocate and initialize the mark data
	//
	if (!target_page->markings) {
		//printk(KERN_ERR "Mark: %lx %lx\n", (unsigned long) task_pid_nr(current), (unsigned long) target_page);
		target_page->markings = kmalloc(sizeof(*target_page->markings), GFP_KERNEL);
		INIT_TOCTTOU_PAGE_DATA(target_page->markings);
		SetPageTocttou(target_page);

		// Iterate through other pages and mark them
		total = 0;

		struct vm_area_struct *target_vma = find_vma(current->mm, vaddr);

		if (!is_cow_mapping(target_vma->vm_flags)) {
			pte_unmap(ptep);
			rmap_walk(target_page, &rwc);
		} else {
			set_pte_at(current->mm, vaddr, ptep, pte_userprotect(*ptep));
		}
	}
	markings = target_page->markings;

	// Increment the owners so we keep the track how many processes need to protect this page
	//
	markings->owners++;
	list_add(&new_node->other_nodes, &current->marked_pages_list);

	unlock_tocttou_mutex();
}
EXPORT_SYMBOL(lock_page_from_va);
#endif

#ifdef CONFIG_TOCTTOU_PROTECTION
void unlock_pages_from_page_frame(struct page* target_page)
{
	struct tocttou_page_data *markings;

	struct rmap_walk_control rwc = {
		.rmap_one = page_unmark_one,
		.arg = NULL,
		.anon_lock = page_lock_anon_vma_read,
	};

	//printk(KERN_ERR "Unmark: %lx\n", (unsigned long) (target_page));
	
	lock_tocttou_mutex();
	
	markings = READ_ONCE(target_page->markings);
	BUG_ON(!target_page->markings);
	
	markings->owners--;
	if (!markings->owners)
	{	
		struct permission_refs_node *iter;
		struct permission_refs_node *temp;

		rmap_walk(target_page, &rwc);

		target_page->markings = NULL;

		complete_all(&markings->unmarking_completed);
		ClearPageTocttou(target_page);
	}
	unlock_tocttou_mutex();
}
EXPORT_SYMBOL(unlock_pages_from_page_frame);
#endif

#ifdef CONFIG_TOCTTOU_PROTECTION
int remove_vma_from_markings(struct tocttou_page_data *markings, struct vm_area_struct *vma)
{
	struct permission_refs_node *iter;
	struct permission_refs_node *temp;
	list_for_each_entry_safe(iter, temp, &markings->old_permissions_list, nodes) {
		if (iter->vma == vma) {
			list_del(&iter->nodes);
			kfree(iter);
			return 0;
		}
	}
	return 1;
}
EXPORT_SYMBOL(remove_vma_from_markings);

int substitute_vma_in_markings(struct tocttou_page_data *markings, struct vm_area_struct *old_vma, struct vm_area_struct *new_vma)
{
	struct permission_refs_node *iter;
	list_for_each_entry(iter, &markings->old_permissions_list, nodes) {
		if (iter->vma == old_vma) {
			iter->vma = new_vma;
			return 0;
		}
	}
	return 1;
}
EXPORT_SYMBOL(substitute_vma_in_markings);

struct permission_refs_node* find_vma_in_markings(struct tocttou_page_data *markings, struct vm_area_struct *vma)
{
	struct permission_refs_node *iter;
	list_for_each_entry(iter, &markings->old_permissions_list, nodes) {
		if (iter->vma == vma) {
			return iter;
		}
	}
	return NULL;
}
EXPORT_SYMBOL(find_vma_in_markings);
#endif

#ifdef CONFIG_TOCTTOU_PROTECTION
/*__always_inline*/ void 
copy_from_user_unlock(const void __user *from, unsigned long n)
{
	unsigned long res = n;
	unsigned long address;
	might_fault();
	printk("trace1\n");
	if (likely(access_ok(from, res))) {
		printk("trace2\n");
		if (1) {
			printk("trace3\n");
			for (address = (unsigned long) from & PAGE_MASK; address < (unsigned long) from + n; address += PAGE_SIZE) {
				printk("trace4\n");
				printk("%lx", address);
				down_read(&current->mm->mmap_sem);
				//unlock_page_from_va(address);
				up_read(&current->mm->mmap_sem);
			}
		}
	}
}
EXPORT_SYMBOL(copy_from_user_unlock);
#endif