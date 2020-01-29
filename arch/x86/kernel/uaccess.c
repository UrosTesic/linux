#include <linux/sched.h>
#include <linux/page-flags.h>
#include <linux/uaccess.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <linux/slab.h>
#include <linux/rmap.h>
#include <linux/mm.h>
#include "../../mm/internal.h"

static inline __must_check unsigned long
_copy_from_user_check(void *to, const void __user *from, unsigned long n)
{
	unsigned long res = n;
	might_fault();
	if (likely(access_ok(from, n))) {
		mm_segment_t usr_seg = USER_DS;
		kasan_check_write(to, n);
		
		if (!__chk_range_not_ok((unsigned long) from, n, (unsigned long) usr_seg.seg))
			_mark_user_pages_read_only(from, n);

		res = raw_copy_from_user(to, from, n);
	}
	if (unlikely(res))
		memset(to + (n - res), 0, res);
	return res;
}


void
_mark_user_pages_read_only(const void __user *from, unsigned long n)
{
	unsigned long address;
	if (current->flags & PF_EXITING) {
		return;
	}
	switch (current->op_code) {
		case __NR_write:
		case __NR_futex:
		case __NR_poll:
		case __NR_select:
		case __NR_execve:
			return;
	}
	might_fault();
	if (likely(access_ok(from, n))) {
		
		for (address = (unsigned long) from & PAGE_MASK; address < (unsigned long) from + n; address += PAGE_SIZE) {
			/* Iterate through all pages and mark them as RO
			 * Add the pages to the list of pages locked by this process
			 * Save whether a page is RO */
			//if (!address) printk(KERN_ERR "from: %lx n: %lx\n", (unsigned long) from, n);
			down_read(&current->mm->mmap_sem);

			lock_page_from_va(address);

			up_read(&current->mm->mmap_sem);
		}
		current->tocttou_syscall = 1;
	}

}

unsigned long
copy_from_user(void *to, const void __user *from, unsigned long n)
{
	if (likely(check_copy_size(to, n, false)))
		n = _copy_from_user_check(to, from, n);
	return n;
}
EXPORT_SYMBOL(copy_from_user);


#ifdef CONFIG_TOCTTOU_PROTECTION

struct mutex tocttou_global_mutex;
//static spinlock_t tocttou_lock;
//static struct semaphore tocttou_sem;

void inline init_tocttou_mutex()
{
	mutex_init(&tocttou_global_mutex);
	// spin_lock_init(&tocttou_lock);
	//sema_init(&tocttou_sem, 1);
}
EXPORT_SYMBOL(init_tocttou_mutex);

void inline lock_tocttou_mutex()
{
	if (!current->tocttou_mutex_taken) {
		mutex_lock(&tocttou_global_mutex);
		current->tocttou_mutex_taken = 1;
	}
}
EXPORT_SYMBOL(lock_tocttou_mutex);

void inline unlock_tocttou_mutex()
{
	if (current->tocttou_mutex_taken) {
		mutex_unlock(&tocttou_global_mutex);
		current->tocttou_mutex_taken = 0;
	}
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
		update_mmu_cache(vma, address, ppte);
	}
	return true;
}

static bool page_unmark_one(struct page *page, struct vm_area_struct *vma,
		     unsigned long address, void *arg)
{
	pte_t entry;
	spinlock_t *ptl;
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

		// Implement R and S unmarking 

		entry = READ_ONCE(*ppte);
		unsigned smarked = !pte_user(entry);
		unsigned rmarked = !pte_rmarked(entry);
		
		if (!smarked && !rmarked) {
			continue;
		}
		if (smarked) {
			set_pte_at(vma->vm_mm, pvmw.address, pvmw.pte, pte_mkuser(entry));
		} else if (rmarked) {
			pte_t temp = pte_rtos_mark(*pvmw.pte);
			set_pte_at(vma->vm_mm, pvmw.address, pvmw.pte, pte_mkuser(entry));
		}
		// Flush the TLB for every page
		//
		flush_tlb_page(vma, address);
		update_mmu_cache(vma, address, ppte);
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
	struct vm_area_struct *vma;
	pte_t entry;
	unsigned total;
	unsigned retried = 0;

	struct rmap_walk_control rwc = {
		.rmap_one = page_mark_one,
		.arg = (void *)&total,
		.anon_lock = page_lock_anon_vma_read,
	};

	vma = find_vma(current->mm, vaddr);
	// Page walk to find the page frame
	// TO DO: Replace with the visitor
	//

	if (!vma)
		return;

retry:
    if (retried == 2) {
		//BUG();
		return;
	}

    pgd = pgd_offset(current->mm, vaddr);
	if (!pgd_present(*pgd)) {
		//printk(KERN_ERR "Retry: %lx %lx\n", (unsigned long) task_pid_nr(current), vaddr);
		up_read(&current->mm->mmap_sem);
		mm_populate(vaddr, PAGE_SIZE);
		down_read(&current->mm->mmap_sem);
		retried += 1;
		goto retry;
	}
		

	p4d = p4d_offset(pgd, vaddr);
	if (!p4d_present(*p4d)) {
		//printk(KERN_ERR "Retry: %lx %lx\n", (unsigned long) task_pid_nr(current), vaddr);
		up_read(&current->mm->mmap_sem);
		mm_populate(vaddr, PAGE_SIZE);
		down_read(&current->mm->mmap_sem);
		retried += 1;
		goto retry;
	}

	pud = pud_offset(p4d, vaddr);
	if (!pud_present(*pud)) {
		//printk(KERN_ERR "Retry: %lx %lx\n", (unsigned long) task_pid_nr(current), vaddr);
		up_read(&current->mm->mmap_sem);
		mm_populate(vaddr, PAGE_SIZE);
		down_read(&current->mm->mmap_sem);
		retried += 1;
		goto retry;
	}

	pmd = pmd_offset(pud, vaddr);
	if (!pmd_present(*pmd)) {
		//printk(KERN_ERR "Retry: %lx %lx\n", (unsigned long) task_pid_nr(current), vaddr);
		up_read(&current->mm->mmap_sem);
		mm_populate(vaddr, PAGE_SIZE);
		down_read(&current->mm->mmap_sem);
		retried += 1;
		goto retry;
	}

	ptep = pte_offset_map(pmd, vaddr);
	if (!pte_present(*ptep)) {
		pte_unmap(ptep);
		//printk(KERN_ERR "Retry: %lx %lx\n", (unsigned long) task_pid_nr(current), vaddr);
		up_read(&current->mm->mmap_sem);
		mm_populate(vaddr, PAGE_SIZE);
		down_read(&current->mm->mmap_sem);
		retried += 1;
		goto retry;
	}

	pte = *ptep;

	// Here is our page frame
	//
	target_page = pte_page(pte);

	// pte_unmap(ptep);

	temp = &current->marked_pages_list;

	if (!pte_user(*ptep) || pte_rmarked(*ptep)) {
	// Check if we have already locked this page
	//
		list_for_each_entry(iter, temp, other_nodes) {
			if (iter->marked_page == target_page) {
				return;
			}
		}
	}

	if (!in_atomic())
		new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
	else
		new_node = kmalloc(sizeof(*new_node), GFP_ATOMIC);

	BUG_ON(!new_node);

	new_node->marked_page = target_page;

	activate_page(target_page);

	lock_tocttou_mutex();
	
	// Allocate and initialize the mark data
	//
	if (!target_page->markings) {
		//printk(KERN_ERR "Mark: %lx %lx\n", (unsigned long) task_pid_nr(current), (unsigned long) target_page);
		if (!in_atomic())
			target_page->markings = kmalloc(sizeof(*target_page->markings), GFP_KERNEL);
		else
			target_page->markings = kmalloc(sizeof(*target_page->markings), GFP_ATOMIC);
		INIT_TOCTTOU_PAGE_DATA(target_page->markings);
		SetPageTocttou(target_page);
		target_page->markings->op_code = current->op_code;

		// Iterate through other pages and mark them
		total = 0;

		struct vm_area_struct *target_vma = find_vma(current->mm, vaddr);

		if (!is_cow_mapping(target_vma->vm_flags)) {
			pte_unmap(ptep);
			rmap_walk(target_page, &rwc);
		} else {
			spinlock_t *ptl = pte_lockptr(current->mm, pmd);
			spin_lock(ptl);
			entry = READ_ONCE(*ptep);
			if (!pte_user(entry) || !pte_rmarked(entry))
				set_pte_at(current->mm, vaddr, ptep, pte_userprotect(entry));
			spin_unlock(ptl);
			flush_tlb_page(vma, vaddr);
			update_mmu_cache(vma, vaddr, ptep);

			pte_unmap(ptep);
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