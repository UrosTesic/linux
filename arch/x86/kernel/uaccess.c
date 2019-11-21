#include <linux/sched.h>
#include <linux/page-flags.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <linux/slab.h>
#include <linux/rmap.h>

#ifdef CONFIG_TOCTTOU_PROTECTION

struct mutex tocttou_global_mutex;
EXPORT_SYMBOL(tocttou_global_mutex);

static bool page_mark_one(struct page *page, struct vm_area_struct *vma,
		     unsigned long address, void *arg)
{
	struct page_vma_mapped_walk pvmw = {
		.page = page,
		.vma = vma,
		.address = address,
	};
	unsigned *total;

	total = arg;

	// Find the PTE which maps the address
	//
	while (page_vma_mapped_walk(&pvmw)) {
		pte_t * ppte = pvmw.pte;

		// For a writable page, just mark as RO
		//
		if (pte_write(*ppte)) {
			printk(KERN_DEBUG "Locking W page\n");
			*ppte = pte_wrprotect(*ppte);

		// Keep track of RO pages
		//
		} else {
			struct read_only_refs_node *new_node;
			new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
			new_node->vma = vma;
			list_add(&new_node->nodes, &page->markings->read_only_list);
			printk(KERN_DEBUG "Locking RO page\n");
		}

		// Flush the TLB for every page
		//
		flush_tlb_page(vma, address);
		barrier();
		(*total)++;
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
	unsigned *total;
	total = arg;

	BUG_ON(!markings);
	// Find the PTE which maps the address
	//
	while (page_vma_mapped_walk(&pvmw)) {
		bool is_read_only = false;
		struct read_only_refs_node *iter;
		pte_t * ppte = pvmw.pte;

		BUG_ON(pte_write(*ppte));

		list_for_each_entry(iter, &markings->read_only_list, nodes) {
			if (iter->vma == vma) {
				is_read_only = true;
				break;
			}
		}

		if (!is_read_only) {
			set_pte(ppte, pte_mkwrite(*ppte));
			printk(KERN_DEBUG "Unocking W page\n");
		} else {
			printk(KERN_DEBUG "Unlocking RO page\n");
		}
		// Flush the TLB for every page
		//
		flush_tlb_page(vma, address);
		barrier();
		(*total)++;
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

	struct rmap_walk_control rwc = {
		.rmap_one = page_mark_one,
		.arg = (void *)&total,
		.anon_lock = page_lock_anon_vma_read,
	};

	// Page walk to find the page frame
	// TO DO: Replace with the visitor
	//
	pgd = pgd_offset(current->mm, vaddr);
	if (!pgd)
		return;

	p4d = p4d_offset(pgd, vaddr);
	if (!p4d)
		return;

	pud = pud_offset(p4d, vaddr);
	if (!pud)
		return;

	pmd = pmd_offset(pud, vaddr);
	if (!pmd)
		return;

	ptep = pte_offset_map(pmd, vaddr);
	if (!ptep)
		return;

	pte = *ptep;

	// Here is our page frame
	//
	target_page = pte_page(pte);

	pte_unmap(ptep);

	temp = &current->marked_pages_list;

	// Check if we have already locked this page
	//
	list_for_each_entry(iter, temp, other_nodes) {
		if (iter->marked_page == target_page) {
			pte_unmap(ptep);
			return;
		}
	}

	new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);

	BUG_ON(!new_node);

	new_node->marked_page = target_page;

	activate_page(target_page);

	mutex_lock(&tocttou_global_mutex);
	
	// Allocate and initialize the mark data
	//
	if (!target_page->markings) {
		target_page->markings = kmalloc(sizeof(*target_page->markings), GFP_KERNEL);
		INIT_TOCTTOU_PAGE_DATA(target_page->markings);
		SetPageTocttou(target_page);

		// Iterate through other pages and mark them
		total = 0;
		rmap_walk(target_page, &rwc);
		printk(KERN_DEBUG "Pages marked RO: %u\n", total);
	}
	markings = target_page->markings;

	// Increment the owners so we keep the track how many processes need to protect this page
	//
	markings->owners++;
	list_add(&new_node->other_nodes, &current->marked_pages_list);

	mutex_unlock(&tocttou_global_mutex);
}
EXPORT_SYMBOL(lock_page_from_va);
#endif

#ifdef CONFIG_TOCTTOU_PROTECTION
void unlock_pages_from_page_frame(struct page* target_page)
{
	struct tocttou_page_data *markings;
	unsigned total = 0;

	struct rmap_walk_control rwc = {
		.rmap_one = page_unmark_one,
		.arg = (void *)&total,
		.anon_lock = page_lock_anon_vma_read,
	};
	
	mutex_lock(&tocttou_global_mutex);
	

	markings = READ_ONCE(target_page->markings);
	BUG_ON(!target_page->markings);
	
	markings->owners--;
	if (!markings->owners)
	{	
		struct read_only_refs_node *iter;
		struct read_only_refs_node *temp;

		rmap_walk(target_page, &rwc);
		printk(KERN_DEBUG "Pages freed: %u\n", total);

		list_for_each_entry_safe(iter, temp, &markings->read_only_list, nodes) {
			list_del(&iter->nodes);
			kfree(iter);
		}
		target_page->markings = NULL;

		complete_all(&markings->unmarking_completed);
		ClearPageTocttou(target_page);
	}
	mutex_unlock(&tocttou_global_mutex);
}
EXPORT_SYMBOL(unlock_pages_from_page_frame);
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