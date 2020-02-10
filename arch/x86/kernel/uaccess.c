#include <linux/sched.h>
#include <linux/page-flags.h>
#include <linux/uaccess.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <linux/slab.h>
#include <linux/rmap.h>
#include <linux/mm.h>
#include "../../mm/internal.h"

__must_check unsigned long
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
EXPORT_SYMBOL(_copy_from_user_check);


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
			down_read(&current->mm->mmap_sem);

			lock_page_from_va(address);

			up_read(&current->mm->mmap_sem);
		}
		current->tocttou_syscall = 1;
	}

}


#ifdef CONFIG_TOCTTOU_PROTECTION

#define TOCTTOU_MUTEX_BITS 8
#define NUM_TOCTTOU_MUTEXES (1 << TOCTTOU_MUTEX_BITS)
#define TOCTTOU_MUTEX_MASK (NUM_TOCTTOU_MUTEXES - 1)

struct mutex tocttou_global_mutexes[NUM_TOCTTOU_MUTEXES];
void *tocttou_page_data_cache;
void *tocttou_node_cache;

void inline tocttou_mutex_init(void)
{
	int i;
	for (i = 0; i < NUM_TOCTTOU_MUTEXES, i++)
		mutex_init(&tocttou_global_mutexes[i]);
}
EXPORT_SYMBOL(tocttou_mutex_init);

void inline tocttou_cache_init(void)
{
	tocttou_page_data_cache = kmem_cache_create("tocttou_page_data", sizeof(struct tocttou_page_data), 0, 0, NULL);
	tocttou_node_cache = kmem_cache_create("tocttou_node", sizeof(struct tocttou_marked_node), 0, 0, NULL);
}
EXPORT_SYMBOL(tocttou_cache_init);

void inline lock_tocttou_mutex(struct page *page)
{
	unsigned long idx = page_to_pfn(page) & TOCTTOU_MUTEX_MASK;
	mutex_lock(&tocttou_global_mutex[idx]);
}
EXPORT_SYMBOL(lock_tocttou_mutex);

void inline unlock_tocttou_mutex(struct page *page)
{
	unsigned long idx = page_to_pfn(page) & TOCTTOU_MUTEX_MASK;
	mutex_unlock(&tocttou_global_mutex[idx]);
}
EXPORT_SYMBOL(unlock_tocttou_mutex);

struct tocttou_page_data* tocttou_page_data_alloc()
{
	return (struct tocttou_page_data*) kmem_cache_alloc(tocttou_page_data_cache, GFP_KERNEL);
}

void tocttou_page_data_free(struct tocttou_page_data* data)
{
	kmem_cache_free(tocttou_page_data_cache, data);
}

struct tocttou_marked_node* tocttou_node_alloc()
{
	return (struct tocttou_marked_node*) kmem_cache_alloc(tocttou_node_cache, GFP_KERNEL);
}

void tocttou_node_free(struct tocttou_marked_node* data)
{
	kmem_cache_free(tocttou_node_cache, data);
}


#else 

void inline tocttou_mutex_init(void) {}
void inline tocttou_cache_init(void) {}
void inline lock_tocttou_mutex(struct page*) {}
void inline unlock_tocttou_mutex(struct page*) {}

struct tocttou_page_data* tocttou_page_data_alloc(void) {}
void tocttou_page_data_free(struct tocttou_page_data* data) {}
struct tocttou_marked_node* tocttou_node_alloc(void) {}
void tocttou_node_free(struct tocttou_marked_node* data) {}

#endif

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

#ifdef CONFIG_TOCTTOU_PROTECTION
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


	new_node = tocttou_node_alloc();


	BUG_ON(!new_node);

	new_node->marked_page = target_page;

	activate_page(target_page);

	lock_tocttou_mutex(target_page);
	
	// Allocate and initialize the mark data
	//
	if (!target_page->markings) {

		target_page->markings = tocttou_page_data_alloc();

		INIT_TOCTTOU_PAGE_DATA(target_page->markings);

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

	unlock_tocttou_mutex(target_page);
}
#else
void lock_page_from_va(unsigned long addr) {}
#endif
EXPORT_SYMBOL(lock_page_from_va);


#ifdef CONFIG_TOCTTOU_PROTECTION
void unlock_pages_from_page_frame(struct page* target_page)
{
	struct tocttou_page_data *markings;

	struct rmap_walk_control rwc = {
		.rmap_one = page_unmark_one,
		.arg = NULL,
		.anon_lock = page_lock_anon_vma_read,
	};
	
	lock_tocttou_mutex(target_page);
	
	markings = READ_ONCE(target_page->markings);
	BUG_ON(!target_page->markings);
	
	markings->owners--;
	if (!markings->owners)
	{	
		struct permission_refs_node *iter;
		struct permission_refs_node *temp;
		target_page->markings = NULL;
		barrier();
		rmap_walk(target_page, &rwc);

		complete_all(&markings->unmarking_completed);
	}
	unlock_tocttou_mutex(target_page);
}
EXPORT_SYMBOL(unlock_pages_from_page_frame);
#endif