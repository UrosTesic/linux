#include <linux/sched.h>
#include <linux/page-flags.h>
#include <linux/uaccess.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <linux/slab.h>
#include <linux/rmap.h>
#include <linux/mm.h>
#include <linux/interval_tree.h>
#include "../../mm/internal.h"
#include <uapi/asm/unistd_64.h>

__attribute__((optimize("-Og"))) unsigned long __must_check
raw_copy_to_user(void __user *to, const void *from, unsigned long n)
{
	unsigned long bytes_left;
	unsigned long start;
	unsigned long end;
	unsigned long write_to;
	unsigned long read_from;
	struct interval_tree_node *check;

	//printk(KERN_ERR"%u Copy_to_user Start\n", current->pid);
	write_to = (unsigned long) to;
	read_from = (unsigned long) from;

	start = (unsigned long) to;
	end = (unsigned long) to + n;

	bytes_left = 0;

	if (false && current->mm && current->op_code != -1) {
		mutex_lock(&current->mm->marked_ranges_mutex);
		check = interval_tree_iter_first(&current->mm->marked_ranges_root, start, end-1);

		while (check) {
			
			if (write_to < check->start) {
				unsigned long local_end = min(end, check->start);
				unsigned long write_length = local_end - write_to;

				bytes_left += __raw_copy_to_user((void *)write_to, (void *) read_from, write_length);
				write_to += write_length;
				read_from += write_length;
			}

			{
				struct tocttou_deferred_write *new_node;
				unsigned long local_end = min(end, check->last + 1);
				unsigned long write_length = local_end - write_to;

				void* temp_data = kmalloc(write_length, GFP_KERNEL);

				memcpy(temp_data, (void*) read_from, write_length);

				new_node = tocttou_deferred_write_alloc();
				new_node->address = write_to;
				new_node->length = write_length;
				new_node->data = temp_data;

				list_add_tail(&new_node->other_nodes, &current->deferred_writes_list);

				write_to += write_length;
				read_from += write_length;
				bytes_left += write_length;
			}

			check = interval_tree_iter_next(check, start, end-1);
		}
		mutex_unlock(&current->mm->marked_ranges_mutex);
	}

	if (write_to < end) {
		unsigned long write_length = end - write_to;

		bytes_left += __raw_copy_to_user((void *) write_to, (void *) read_from, write_length);
		write_to += write_length;
		read_from += write_length;

	}

	// uaccprintk(KERN_ERR"%u Copy_to_user End\n", current->pid);
	return bytes_left;
}
EXPORT_SYMBOL(raw_copy_to_user);

#if defined (CONFIG_TOCTTOU_PROTECTION) && !defined(INLINE_COPY_FROM_USER)
__must_check unsigned long
_copy_from_user(void *to, const void __user *from, unsigned long n)
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
EXPORT_SYMBOL(_copy_from_user);
#endif

void
_mark_user_pages_read_only(const void __user *from, unsigned long n)
{
	unsigned long address;
	struct vm_area_struct *vma;

	return;
	
	if (!current->pid)
		return;

	if (current->flags & PF_EXITING) {
		return;
	}
	switch (current->op_code) {
		case __NR_write:
		case __NR_futex:
		case __NR_poll:
		case __NR_select:
		case __NR_execve:
		case __NR_writev:
		case __NR_pwrite64:
		case __NR_pwritev2:
		case __NR_finit_module:
		case __NR_exit:
		case -1:
			return;
	}
	vma = find_vma(current->mm, (unsigned long) from);
	might_fault();
	if (likely(access_ok(from, n))) {
		
		for (address = (unsigned long) from & PAGE_MASK; address < (unsigned long) from + n; address += PAGE_SIZE) {
			/* Iterate through all pages and mark them as RO
			 * Add the pages to the list of pages locked by this process
			 * Save whether a page is RO */
			if (address >= vma->vm_end) vma = vma->vm_next;
			if (!vma) break;

			if (vma->vm_file && (vma->vm_flags & VM_SHARED)) tocttou_file_mark_start(vma->vm_file);
				
			down_read(&current->mm->mmap_sem);

			lock_page_from_va(address);

			up_read(&current->mm->mmap_sem);
		}
		current->tocttou_syscall = 1;
	}

}


#ifdef CONFIG_TOCTTOU_PROTECTION

#define TOCTTOU_MUTEX_BITS 4
#define NUM_TOCTTOU_MUTEXES (1 << TOCTTOU_MUTEX_BITS)
#define TOCTTOU_MUTEX_MASK (NUM_TOCTTOU_MUTEXES - 1)

struct mutex tocttou_global_mutexes[NUM_TOCTTOU_MUTEXES];
struct list_head tocttou_global_structs[NUM_TOCTTOU_MUTEXES];
void *tocttou_page_data_cache;
void *tocttou_node_cache;
void *tocttou_file_cache;
void *tocttou_deferred_write_cache;
void *tocttou_interval_cache;

void inline tocttou_mutex_init(void)
{
	int i;
	for (i = 0; i < NUM_TOCTTOU_MUTEXES; i++) {
		mutex_init(&tocttou_global_mutexes[i]);
		INIT_LIST_HEAD(&tocttou_global_structs[i]);
	}
}
EXPORT_SYMBOL(tocttou_mutex_init);

void inline tocttou_cache_init(void)
{
	tocttou_page_data_cache = kmem_cache_create("tocttou_page_data", sizeof(struct tocttou_page_data), 0, 0, NULL);
	tocttou_node_cache = kmem_cache_create("tocttou_node", sizeof(struct tocttou_marked_node), 0, 0, NULL);
	tocttou_file_cache = kmem_cache_create("tocttou_file_node", sizeof(struct tocttou_marked_file), 0, 0, NULL);
	tocttou_deferred_write_cache = kmem_cache_create("tocttou_deferred_write", sizeof(struct tocttou_deferred_write), 0, 0, NULL);
	tocttou_interval_cache = kmem_cache_create("tocttou_interval", sizeof(struct interval_tree_node), 0, 0, NULL);
}
EXPORT_SYMBOL(tocttou_cache_init);

void inline lock_tocttou_mutex(struct page *page)
{
	unsigned long idx = page_to_pfn(page) & TOCTTOU_MUTEX_MASK;
	mutex_lock(&tocttou_global_mutexes[idx]);
}
EXPORT_SYMBOL(lock_tocttou_mutex);

void inline unlock_tocttou_mutex(struct page *page)
{
	unsigned long idx = page_to_pfn(page) & TOCTTOU_MUTEX_MASK;
	mutex_unlock(&tocttou_global_mutexes[idx]);
}
EXPORT_SYMBOL(unlock_tocttou_mutex);

struct interval_tree_node * tocttou_interval_alloc()
{
	return (struct interval_tree_node *) kmem_cache_alloc(tocttou_interval_cache, GFP_KERNEL);
}

void tocttou_interval_free(struct interval_tree_node *node)
{
	kmem_cache_free(tocttou_interval_cache, node);
}
struct tocttou_deferred_write *tocttou_deferred_write_alloc()
{
	return (struct tocttou_deferred_write *) kmem_cache_alloc(tocttou_deferred_write_cache, GFP_KERNEL);
}

void tocttou_deferred_write_free(struct tocttou_deferred_write * data)
{
	kmem_cache_free(tocttou_deferred_write_cache, data);
}

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

struct tocttou_marked_file* tocttou_marked_file_alloc()
{
	return (struct tocttou_marked_file *) kmem_cache_alloc(tocttou_file_cache, GFP_KERNEL);
}

void tocttou_marked_file_free(struct tocttou_marked_file *data)
{
	kmem_cache_free(tocttou_file_cache, data);
}

void tocttou_file_write_start(struct file *file)
{
	down_write(&file->f_mapping->host->i_tocttou_sem);
}

void tocttou_file_write_end(struct file *file)
{
	up_write(&file->f_mapping->host->i_tocttou_sem);
}

void tocttou_file_mark_start(struct file *file)
{
	struct rw_semaphore *sem = &file->f_mapping->host->i_tocttou_sem;
	struct tocttou_marked_file *iter;

	list_for_each_entry(iter, &current->marked_files_list, other_nodes) {
		if (iter->sem == sem)
			return;
	}

	struct tocttou_marked_file *new_node = tocttou_marked_file_alloc();
	new_node->sem = sem;
	list_add(&new_node->other_nodes, &current->marked_files_list);
	down_read(sem);
}

void tocttou_file_mark_end(struct rw_semaphore *sem)
{
	up_read(sem);
}

void tocttou_unmark_all_files()
{
	struct tocttou_marked_file *iter;
	struct tocttou_marked_file *temp;

	list_for_each_entry_safe(iter, temp, &current->marked_files_list, other_nodes) {
		up_read(iter->sem);
		list_del(&iter->other_nodes);
		tocttou_marked_file_free(iter);
	}
}

struct tocttou_page_data* get_page_markings(struct page* page)
{
	struct tocttou_page_data *ptr;

	if (!is_page_tocttou(page))
		return NULL;

	unsigned long pfn = page_to_pfn(page);
	unsigned long idx = page_to_pfn(page) & TOCTTOU_MUTEX_MASK;
	
	list_for_each_entry(ptr, &tocttou_global_structs[idx], other_nodes) {
		if (ptr->pfn == pfn)
			return ptr;
	}
	return NULL;
}

struct tocttou_page_data* remove_page_markings(struct page* page)
{
	struct tocttou_page_data *ptr;
	struct tocttou_page_data *temp;

	if (!is_page_tocttou(page))
		return NULL;

	unsigned long pfn = page_to_pfn(page);
	unsigned long idx = page_to_pfn(page) & TOCTTOU_MUTEX_MASK;
	
	clear_page_tocttou(page);
	list_for_each_entry_safe(ptr, temp, &tocttou_global_structs[idx], other_nodes) {
		if (ptr->pfn == pfn){
			list_del(&ptr->other_nodes);
			return ptr;
		}
	}
	BUG();
	return NULL;
}

void add_page_markings(struct page* page, struct tocttou_page_data* data)
{
	unsigned long pfn = page_to_pfn(page);
	unsigned long idx = page_to_pfn(page) & TOCTTOU_MUTEX_MASK;

	set_page_tocttou(page);
	data->pfn = pfn;
	list_add(&data->other_nodes, &tocttou_global_structs[idx]);
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
	struct interval_tree_node **preallocated_range = (struct interval_tree_node **) arg;
	struct page_vma_mapped_walk pvmw = {
		.page = page,
		.vma = vma,
		.address = address,
	};

	if (is_cow_mapping(vma->vm_flags)) return true;
	// Find the PTE which maps the address
	//
	mutex_lock(&vma->vm_mm->marked_ranges_mutex);
	while (page_vma_mapped_walk(&pvmw)) {
		struct interval_tree_node *new_range = *preallocated_range;
		*preallocated_range = NULL;
		new_range->start = address;
		new_range->last = address + PAGE_SIZE - 1;
		// printk(KERN_ERR "Mark %u: %lx - %lx\n", current->pid, new_range->start, new_range->last);

		
		interval_tree_insert(new_range, &vma->vm_mm->marked_ranges_root);
		pte_t * ppte = pvmw.pte;
		set_pte_at(vma->vm_mm, pvmw.address, ppte, pte_rmark(*ppte));

		// Flush the TLB for every page
		//
		flush_tlb_page(vma, address);
		update_mmu_cache(vma, address, ppte);
	}
	mutex_unlock(&vma->vm_mm->marked_ranges_mutex);
	if (!*preallocated_range) {
		*preallocated_range = tocttou_interval_alloc();
	}
	return true;
}

static bool page_unmark_one(struct page *page, struct vm_area_struct *vma,
		     unsigned long address, void *arg) 
{
	pte_t entry;
	spinlock_t *ptl;
	struct tocttou_page_data *markings;
	struct page_vma_mapped_walk pvmw = {
		.page = page,
		.vma = vma,
		.address = address,
	};

	BUG_ON(!is_page_tocttou(page));

	markings = get_page_markings(page);
	// Find the PTE which maps the address
	//
	mutex_lock(&vma->vm_mm->marked_ranges_mutex);
	while (page_vma_mapped_walk(&pvmw)) {
		struct interval_tree_node *range;
		pte_t * ppte = pvmw.pte;

		// R unmarking
		entry = *ppte;
		unsigned rmarked = pte_rmarked(entry);

		
		if (pte_rmarked(*pvmw.pte)) {
	
			pte_t temp = pte_runmark(*pvmw.pte);
			set_pte_at(vma->vm_mm, pvmw.address, pvmw.pte, temp);
		
			// Flush the TLB for every page
			//
			flush_tlb_page(vma, address);
			update_mmu_cache(vma, address, ppte);
		
			// printk(KERN_ERR "Unmark %u: %lx - %lx\n", current->pid, pvmw.address, pvmw.address + PAGE_SIZE - 1);
			
			range = interval_tree_iter_first(&vma->vm_mm->marked_ranges_root, pvmw.address, pvmw.address + PAGE_SIZE - 1);
			// printk(KERN_ERR "Range: %p\n", range);
			if (!range) {
				BUG();
			}
			interval_tree_remove(range, &vma->vm_mm->marked_ranges_root);
			tocttou_interval_free(range);
		}
		
	}
	mutex_unlock(&vma->vm_mm->marked_ranges_mutex);
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
	unsigned retried = 0;

	struct rmap_walk_control rwc = {
		.rmap_one = page_mark_one,
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

	activate_page(target_page);

	temp = &current->marked_pages_list;

	if (pte_rmarked(*ptep)) {
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


	lock_tocttou_mutex(target_page);
	
	// Allocate and initialize the mark data
	//
	if (!is_page_tocttou(target_page)) {
		markings = tocttou_page_data_alloc();

		INIT_TOCTTOU_PAGE_DATA(markings);

		add_page_markings(target_page, markings);
		markings->op_code = current->op_code;


		struct vm_area_struct *target_vma = find_vma(current->mm, vaddr);

		if (!is_cow_mapping(target_vma->vm_flags)) {
			struct interval_tree_node *new_range = tocttou_interval_alloc();
			pte_unmap(ptep);
			rwc.arg = &new_range;
			rmap_walk(target_page, &rwc);
			tocttou_interval_free(new_range);
		} else {
			int rmarked;
			struct interval_tree_node *new_range = tocttou_interval_alloc();
			mutex_lock(&vma->vm_mm->marked_ranges_mutex);
			spinlock_t *ptl = pte_lockptr(current->mm, pmd);
			spin_lock(ptl);

			entry = *(volatile pte_t *)ptep;
			rmarked = pte_rmarked(entry);
			// If the pte hasn't been marked already
			if (!rmarked) {
				new_range->start = vaddr;
				new_range->last = vaddr + PAGE_SIZE - 1;
				// printk(KERN_ERR "Mark %u: %lx - %lx\n", current->pid, new_range->start, new_range->last);

				
				interval_tree_insert(new_range, &vma->vm_mm->marked_ranges_root);

				set_pte_at(current->mm, vaddr, ptep, (pte_rmark(entry)));

			}
			spin_unlock(ptl);

			flush_tlb_page(vma, vaddr);
			update_mmu_cache(vma, vaddr, ptep);
			mutex_unlock(&vma->vm_mm->marked_ranges_mutex);

			if (rmarked)
				tocttou_interval_free(new_range);
			pte_unmap(ptep);
		}
	} else {
		markings = get_page_markings(target_page);
	}

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
__attribute__((optimize("-Og"))) void tocttou_perform_deferred_writes()
{
	struct tocttou_deferred_write *iter, *temp;
	struct list_head *list = &current->deferred_writes_list;

	list_for_each_entry_safe(iter, temp, list, other_nodes) {
		printk(KERN_ERR"Deferred write started: %u %ld %lx-%lx\n", current->pid, current->op_code, iter->address, iter->address + iter->length);
		__raw_copy_to_user((void*)iter->address, iter->data, iter->length);
		list_del(&iter->other_nodes);
		kfree(iter->data);
		printk(KERN_ERR"Deferred write finished: %u %ld %lx-%lx\n", current->pid, current->op_code, iter->address, iter->address + iter->length);
		tocttou_deferred_write_free(iter);
		
	}
}
EXPORT_SYMBOL(tocttou_perform_deferred_writes);
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
	
	lock_tocttou_mutex(target_page);
	
	BUG_ON(!is_page_tocttou(target_page));
	markings = get_page_markings(target_page);
	
	markings->owners--;
	if (!markings->owners)
	{	
		struct permission_refs_node *iter;
		struct permission_refs_node *temp;
		barrier();
		rmap_walk(target_page, &rwc);
		remove_page_markings(target_page);

		complete_all(&markings->unmarking_completed);
	}
	unlock_tocttou_mutex(target_page);
}
EXPORT_SYMBOL(unlock_pages_from_page_frame);
#endif