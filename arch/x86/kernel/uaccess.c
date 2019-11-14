#include <linux/sched.h>
#include <linux/page-flags.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <linux/slab.h>

#ifdef CONFIG_TOCTTOU_PROTECTION

struct mutex tocttou_global_mutex;
EXPORT_SYMBOL(tocttou_global_mutex);

static bool try_to_mark_one(struct page *page, struct vm_area_struct *vma,
		     unsigned long address, void *arg)
{
	struct mm_struct *mm = vma->vm_mm;
	struct page_vma_mapped_walk pvmw = {
		.page = page,
		.vma = vma,
		.address = address,
	};
	pte_t pteval;

	while (page_vma_mapped_walk(&pvmw)) {
		pte_t * ppte = pvmw->pte;
		if (!pte_write(*ppte)) {
			
		}
	}
}
void lock_page_from_va(unsigned long vaddr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;
	struct page *target_page;
	struct vm_area_struct *vma_iter;
	struct tocttou_marked_node *new_node;
	struct tocttou_marked_node *iter;
	struct list_head *temp;
	struct tocttou_page_data *markings;
	struct rmap_walk_control rwc = {
		.rmap_one = try_to_unmap_one,
		.arg = (void *)TTU_MUNLOCK,
		.done = page_not_mapped,
		.anon_lock = page_lock_anon_vma_read,
	};

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

	target_page = pte_page(pte);

	temp = &current->marked_pages_list;

	list_for_each_entry(iter, temp, other_nodes) {
		if (iter->marked_page == target_page) {
			pte_unmap(ptep);
			return;
		}
	}

	new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);

	BUG_ON(!new_node);

	new_node->marked_page = target_page;
	new_node->vaddr = vaddr;

	activate_page(target_page);

	mutex_lock(&tocttou_global_mutex);
	
	if (!target_page->markings) {
		target_page->markings = kmalloc(sizeof(*target_page->markings), GFP_KERNEL);
		INIT_TOCTTOU_PAGE_DATA(&target_page->markings);
		SetPageTocttou(target_page);

		// Iterate through other pages and mark them
	}
	markings = target_page->markings;
	markings->owners++;

	list_add(&new_node->other_nodes, &current->marked_pages_list);

	mutex_unlock(&tocttou_global_mutex);
	
	*ptep = pte_wrprotect(pte);
	pte_unmap(ptep);

	for (vma_iter = current->mm->mmap; vaddr < vma_iter->vm_start; vma_iter = vma_iter->vm_next) {}

	BUG_ON(!vma_iter);

	flush_tlb_page(vma_iter, vaddr); 
	barrier();
}
EXPORT_SYMBOL(lock_page_from_va);
#endif

#ifdef CONFIG_TOCTTOU_PROTECTION
void unlock_page_from_va(unsigned long vaddr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;
	struct page *target_page;
	struct vm_area_struct* vma_iter;

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

	target_page = pte_page(pte);
	
	// TO DO: Add a list of permissions. Current version only restores the current VA permissions.
	//
	mutex_lock(&tocttou_global_mutex);
	target_page->tocttou_refs--;
	if (target_page->tocttou_refs == 0)
	{	
		ClearPageTocttou(target_page);

		if (target_page->old_write_perm)
			*ptep = pte_mkwrite(pte);
		else
			*ptep = pte_wrprotect(pte);
		
		for (vma_iter = current->mm->mmap; vaddr < vma_iter->vm_start; vma_iter = vma_iter->vm_next) {}

		BUG_ON(vma_iter == NULL);

		flush_tlb_page(vma_iter, vaddr);
		barrier();

		complete_all(&target_page->tocttou_protection);
	}
	mutex_unlock(&tocttou_global_mutex);

	pte_unmap(ptep);
}
EXPORT_SYMBOL(unlock_page_from_va);
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
				unlock_page_from_va(address);
				up_read(&current->mm->mmap_sem);
			}
		}
	}
}
EXPORT_SYMBOL(copy_from_user_unlock);
#endif