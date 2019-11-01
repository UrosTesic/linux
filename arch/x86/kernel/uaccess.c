#include <linux/sched.h>
#include <linux/page-flags.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#ifdef CONFIG_TOCTTOU_PROTECTION
__attribute__((optimize("O0"))) void lock_page_from_va(unsigned long vaddr)
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
	activate_page(target_page);

	if (atomic_inc_return(&target_page->tocttou_refs) == 1) {
		target_page->old_write_perm = pte_write(pte);
		SetPageTocttou(target_page);
		reinit_completion(&target_page->tocttou_protection);
	}
	
	*ptep = pte_wrprotect(pte);
	pte_unmap(ptep);

	for (vma_iter = current->mm->mmap; vaddr < vma_iter->vm_start; vma_iter = vma_iter->vm_next) {}

	BUG_ON(vma_iter == NULL);

	flush_tlb_page(vma_iter, vaddr); 
	barrier();
}
EXPORT_SYMBOL(lock_page_from_va);
#endif

#ifdef CONFIG_TOCTTOU_PROTECTION
__attribute__((optimize("O0"))) void unlock_page_from_va(unsigned long vaddr)
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
	if (atomic_dec_and_test(&target_page->tocttou_refs))
	{	
		ClearPageTocttou(target_page);
		if (target_page->old_write_perm)
			*ptep = pte_mkwrite(pte);
		else
			*ptep = pte_wrprotect(pte);

		complete_all(&target_page->tocttou_protection);
	}

	pte_unmap(ptep);

	for (vma_iter = current->mm->mmap; vaddr < vma_iter->vm_start; vma_iter = vma_iter->vm_next) {}

	BUG_ON(vma_iter == NULL);

	flush_tlb_page(vma_iter, vaddr);
	barrier();
}
EXPORT_SYMBOL(unlock_page_from_va);
#endif

#ifdef CONFIG_TOCTTOU_PROTECTION
/*__always_inline*/ __attribute__((optimize("O0"))) void 
copy_from_user_unlock(const void __user *from, unsigned long n)
{
	unsigned long res = n;
	unsigned long address;
	might_fault();
	if (likely(access_ok(from, res))) {
		if (current->tocttou_syscall) {
			for (address = (unsigned long) from & PAGE_MASK; address < (unsigned long) from + n; address += PAGE_SIZE) {
				down_read(&current->mm->mmap_sem);
				unlock_page_from_va(address);
				up_read(&current->mm->mmap_sem);
			}
		}
	}
}
EXPORT_SYMBOL(copy_from_user_unlock);
#endif