#include <uaccess.h>
// A really old file. Ignore this.

#ifdef CONFIG_TOCTTOU_PROTECTION
void lock_page_from_va(unsigned long vaddr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;
	struct page *target_page;

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

	return;
}
EXPORT_SYMBOL(unlock_page_from_va);
#endif