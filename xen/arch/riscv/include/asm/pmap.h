#ifndef __ASM_PMAP_H__
#define __ASM_PMAP_H__

#include <xen/bug.h>
#include <xen/mm.h>

#include <asm/fixmap.h>

static inline void arch_pmap_map(unsigned int slot, mfn_t mfn)
{
    pte_t *entry = &xen_fixmap[slot];
    pte_t pte;

    ASSERT(!pte_is_valid(*entry));

    pte = mfn_to_xen_entry(mfn, PAGE_HYPERVISOR_RW);
    pte.pte |= PTE_LEAF_DEFAULT;
    write_pte(entry, pte);
}

static inline void arch_pmap_unmap(unsigned int slot)
{
    pte_t pte = {};

    write_pte(&xen_fixmap[slot], pte);
}

#endif /* __ASM_PMAP_H__ */
