/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _ASM_RISCV_PAGE_H
#define _ASM_RISCV_PAGE_H

#ifndef __ASSEMBLY__

#include <xen/const.h>
#include <xen/types.h>

#include <asm/mm.h>
#include <asm/page-bits.h>

#define pfn_to_paddr(pfn) ((paddr_t)(pfn) << PAGE_SHIFT)
#define paddr_to_pfn(pa)  ((unsigned long)((pa) >> PAGE_SHIFT))

#define VPN_MASK                    (PAGETABLE_ENTRIES - 1UL)

#define XEN_PT_LEVEL_ORDER(lvl)     ((lvl) * PAGETABLE_ORDER)
#define XEN_PT_LEVEL_SHIFT(lvl)     (XEN_PT_LEVEL_ORDER(lvl) + PAGE_SHIFT)
#define XEN_PT_LEVEL_SIZE(lvl)      (_AT(paddr_t, 1) << XEN_PT_LEVEL_SHIFT(lvl))
#define XEN_PT_LEVEL_MAP_MASK(lvl)  (~(XEN_PT_LEVEL_SIZE(lvl) - 1))
#define XEN_PT_LEVEL_MASK(lvl)      (VPN_MASK << XEN_PT_LEVEL_SHIFT(lvl))

#define PTE_VALID                   BIT(0, UL)
#define PTE_READABLE                BIT(1, UL)
#define PTE_WRITABLE                BIT(2, UL)
#define PTE_EXECUTABLE              BIT(3, UL)
#define PTE_USER                    BIT(4, UL)
#define PTE_GLOBAL                  BIT(5, UL)
#define PTE_ACCESSED                BIT(6, UL)
#define PTE_DIRTY                   BIT(7, UL)
#define PTE_RSW                     (BIT(8, UL) | BIT(9, UL))

#define PTE_LEAF_DEFAULT            (PTE_VALID | PTE_READABLE | PTE_WRITABLE)
#define PTE_TABLE                   (PTE_VALID)

/* Calculate the offsets into the pagetables for a given VA */
#define pt_linear_offset(lvl, va)   ((va) >> XEN_PT_LEVEL_SHIFT(lvl))

#define pt_index(lvl, va) (pt_linear_offset((lvl), (va)) & VPN_MASK)

#define clear_page(pgaddr)			memset((pgaddr), 0, PAGE_SIZE)
#define copy_page(to, from)			memcpy((to), (from), PAGE_SIZE)

/*
 * Attribute Indexes.
 *
 */
#define MT_NORMAL        0x0

#define _PAGE_XN_BIT    3
#define _PAGE_RO_BIT    4
#define _PAGE_XN    (1U << _PAGE_XN_BIT)
#define _PAGE_RO    (1U << _PAGE_RO_BIT)
#define PAGE_XN_MASK(x) (((x) >> _PAGE_XN_BIT) & 0x1U)
#define PAGE_RO_MASK(x) (((x) >> _PAGE_RO_BIT) & 0x1U)

/*
 * _PAGE_DEVICE and _PAGE_NORMAL are convenience defines. They are not
 * meant to be used outside of this header.
 */
#define _PAGE_DEVICE    _PAGE_XN
#define _PAGE_NORMAL    MT_NORMAL

#define PAGE_HYPERVISOR_RO      (_PAGE_NORMAL|_PAGE_RO|_PAGE_XN)
#define PAGE_HYPERVISOR_RX      (_PAGE_NORMAL|_PAGE_RO)
#define PAGE_HYPERVISOR_RW      (_PAGE_NORMAL|_PAGE_XN)

#define PAGE_HYPERVISOR         PAGE_HYPERVISOR_RW
#define PAGE_HYPERVISOR_NOCACHE (_PAGE_DEVICE)
#define PAGE_HYPERVISOR_WC      (_PAGE_DEVICE)

/* Invalidate all instruction caches in Inner Shareable domain to PoU */
static inline void invalidate_icache(void)
{
    asm volatile ("fence.i" ::: "memory");
}

/* Page Table entry */
typedef struct {
#ifdef CONFIG_RISCV_64
    uint64_t pte;
#else
    uint32_t pte;
#endif
} pte_t;

static inline pte_t paddr_to_pte(paddr_t paddr,
                                 unsigned int permissions)
{
    return (pte_t) { .pte = (paddr_to_pfn(paddr) << PTE_PPN_SHIFT) | permissions };
}

static inline paddr_t pte_to_paddr(pte_t pte)
{
    return pfn_to_paddr(pte.pte >> PTE_PPN_SHIFT);
}

static inline bool pte_is_valid(pte_t p)
{
    return p.pte & PTE_VALID;
}

#define PAGE_ALIGN(x) (((x) + PAGE_SIZE - 1) & PAGE_MASK)

/* Flush the dcache for an entire page. */
void flush_page_to_ram(unsigned long mfn, bool sync_icache);

/* Write a pagetable entry. */
static inline void write_pte(pte_t *p, pte_t pte)
{
    *p = pte;
    asm volatile ("sfence.vma");
}

#endif /* __ASSEMBLY__ */

#endif /* _ASM_RISCV_PAGE_H */
