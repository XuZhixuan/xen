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

#define PTE_LEAF_DEFAULT            (PTE_VALID | PTE_READABLE | PTE_WRITABLE | PTE_ACCESSED | PTE_DIRTY)
#define PTE_TABLE                   (PTE_VALID)

/* Calculate the offsets into the pagetables for a given VA */
#define pt_linear_offset(lvl, va)   ((va) >> XEN_PT_LEVEL_SHIFT(lvl))

#define pt_index(lvl, va) (pt_linear_offset((lvl), (va)) & VPN_MASK)

#define FIRST_SIZE (XEN_PT_LEVEL_SIZE(2))

#define TABLE_OFFSET(offs) (_AT(unsigned int, offs) & ((_AC(1, U) << PAGETABLE_ORDER) - 1))
#define l0_table_offset(va)  TABLE_OFFSET(pt_linear_offset(0, va))
#define l1_table_offset(va)  TABLE_OFFSET(pt_linear_offset(1, va))
#define l2_table_offset(va) TABLE_OFFSET(pt_linear_offset(2, va))
#define l3_table_offset(va)  TABLE_OFFSET(pt_linear_offset(3, va))

/* Generate an array @var containing the offset for each level from @addr */
#define DECLARE_OFFSETS(var, addr)          \
    const unsigned int var[4] = {           \
        l0_table_offset(addr),              \
        l1_table_offset(addr),              \
        l2_table_offset(addr),              \
        l3_table_offset(addr)               \
    }

#define clear_page(pgaddr)			memset((pgaddr), 0, PAGE_SIZE)
#define copy_page(to, from)			memcpy((to), (from), PAGE_SIZE)

/*
 * There is no such attribute in RISC-V
 * but is needed to make common/mm.c code happy.
 */
#define MT_NORMAL        0x0

#define _PAGE_W_BIT     2
#define _PAGE_XN_BIT    3
#define _PAGE_RO_BIT    1
#define _PAGE_XN        (1U << _PAGE_XN_BIT)
#define _PAGE_RO        (1U << _PAGE_RO_BIT)
#define _PAGE_W         (1U << _PAGE_W_BIT)
#define PAGE_XN_MASK(x) (((x) >> _PAGE_XN_BIT) & 0x1U)
#define PAGE_RO_MASK(x) (((x) >> _PAGE_RO_BIT) & 0x1U)
#define PAGE_W_MASK(x)  (((x) >> _PAGE_W_BIT) & 0x1U)

#define _PAGE_BLOCK     (BIT(8, UL))
#define _PAGE_POPULATE  (BIT(9, UL))
#define _PAGE_CONTIG    (BIT(10, UL))

/*
 * _PAGE_DEVICE and _PAGE_NORMAL are convenience defines. They are not
 * meant to be used outside of this header.
 */
// #define _PAGE_DEVICE    _PAGE_XN
#define _PAGE_NORMAL    _PAGE_PRESENT

#define PAGE_HYPERVISOR_RO      (_PAGE_NORMAL | _PAGE_RO | _PAGE_XN)
#define PAGE_HYPERVISOR_RX      (_PAGE_NORMAL | _PAGE_RO)
#define PAGE_HYPERVISOR_RW      (_PAGE_NORMAL | _PAGE_RO | _PAGE_XN | _PAGE_W)

#define PAGE_HYPERVISOR         PAGE_HYPERVISOR_RW
#define PAGE_HYPERVISOR_NOCACHE (PAGE_HYPERVISOR_RW)
#define PAGE_HYPERVISOR_WC      (PAGE_HYPERVISOR_RW)

/* Invalidate all instruction caches in Inner Shareable domain to PoU */
static inline void invalidate_icache(void)
{
    asm volatile ("fence.i" ::: "memory");
}

static inline int clean_and_invalidate_dcache_va_range
    (const void *p, unsigned long size)
{
    /* TODO: does RISC-V support clean and invlalidate of dcache */
    asm volatile("sfence.vma");

    return 0;
}

typedef struct {
    unsigned long v:1;
    unsigned long r:1;
    unsigned long w:1;
    unsigned long x:1;
    unsigned long u:1;
    unsigned long g:1;
    unsigned long a:1;
    unsigned long d:1;
    unsigned long rsw:2;
#if RV_STAGE1_MODE == SATP_MODE_SV39
    unsigned long ppn0:9;
    unsigned long ppn1:9;
    unsigned long ppn2:26;
    unsigned long rsw2:7;
    unsigned long pbmt:2;
    unsigned long n:1;
#elif RV_STAGE1_MODE == SATP_MODE_SV48
    unsigned long ppn0:9;
    unsigned long ppn1:9;
    unsigned long ppn2:9;
    unsigned long ppn3:17;
    unsigned long rsw2:7;
    unsigned long pbmt:2;
    unsigned long n:1;
#else
#error "Add proper bits for SATP_MODE"
#endif
} pt_t;

/* Page Table entry */
typedef union {
#ifdef CONFIG_RISCV_64
    uint64_t pte;
#else
    uint32_t pte;
#endif
pt_t bits;
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

inline bool pte_is_table(const pte_t p, unsigned int level)
{
    (void) level;

    return (((p.pte) & (PTE_VALID
                       | PTE_READABLE
                       | PTE_WRITABLE
                       | PTE_EXECUTABLE)) == PTE_VALID);
}

static inline bool pte_is_mapping(const pte_t pte, unsigned int level)
{
    return !pte_is_table(pte, level);
}

static inline bool pte_is_superpage(const pte_t pte, unsigned int level)
{
    if ( !pte.pte )
        return false;

    return pte_is_valid(pte) && !pte_is_table(pte, level) && level != 0;
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
