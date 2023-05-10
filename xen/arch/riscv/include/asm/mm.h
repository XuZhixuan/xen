/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _ASM_RISCV_MM_H
#define _ASM_RISCV_MM_H

#include <xen/kernel.h>
#include <xen/types.h>
#include <asm/page.h>
#include <asm/pgtable-bits.h>
#include <public/xen.h>
#include <xen/pdx.h>
#include <xen/errno.h>

extern unsigned char cpu0_boot_stack[];
extern unsigned long phys_offset;

#define convert_level(level) (HYP_PT_ROOT_LEVEL - level)

/* Align Xen to a 2 MiB boundary. */
// #define XEN_PADDR_ALIGN (1 << 21)

/* TODO: Rewrite this file to be correct */

/*
 * Per-page-frame information.
 *
 * Every architecture must ensure the following:
 *  1. 'struct page_info' contains a 'struct page_list_entry list'.
 *  2. Provide a PFN_ORDER() macro for accessing the order of a free page.
 */
#define PFN_ORDER(_pfn) ((_pfn)->v.free.order)

extern unsigned long frametable_base_pdx;

/*
 * The size of struct page_info impacts the number of entries that can fit
 * into the frametable area and thus it affects the amount of physical memory
 * we claim to support. Define PAGE_INFO_SIZE to be used for sanity checking.
*/
#ifdef CONFIG_RISCV_64
#define PAGE_INFO_SIZE 56
#else
#define PAGE_INFO_SIZE 32
#endif

struct page_info
{
    /* Each frame can be threaded onto a doubly-linked list. */
    struct page_list_entry list;

    /* Reference count and various PGC_xxx flags and fields. */
    unsigned long count_info;

    /* Context-dependent fields follow... */
    union {
        /* Page is in use: ((count_info & PGC_count_mask) != 0). */
        struct {
            /* Type reference count and various PGT_xxx flags and fields. */
            unsigned long type_info;
        } inuse;
        /* Page is on a free list: ((count_info & PGC_count_mask) == 0). */
        union {
            struct {
                /*
                 * Index of the first *possibly* unscrubbed page in the buddy.
                 * One more bit than maximum possible order to accommodate
                 * INVALID_DIRTY_IDX.
                 */
#define INVALID_DIRTY_IDX ((1UL << (MAX_ORDER + 1)) - 1)
                unsigned long first_dirty:MAX_ORDER + 1;

                /* Do TLBs need flushing for safety before next page use? */
                bool need_tlbflush:1;

#define BUDDY_NOT_SCRUBBING    0
#define BUDDY_SCRUBBING        1
#define BUDDY_SCRUB_ABORT      2
                unsigned long scrub_state:2;
            };

            unsigned long val;
            } free;

    } u;

    union {
        /* Page is in use, but not as a shadow. */
        struct {
            /* Owner of this page (zero if page is anonymous). */
            struct domain *domain;
        } inuse;

        /* Page is on a free list. */
        struct {
            /* Order-size of the free chunk this page is the head of. */
            unsigned int order;
        } free;

    } v;

    union {
        /*
         * Timestamp from 'TLB clock', used to avoid extra safety flushes.
         * Only valid for: a) free pages, and b) pages with zero type count
         */
        u32 tlbflush_timestamp;
    };
    u64 pad;
};

#define PG_shift(idx)   (BITS_PER_LONG - (idx))
#define PG_mask(x, idx) (x ## UL << PG_shift(idx))

#define PGT_none          PG_mask(0, 1)  /* no special uses of this page   */
#define PGT_writable_page PG_mask(1, 1)  /* has writable mappings?         */
#define PGT_type_mask     PG_mask(1, 1)  /* Bits 31 or 63.                 */

 /* Count of uses of this frame as its current type. */
#define PGT_count_width   PG_shift(2)
#define PGT_count_mask    ((1UL<<PGT_count_width)-1)

 /* Cleared when the owning guest 'frees' this page. */
#define _PGC_allocated    PG_shift(1)
#define PGC_allocated     PG_mask(1, 1)
  /* Page is Xen heap? */
#define _PGC_xen_heap     PG_shift(2)
#define PGC_xen_heap      PG_mask(1, 2)
/* ... */
/* Page is broken? */
#define _PGC_broken       PG_shift(7)
#define PGC_broken        PG_mask(1, 7)
 /* Mutually-exclusive page states: { inuse, offlining, offlined, free }. */
#define PGC_state         PG_mask(3, 9)
#define PGC_state_inuse   PG_mask(0, 9)
#define PGC_state_offlining PG_mask(1, 9)
#define PGC_state_offlined PG_mask(2, 9)
#define PGC_state_free    PG_mask(3, 9)
#define page_state_is(pg, st) (((pg)->count_info&PGC_state) == PGC_state_##st)

/* Count of references to this frame. */
#define PGC_count_width   PG_shift(9)
#define PGC_count_mask    ((1UL<<PGC_count_width)-1)

#define _PGC_extra        PG_shift(10)
#define PGC_extra         PG_mask(1, 10)

#define is_xen_heap_page(page) ((page)->count_info & PGC_xen_heap)
#define is_xen_heap_mfn(mfn) \
    (mfn_valid(_mfn(mfn)) && is_xen_heap_page(mfn_to_page(_mfn(mfn))))

#define is_xen_fixed_mfn(mfn)                                   \
    ((mfn_to_maddr(mfn) >= virt_to_maddr(&_start)) &&       \
     (mfn_to_maddr(mfn) <= virt_to_maddr(&_end)))

#define page_get_owner(_p)    (_p)->v.inuse.domain
#define page_set_owner(_p,_d) ((_p)->v.inuse.domain = (_d))

#define maddr_get_owner(ma)   (page_get_owner(maddr_to_page((ma))))
#define frame_table ((struct page_info *)FRAMETABLE_VIRT_START)

#define PDX_GROUP_SHIFT (PAGE_SHIFT + 9)

/* XXX -- account for base */
#define mfn_valid(mfn) ({                                                       \
    unsigned long __m_f_n = mfn_x(mfn);                                         \
    likely(pfn_to_pdx(__m_f_n) >= frametable_base_pdx); \
})

/* Convert between machine frame numbers and page-info structures. */
#define mfn_to_page(mfn)                                            \
    (frame_table + (mfn_to_pdx(mfn) - frametable_base_pdx))
#define page_to_mfn(pg)                                             \
    pdx_to_mfn((unsigned long)((pg) - frame_table) + frametable_base_pdx)

/* Convert between machine addresses and page-info structures. */
#define maddr_to_page(ma) mfn_to_page(maddr_to_mfn(ma))
#define page_to_maddr(pg) (mfn_to_maddr(page_to_mfn(pg)))

/* Convert between frame number and address formats.  */
#define pfn_to_paddr(pfn) ((paddr_t)(pfn) << PAGE_SHIFT)
#define paddr_to_pfn(pa)  ((unsigned long)((pa) >> PAGE_SHIFT))
#define paddr_to_pdx(pa)    mfn_to_pdx(maddr_to_mfn(pa))
#define gfn_to_gaddr(gfn)   pfn_to_paddr(gfn_x(gfn))
#define gaddr_to_gfn(ga)    _gfn(paddr_to_pfn(ga))
#define mfn_to_maddr(mfn)   pfn_to_paddr(mfn_x(mfn))
#define maddr_to_mfn(ma)    _mfn(paddr_to_pfn(ma))
#define vmap_to_mfn(va)     maddr_to_mfn(virt_to_maddr((vaddr_t)va))
#define vmap_to_page(va)    mfn_to_page(vmap_to_mfn(va))

extern unsigned long max_page;
extern unsigned long total_pages;
extern unsigned long xenheap_base_pdx;

static inline void *maddr_to_virt(paddr_t ma)
{
    ASSERT((mfn_to_pdx(maddr_to_mfn(ma)) - directmap_base_pdx) <
           (DIRECTMAP_SIZE >> PAGE_SHIFT));
    return (void *)(XENHEAP_VIRT_START -
                    (directmap_base_pdx << PAGE_SHIFT) +
                    ((ma & ma_va_bottom_mask) |
                     ((ma & ma_top_mask) >> pfn_pdx_hole_shift)));
}

paddr_t __virt_to_maddr(vaddr_t va);

#define virt_to_maddr(va) __virt_to_maddr((vaddr_t) (va))

/* Convert between Xen-heap virtual addresses and machine frame numbers. */
#define __virt_to_mfn(va)  paddr_to_pfn((vaddr_t)va)
#define __mfn_to_virt(mfn) (maddr_to_virt((paddr_t)(mfn) << PAGE_SHIFT))

#define pte_get_mfn(pte) maddr_to_mfn(pte_to_paddr(pte))

/*
 * Page needs to be scrubbed. Since this bit can only be set on a page that is
 * free (i.e. in PGC_state_free) we can reuse PGC_allocated bit.
 */
#define _PGC_need_scrub   _PGC_allocated
#define PGC_need_scrub    PGC_allocated

/*
 * We define non-underscored wrappers for above conversion functions.
 * These are overriden in various source files while underscored version
 * remain intact.
 */
#define virt_to_mfn(va)     __virt_to_mfn(va)
#define mfn_to_virt(mfn)    __mfn_to_virt(mfn)

/* Convert between Xen-heap virtual addresses and page-info structures. */
static inline struct page_info *virt_to_page(const void *v)
{
    unsigned long va = (unsigned long)v;
    unsigned long pdx;

    ASSERT(va >= XENHEAP_VIRT_START);
    ASSERT(va < directmap_virt_end);

    pdx = (va - XENHEAP_VIRT_START) >> PAGE_SHIFT;
    pdx += mfn_to_pdx(directmap_mfn_start);
    return frame_table + pdx - frametable_base_pdx;
}

static inline void *page_to_virt(const struct page_info *pg)
{
    return mfn_to_virt(mfn_x(page_to_mfn(pg)));
}

#define domain_set_alloc_bitsize(d) ((void)0)
#define domain_clamp_alloc_bitsize(d, b) (b)

/*
 * RISC-V does not have an M2P, but common code expects a handful of
 * M2P-related defines and functions. Provide dummy versions of these.
 */
#define INVALID_M2P_ENTRY        (~0UL)
#define SHARED_M2P_ENTRY         (~0UL - 1UL)
#define SHARED_M2P(_e)           ((_e) == SHARED_M2P_ENTRY)

/* Xen always owns P2M on RISC-V  (no PV) */
#define set_gpfn_from_mfn(mfn, pfn) do { (void) (mfn), (void)(pfn); } while (0)
#define mfn_to_gfn(d, mfn) ((void)(d), _gfn(mfn_x(mfn)))

/* Arch-specific portion of memory_op hypercall. */
long arch_memory_op(int op, XEN_GUEST_HANDLE_PARAM(void) arg);

extern void put_page_type(struct page_info *page);
static inline void put_page_and_type(struct page_info *page)
{
    put_page_type(page);
    put_page(page);
}

int guest_physmap_mark_populate_on_demand(struct domain *d, unsigned long gfn,
                                          unsigned int order);

unsigned long domain_get_maximum_gpfn(struct domain *d);

/*
 * On RISC-V, all the RAM is currently direct mapped in Xen.
 * Hence return always true.
 */
static inline bool arch_mfns_in_directmap(unsigned long mfn, unsigned long nr)
{
    return true;
}

void setup_initial_pagetables(void);

void enable_mmu(void);

void remove_identity_mapping(void);

void calc_phys_offset(void);

void* early_fdt_map(paddr_t fdt_paddr);

void setup_fixmap_mappings(void);

paddr_t pt_walk(unsigned long root, vaddr_t va, bool is_xen);

void __iomem *ioremap_attr(paddr_t start, size_t len, unsigned attributes);

static inline void __iomem *ioremap_cache(paddr_t start, size_t len)
{
    return ioremap_attr(start, len, PAGE_HYPERVISOR);
}

int pt_update(vaddr_t root, vaddr_t va, paddr_t pa,
              bool use_xenheap, struct domain *d, unsigned long flags);

#endif /* _ASM_RISCV_MM_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
