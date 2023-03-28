#ifndef _XEN_P2M_H
#define _XEN_P2M_H

#include <xen/mm.h>

#include <asm/page-bits.h>

#define paddr_bits PADDR_BITS

struct domain;

extern void memory_type_changed(struct domain *);

/* Per-p2m-table state */
struct p2m_domain {
};

/*
 * List of possible type for each page in the p2m entry.
 * The number of available bit per page in the pte for this purpose is 4 bits.
 * So it's possible to only have 16 fields. If we run out of value in the
 * future, it's possible to use higher value for pseudo-type and don't store
 * them in the p2m entry.
 */
typedef enum {
    p2m_invalid = 0,    /* Nothing mapped here */
    p2m_ram_rw,         /* Normal read/write guest RAM */
    p2m_ram_ro,         /* Read-only; writes are silently dropped */
    p2m_mmio_direct_dev,/* Read/write mapping of genuine Device MMIO area */
    p2m_mmio_direct_nc, /* Read/write mapping of genuine MMIO area non-cacheable */
    p2m_mmio_direct_c,  /* Read/write mapping of genuine MMIO area cacheable */
    p2m_map_foreign_rw, /* Read/write RAM pages from foreign domain */
    p2m_map_foreign_ro, /* Read-only RAM pages from foreign domain */
    p2m_grant_map_rw,   /* Read/write grant mapping */
    p2m_grant_map_ro,   /* Read-only grant mapping */
    /* The types below are only used to decide the page attribute in the P2M */
    p2m_iommu_map_rw,   /* Read/write iommu mapping */
    p2m_iommu_map_ro,   /* Read-only iommu mapping */
    p2m_max_real_type,  /* Types after this won't be store in the p2m */
} p2m_type_t;

/* All common type definitions should live ahead of this inclusion. */
#ifdef _XEN_P2M_COMMON_H
# error "xen/p2m-common.h should not be included directly"
#endif
#include <xen/p2m-common.h>

static inline
void p2m_altp2m_check(struct vcpu *v, uint16_t idx)
{
    /* Not supported on ARM. */
}

/* Untyped version for RAM only, for compatibility */
static inline int guest_physmap_add_page(struct domain *d,
                                         gfn_t gfn,
                                         mfn_t mfn,
                                         unsigned int page_order)
{
    BUG();
    return 0;
}

mfn_t gfn_to_mfn(struct domain *d, gfn_t gfn);

// /* Look up a GFN and take a reference count on the backing page. */
typedef unsigned int p2m_query_t;
#define P2M_ALLOC    (1u<<0)   /* Populate PoD and paged-out entries */
#define P2M_UNSHARE  (1u<<1)   /* Break CoW sharing */

struct page_info *get_page_from_gfn(struct domain *d, unsigned long gfn,
                                    p2m_type_t *t, p2m_query_t q);

int get_page_type(struct page_info *page, unsigned long type);

// bool is_iomem_page(mfn_t mfn);
static inline int get_page_and_type(struct page_info *page,
                                    struct domain *domain,
                                    unsigned long type)
{
    BUG();

    return 0;
}

static inline bool arch_acquire_resource_check(struct domain *d)
{
    BUG(); /* unimplemented */
    return true;
}

#endif /* _XEN_P2M_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
