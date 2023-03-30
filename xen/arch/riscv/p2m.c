#include <xen/bug.h>
#include <xen/domain_page.h>
#include <xen/lib.h>
#include <asm/p2m.h>

/* Return the size of the pool, in bytes. */
int arch_get_paging_mempool_size(struct domain *d, uint64_t *size)
{
    assert_failed("need to be implemented\n");

    return 0;
}

int arch_set_paging_mempool_size(struct domain *d, uint64_t size)
{
    assert_failed("need to be implemented\n");

    return 0;
}

void memory_type_changed(struct domain *d)
{
}

mfn_t gfn_to_mfn(struct domain *d, gfn_t gfn)
{
    assert_failed("need to be implemented\n");

    return maddr_to_mfn(0);
}

int map_mmio_regions(struct domain *d,
                     gfn_t start_gfn,
                     unsigned long nr,
                     mfn_t mfn)
{
    assert_failed("need to be implemented\n");

    return -1;
}

int unmap_mmio_regions(struct domain *d,
                       gfn_t start_gfn,
                       unsigned long nr,
                       mfn_t mfn)
{
    assert_failed("need to be implemented\n");

    return -1;
}

int guest_physmap_remove_page(struct domain *d, gfn_t gfn, mfn_t mfn,
                              unsigned int page_order)
{
    assert_failed("need to be implemented\n");

    return 0;
}

void vcpu_mark_events_pending(struct vcpu *v)
{
    WARN();
}

struct page_info *get_page_from_gfn(struct domain *d, unsigned long gfn,
                                    p2m_type_t *t, p2m_query_t q)
{
    assert_failed("need to be implemented\n");

    return 0;
}
