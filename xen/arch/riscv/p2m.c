#include <xen/bug.h>
#include <xen/domain_page.h>
#include <xen/lib.h>
#include <xen/rwlock.h>
#include <xen/sched.h>
#include <asm/domain.h>

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

/*
 * Force a synchronous P2M TLB flush.
 *
 * Must be called with the p2m lock held.
 */
static void p2m_force_tlb_flush_sync(struct p2m_domain *p2m)
{
    asm volatile ("sfence.vma");
}

void clear_and_clean_page(struct page_info *page)
{
    void *p = __map_domain_page(page);

    clear_page(p);
    unmap_domain_page(p);
}

static struct page_info *p2m_get_clean_page(struct domain *d)
{
    struct page_info *page;

    page = alloc_domheap_pages(NULL, 2, 0);
    if ( page == NULL )
        return NULL;

    clear_and_clean_page(page);

    return page;
}

static struct page_info *p2m_allocate_root(struct domain *d)
{
    return p2m_get_clean_page(d);
}

static unsigned long hgatp_from_page_info(struct page_info *page_info)
{
    unsigned long ppn;
    unsigned long hgatp_mode;

    ppn = (page_to_maddr(page_info) >> PAGE_SHIFT) & HGATP_PPN;

    /* ASID not supported yet */

#if RV_STAGE1_MODE == SATP_MODE_SV39
    hgatp_mode = HGATP_MODE_SV39X4;
#elif RV_STAGE1_MODE == SATP_MODE_SV48
    hgatp_mode = HGATP_MODE_SV48X4;
#else
    #error "add HGATP_MODE"
#endif

    return ppn | (hgatp_mode << HGATP_MODE_SHIFT);
}

static int p2m_alloc_table(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    p2m->root = p2m_allocate_root(d);
    if ( !p2m->root )
        return -ENOMEM;

    p2m->hgatp = hgatp_from_page_info(p2m->root);

    p2m_write_lock(p2m);
    p2m_force_tlb_flush_sync(p2m);
    p2m_write_unlock(p2m);

    return 0;
}

int p2m_init(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int rc;

    rc = p2m_alloc_table(d);
    if ( rc )
        return rc;

    rwlock_init(&p2m->lock);
    INIT_PAGE_LIST_HEAD(&p2m->pages);

    return 0;
}

