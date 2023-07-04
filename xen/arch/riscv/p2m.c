#include <xen/bug.h>
#include <xen/domain_page.h>
#include <xen/event.h>
#include <xen/lib.h>
#include <xen/rwlock.h>
#include <xen/sched.h>
#include <asm/domain.h>
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
    spin_lock_init(&d->arch.paging.lock);
    INIT_PAGE_LIST_HEAD(&p2m->pages);
    INIT_PAGE_LIST_HEAD(&d->arch.paging.p2m_freelist);

    return 0;
}

struct page_info *p2m_get_page_from_gfn(struct domain *d, gfn_t gfn,
                                        p2m_type_t *t)
{
    p2m_type_t p2mt = {0};
    struct page_info *page;

    mfn_t mfn = p2m_lookup(d, gfn, &p2mt);

    if ( t )
        *t = p2mt;

    if ( !mfn_valid(mfn) )
        return NULL;

    page = mfn_to_page(mfn);

    return get_page(page, d) ? page : NULL;
}

static paddr_t get_p2m_root_pt_mfn(struct domain *d)
{
    return (p2m_get_hostp2m(d)->hgatp & HGATP_PPN) << PAGE_SHIFT;
}

mfn_t p2m_lookup(struct domain *d, gfn_t gfn, p2m_type_t *t)
{
    vaddr_t root;
    paddr_t pa;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    p2m_read_lock(p2m);
    root = (vaddr_t)map_domain_page(maddr_to_mfn(get_p2m_root_pt_mfn(d)));
    pa = pt_walk(root, gfn_to_gaddr(gfn), false);
    p2m_read_unlock(p2m);

    return maddr_to_mfn(pa);
}

int guest_physmap_add_entry(struct domain *d,
                            gfn_t gfn,
                            mfn_t mfn,
                            unsigned long page_order,
                            p2m_type_t t)
{
    const unsigned long nr = 1 << page_order;
    paddr_t guest_start, guest_end;
    vaddr_t root;
    unsigned long i = 0;

    printk("%s: map %lu pages from gfn 0x%02lx to mfn 0x%02lx\n", __func__,
            nr, gfn_to_gaddr(gfn), mfn_to_maddr(mfn));

    root = (vaddr_t)map_domain_page(maddr_to_mfn(get_p2m_root_pt_mfn(d)));
    guest_start = gfn_to_gaddr(gfn);
    guest_end = guest_start + (nr * PAGE_SIZE);

    for (i = 0; i < nr; i++ )
    {
        paddr_t guest_addr = guest_start + (i * PAGE_SIZE);
        paddr_t supervisor_addr = mfn_to_maddr(mfn) + (i * PAGE_SIZE);
        pt_update(root, guest_addr, supervisor_addr, false,
                  d, PTE_READABLE | PTE_WRITABLE | PTE_EXECUTABLE | PTE_USER);

        /* Remove this after pt_update/pt_walk stand the test of time */
        BUG_ON(pt_walk(root, guest_addr, false) != supervisor_addr);

    }
    unmap_domain_page(root);

    return 0;
}

void p2m_save_state(struct vcpu *p)
{
}

void p2m_restore_state(struct vcpu *n)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(n->domain);

    if ( is_idle_vcpu(n) )
    {
        printk("%s: is_idle_vcpu\n", __func__);
        return;
    }

    n->arch.hgatp = p2m->hgatp;
}

/*
 * Set the pool of pages to the required number of pages.
 * Returns 0 for success, non-zero for failure.
 * Call with d->arch.paging.lock held.
 */
int p2m_set_allocation(struct domain *d, unsigned long pages, bool *preempted)
{
    struct page_info *pg;

    ASSERT(spin_is_locked(&d->arch.paging.lock));

    for ( ; ; )
    {
        if ( d->arch.paging.p2m_total_pages < pages )
        {
            /* Need to allocate more memory from domheap */
            pg = alloc_domheap_page(NULL, 0);
            if ( pg == NULL )
            {
                printk(XENLOG_ERR "Failed to allocate P2M pages.\n");
                return -ENOMEM;
            }
            ACCESS_ONCE(d->arch.paging.p2m_total_pages) =
                d->arch.paging.p2m_total_pages + 1;
            page_list_add_tail(pg, &d->arch.paging.p2m_freelist);
        }
        else if ( d->arch.paging.p2m_total_pages > pages )
        {
            /* Need to return memory to domheap */
            pg = page_list_remove_head(&d->arch.paging.p2m_freelist);
            if( pg )
            {
                ACCESS_ONCE(d->arch.paging.p2m_total_pages) =
                    d->arch.paging.p2m_total_pages - 1;
                free_domheap_page(pg);
            }
            else
            {
                printk(XENLOG_ERR
                       "Failed to free P2M pages, P2M freelist is empty.\n");
                return -ENOMEM;
            }
        }
        else
            break;

        /* Check to see if we need to yield and try again */
        if ( preempted && general_preempt_check() )
        {
            *preempted = true;
            return -ERESTART;
        }
    }

    return 0;
}

int p2m_teardown_allocation(struct domain *d)
{
    int ret = 0;
    bool preempted = false;

    spin_lock(&d->arch.paging.lock);
    if ( d->arch.paging.p2m_total_pages != 0 )
    {
        ret = p2m_set_allocation(d, 0, &preempted);
        if ( preempted )
        {
            spin_unlock(&d->arch.paging.lock);
            return -ERESTART;
        }
        ASSERT(d->arch.paging.p2m_total_pages == 0);
    }
    spin_unlock(&d->arch.paging.lock);

    return ret;
}

