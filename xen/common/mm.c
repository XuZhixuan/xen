#include <xen/domain_page.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/pfn.h>
#include <xen/pmap.h>
#include <xen/vmap.h>

/* Limits of the Xen heap */
mfn_t directmap_mfn_start __read_mostly = INVALID_MFN_INITIALIZER;
mfn_t directmap_mfn_end __read_mostly;
vaddr_t directmap_virt_end __read_mostly;
#ifndef CONFIG_ARM_32
vaddr_t directmap_virt_start __read_mostly;
unsigned long directmap_base_pdx __read_mostly;
#endif

unsigned long frametable_base_pdx __read_mostly;
unsigned long frametable_virt_end __read_mostly;

static pte_t *xen_map_table(mfn_t mfn)
{
    /*
     * During early boot, map_domain_page() may be unusable. Use the
     * PMAP to map temporarily a page-table.
     */
    if ( system_state == SYS_STATE_early_boot )
        return pmap_map(mfn);

    return map_domain_page(mfn);
}

static void xen_unmap_table(const pte_t *table)
{
    /*
     * During early boot, xen_map_table() will not use map_domain_page()
     * but the PMAP.
     */
    if ( system_state == SYS_STATE_early_boot )
        pmap_unmap(table);
    else
        unmap_domain_page(table);
}

static int create_xen_table(pte_t *entry)
{
    mfn_t mfn;
    void *p;
    pte_t pte;

    if ( system_state != SYS_STATE_early_boot )
    {
        struct page_info *pg = alloc_domheap_page(NULL, 0);

        if ( pg == NULL )
            return -ENOMEM;

        mfn = page_to_mfn(pg);
    }
    else
        mfn = alloc_boot_pages(1, 1);

    p = xen_map_table(mfn);
    clear_page(p);
    xen_unmap_table(p);

    pte = mfn_to_xen_entry(mfn, MT_NORMAL);
    
    set_pte_table_bit(&pte, 1);

    write_pte(entry, pte);

    return 0;
}

#define XEN_TABLE_MAP_FAILED 0
#define XEN_TABLE_SUPER_PAGE 1
#define XEN_TABLE_NORMAL_PAGE 2

/*
 * Take the currently mapped table, find the corresponding entry,
 * and map the next table, if available.
 *
 * The read_only parameters indicates whether intermediate tables should
 * be allocated when not present.
 *
 * Return values:
 *  XEN_TABLE_MAP_FAILED: Either read_only was set and the entry
 *  was empty, or allocating a new page failed.
 *  XEN_TABLE_NORMAL_PAGE: next level mapped normally
 *  XEN_TABLE_SUPER_PAGE: The next entry points to a superpage.
 */
static int xen_pt_next_level(bool read_only, unsigned int level,
                             pte_t **table, unsigned int offset)
{
    pte_t *entry;
    int ret;
    mfn_t mfn;

    entry = *table + offset;

    if ( !pte_is_valid(*entry) )
    {
        if ( read_only )
            return XEN_TABLE_MAP_FAILED;

        ret = create_xen_table(entry);
        if ( ret )
            return XEN_TABLE_MAP_FAILED;
    }

    if ( pte_is_mapping(*entry, level) )
    {
        return XEN_TABLE_SUPER_PAGE;
    }

    mfn = pte_get_mfn(*entry);

    xen_unmap_table(*table);
    *table = xen_map_table(mfn);

    return XEN_TABLE_NORMAL_PAGE;
}

/* Sanity check of the entry */
static bool xen_pt_check_entry(pte_t entry, mfn_t mfn, unsigned int level,
                               unsigned int flags)
{
    /* Sanity check when modifying an entry. */
    if ( (flags & _PAGE_PRESENT) && mfn_eq(mfn, INVALID_MFN) )
    {
        /* We don't allow modifying an invalid entry. */
        if ( !pte_is_valid(entry) )
        {
            printk("Modifying invalid entry is not allowed.\n");
            return false;
        }

        /* We don't allow modifying a table entry */
        if ( !pte_is_mapping(entry, level) )
        {
            printk("Modifying a table entry is not allowed.\n");
            return false;
        }

        if ( !sanity_arch_specific_pte_checks(entry) )
        {
            printk("sanity check failed\n");
            return false;
        }
    }
    /* Sanity check when inserting a mapping */
    else if ( flags & _PAGE_PRESENT )
    {
        /* We should be here with a valid MFN. */
        ASSERT(!mfn_eq(mfn, INVALID_MFN));

        /*
         * We don't allow replacing any valid entry.
         *
         * Note that the function xen_pt_update() relies on this
         * assumption and will skip the TLB flush. The function will need
         * to be updated if the check is relaxed.
         */
        if ( pte_is_valid(entry) )
        {
            if ( pte_is_mapping(entry, level) )
                printk("Changing MFN for a valid entry is not allowed (%#"PRI_mfn" -> %#"PRI_mfn").\n",
                          mfn_x(pte_get_mfn(entry)), mfn_x(mfn));
            else
                printk("Trying to replace a table with a mapping.\n");
            return false;
        }
    }
    /* Sanity check when removing a mapping. */
    else if ( (flags & (_PAGE_PRESENT|_PAGE_POPULATE)) == 0 )
    {
        /* We should be here with an invalid MFN. */
        ASSERT(mfn_eq(mfn, INVALID_MFN));

        /* We don't allow removing a table */
        if ( pte_is_table(entry, level) )
        {
            printk("Removing a table is not allowed.\n");
            return false;
        }

        if ( get_contig_bit(entry) )
        {
            printk("Removing entry with contiguous bit set is not allowed.\n");
            return false;
        }
    }
    /* Sanity check when populating the page-table. No check so far. */
    else
    {
        ASSERT(flags & _PAGE_POPULATE);
        /* We should be here with an invalid MFN */
        ASSERT(mfn_eq(mfn, INVALID_MFN));
    }

    return true;
}

/* Update an entry at the level @target. */
static int xen_pt_update_entry(mfn_t root, unsigned long virt,
                               mfn_t mfn, unsigned int arch_target,
                               unsigned int flags)
{
    int rc;
    unsigned int level = convert_level(HYP_PT_ROOT_LEVEL);
    unsigned int arch_level = convert_level(level);
    unsigned int target = convert_level(arch_target);
    pte_t *table;
    /*
     * The intermediate page tables are read-only when the MFN is not valid
     * and we are not populating page table.
     * This means we either modify permissions or remove an entry.
     */
    bool read_only = mfn_eq(mfn, INVALID_MFN) && !(flags & _PAGE_POPULATE);
    pte_t pte, *entry;

    /* convenience aliases */
    DECLARE_OFFSETS(offsets, (paddr_t)virt);

    /* _PAGE_POPULATE and _PAGE_PRESENT should never be set together. */
    ASSERT((flags & (_PAGE_POPULATE|_PAGE_PRESENT)) != (_PAGE_POPULATE|_PAGE_PRESENT));

    table = xen_map_table(root);
    for ( ; level < target; level++, arch_level = convert_level(level) )
    {
        rc = xen_pt_next_level(read_only, arch_level, &table, offsets[arch_level]);
        if ( rc == XEN_TABLE_MAP_FAILED )
        {
            /*
             * We are here because xen_pt_next_level has failed to map
             * the intermediate page table (e.g the table does not exist
             * and the pt is read-only). It is a valid case when
             * removing a mapping as it may not exist in the page table.
             * In this case, just ignore it.
             */
            if ( flags & (_PAGE_PRESENT | _PAGE_POPULATE) )
            {
                printk("%s: Unable to map level %u\n", __func__, arch_level);
                rc = -ENOENT;
                goto out;
            }
            else
            {
                rc = 0;
                goto out;
            }
        }
        else if ( rc != XEN_TABLE_NORMAL_PAGE ) {
            break;
        }
    }

    if ( arch_level != arch_target )
    {
        printk("%s: Shattering superpage is not supported\n", __func__);
        rc = -EOPNOTSUPP;
        goto out;
    }

    entry = table + offsets[arch_level];

    rc = -EINVAL;
    if ( !xen_pt_check_entry(*entry, mfn, arch_level, flags) )
        goto out;

    /* If we are only populating page-table, then we are done. */
    rc = 0;
    if ( flags & _PAGE_POPULATE )
        goto out;

    /* We are removing the page */
    if ( !(flags & _PAGE_PRESENT) )
        memset(&pte, 0x00, sizeof(pte));
    else
    {
        /* We are inserting a mapping => Create new pte. */
        if ( !mfn_eq(mfn, INVALID_MFN) )
        {
            pte = mfn_to_xen_entry(mfn, PAGE_AI_MASK(flags));

            set_pte_table_bit(&pte, (arch_level == 3));
        }
        else /* We are updating the permission => Copy the current pte. */
            pte = *entry;

        set_pte_permissions(&pte, flags);
    }

    write_pte(entry, pte);

    rc = 0;

out:
    xen_unmap_table(table);

    return rc;
}

static DEFINE_SPINLOCK(xen_pt_lock);

static int xen_pt_update(unsigned long virt,
                         mfn_t mfn,
                         /* const on purpose as it is used for TLB flush */
                         const unsigned long nr_mfns,
                         unsigned int flags)
{
    int rc = 0;
    unsigned long vfn = virt >> PAGE_SHIFT;
    unsigned long left = nr_mfns;

    /*
     * For arm32, page-tables are different on each CPUs. Yet, they share
     * some common mappings. It is assumed that only common mappings
     * will be modified with this function.
     *
     * XXX: Add a check.
     */
    const mfn_t root = get_root_page(); /* maddr_to_mfn(READ_SYSREG64(TTBR0_EL2)); */

    /*
     * The hardware was configured to forbid mapping both writeable and
     * executable.
     * When modifying/creating mapping (i.e _PAGE_PRESENT is set),
     * prevent any update if this happen.
     */
    if ( (flags & _PAGE_PRESENT) && !PAGE_RO_MASK(flags) &&
         !PAGE_XN_MASK(flags) )
    {
        printk("Mappings should not be both Writeable and Executable.\n");
        return -EINVAL;
    }

    if ( flags & _PAGE_CONTIG )
    {
        printk("_PAGE_CONTIG is an internal only flag.\n");
        return -EINVAL;
    }

    if ( !IS_ALIGNED(virt, PAGE_SIZE) )
    {
        printk("The virtual address is not aligned to the page-size.\n");
        return -EINVAL;
    }

    spin_lock(&xen_pt_lock);

    while ( left )
    {
        unsigned int order, level, nr_contig, new_flags;

        level = xen_pt_mapping_level(vfn, mfn, left, flags);
        order = XEN_PT_LEVEL_ORDER(level);

        ASSERT(left >= BIT(order, UL));

        /*
         * Check if we can set the contiguous mapping and update the
         * flags accordingly.
         */
        nr_contig = xen_pt_check_contig(vfn, mfn, level, left, flags);
        new_flags = flags | ((nr_contig > 1) ? _PAGE_CONTIG : 0);

        for ( ; nr_contig > 0; nr_contig-- )
        {
            rc = xen_pt_update_entry(root, vfn << PAGE_SHIFT, mfn, level,
                                     new_flags);
            if ( rc )
                break;

            vfn += 1U << order;
            if ( !mfn_eq(mfn, INVALID_MFN) )
                mfn = mfn_add(mfn, 1U << order);

            left -= (1U << order);
        }

        if ( rc )
            break;
    }

    /*
     * The TLBs flush can be safely skipped when a mapping is inserted
     * as we don't allow mapping replacement (see xen_pt_check_entry()).
     *
     * For all the other cases, the TLBs will be flushed unconditionally
     * even if the mapping has failed. This is because we may have
     * partially modified the PT. This will prevent any unexpected
     * behavior afterwards.
     */
    if ( !((flags & _PAGE_PRESENT) && !mfn_eq(mfn, INVALID_MFN)) )
        flush_xen_tlb_range_va(virt, PAGE_SIZE * nr_mfns);

    spin_unlock(&xen_pt_lock);

    return rc;
}

int map_pages_to_xen(unsigned long virt,
                     mfn_t mfn,
                     unsigned long nr_mfns,
                     unsigned int flags)
{
    return xen_pt_update(virt, mfn, nr_mfns, flags);
}

#ifdef CONFIG_ARM_32

/*
 * Set up the direct-mapped xenheap:
 * up to 1GB of contiguous, always-mapped memory.
 */
void __init setup_directmap_mappings(unsigned long base_mfn,
                                     unsigned long nr_mfns)
{
    int rc;

    rc = map_pages_to_xen(XENHEAP_VIRT_START, _mfn(base_mfn), nr_mfns,
                          PAGE_HYPERVISOR_RW | _PAGE_BLOCK);
    if ( rc )
        panic("Unable to setup the directmap mappings.\n");

    /* Record where the directmap is, for translation routines. */
    directmap_virt_end = XENHEAP_VIRT_START + nr_mfns * PAGE_SIZE;
}

#else /* CONFIG_ARM_64 || CONFIG_RISCV_64 */

#ifdef CONFIG_RISCV_32
#error "RV32 isn't supported"
#endif

/* Map the region in the directmap area. */
void __init setup_directmap_mappings(unsigned long base_mfn,
                                     unsigned long nr_mfns)
{
    int rc;

    /* First call sets the directmap physical and virtual offset. */
    if ( mfn_eq(directmap_mfn_start, INVALID_MFN) )
    {
        unsigned long mfn_gb = base_mfn & ~((FIRST_SIZE >> PAGE_SHIFT) - 1);

        directmap_mfn_start = _mfn(base_mfn);
        directmap_base_pdx = mfn_to_pdx(_mfn(base_mfn));
        /*
         * The base address may not be aligned to the first level
         * size (e.g. 1GB when using 4KB pages). This would prevent
         * superpage mappings for all the regions because the virtual
         * address and machine address should both be suitably aligned.
         *
         * Prevent that by offsetting the start of the directmap virtual
         * address.
         */
        directmap_virt_start = DIRECTMAP_VIRT_START +
            (base_mfn - mfn_gb) * PAGE_SIZE;
    }

    if ( base_mfn < mfn_x(directmap_mfn_start) )
        panic("cannot add directmap mapping at %lx below heap start %lx\n",
              base_mfn, mfn_x(directmap_mfn_start));

    rc = map_pages_to_xen((vaddr_t)__mfn_to_virt(base_mfn),
                          _mfn(base_mfn), nr_mfns,
                          PAGE_HYPERVISOR_RW | _PAGE_BLOCK);
    if ( rc )
        panic("Unable to setup the directmap mappings.\n");
}
#endif

/* Map a frame table to cover physical addresses ps through pe */
void __init setup_frametable_mappings(paddr_t ps, paddr_t pe)
{
    unsigned long nr_pdxs = mfn_to_pdx(mfn_add(maddr_to_mfn(pe), -1)) -
                            mfn_to_pdx(maddr_to_mfn(ps)) + 1;
    unsigned long frametable_size = nr_pdxs * sizeof(struct page_info);
    mfn_t base_mfn;
    const unsigned long mapping_size = frametable_size < MB(32) ? MB(2) : MB(32);
    int rc;

    BUILD_BUG_ON(sizeof(struct page_info) != PAGE_INFO_SIZE);

    if ( frametable_size > FRAMETABLE_SIZE )
        panic("The frametable cannot cover the physical region %#"PRIpaddr" - %#"PRIpaddr"\n",
              ps, pe);

    frametable_base_pdx = mfn_to_pdx(maddr_to_mfn(ps));
    /* Round up to 2M or 32M boundary, as appropriate. */
    frametable_size = ROUNDUP(frametable_size, mapping_size);
    base_mfn = alloc_boot_pages(frametable_size >> PAGE_SHIFT, 32<<(20-12));

    rc = map_pages_to_xen(FRAMETABLE_VIRT_START, base_mfn,
                          frametable_size >> PAGE_SHIFT,
                          PAGE_HYPERVISOR_RW | _PAGE_BLOCK);
    if ( rc )
        panic("Unable to setup the frametable mappings.\n");

    memset(&frame_table[0], 0, nr_pdxs * sizeof(struct page_info));
    memset(&frame_table[nr_pdxs], -1,
           frametable_size - (nr_pdxs * sizeof(struct page_info)));

    frametable_virt_end = FRAMETABLE_VIRT_START + (nr_pdxs * sizeof(struct page_info));
}

void *__init arch_vmap_virt_end(void)
{
    return (void *)(VMAP_VIRT_START + VMAP_VIRT_SIZE);
}

void flush_page_to_ram(unsigned long mfn, bool sync_icache)
{
    void *v = map_domain_page(_mfn(mfn));

    clean_and_invalidate_dcache_va_range(v, PAGE_SIZE);
    unmap_domain_page(v);

    /*
     * For some of the instruction cache (such as VIPT), the entire I-Cache
     * needs to be flushed to guarantee that all the aliases of a given
     * physical address will be removed from the cache.
     * Invalidating the I-Cache by VA highly depends on the behavior of the
     * I-Cache (See D4.9.2 in ARM DDI 0487A.k_iss10775). Instead of using flush
     * by VA on select platforms, we just flush the entire cache here.
     */
    if ( sync_icache )
        invalidate_icache();
}

int populate_pt_range(unsigned long virt, unsigned long nr_mfns)
{
    return xen_pt_update(virt, INVALID_MFN, nr_mfns, _PAGE_POPULATE);
}

/*
 * This function should only be used to remap device address ranges
 * TODO: add a check to verify this assumption
 */
void *ioremap_attr(paddr_t pa, size_t len, unsigned int attributes)
{
    mfn_t mfn = _mfn(PFN_DOWN(pa));
    unsigned int offs = pa & (PAGE_SIZE - 1);
    unsigned int nr = PFN_UP(offs + len);
    void *ptr = __vmap(&mfn, nr, 1, 1, attributes, VMAP_DEFAULT);

    if ( ptr == NULL )
        return NULL;

    return ptr + offs;
}

void *ioremap(paddr_t pa, size_t len)
{
    return ioremap_attr(pa, len, PAGE_HYPERVISOR_NOCACHE);
}

int destroy_xen_mappings(unsigned long s, unsigned long e)
{
    ASSERT(IS_ALIGNED(s, PAGE_SIZE));
    ASSERT(IS_ALIGNED(e, PAGE_SIZE));
    ASSERT(s <= e);
    return xen_pt_update(s, INVALID_MFN, (e - s) >> PAGE_SHIFT, 0);
}

