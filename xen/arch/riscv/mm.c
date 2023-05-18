/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/cache.h>
#include <xen/compiler.h>
#include <xen/domain_page.h>
#include <xen/err.h>
#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/pfn.h>
#include <xen/lib.h>
#include <xen/libfdt/libfdt.h>
#include <xen/mm.h>
#include <xen/page-size.h>
#include <xen/pmap.h>
#include <xen/sched.h>
#include <asm/early_printk.h>

#include <asm/early_printk.h>
#include <asm/csr.h>
#include <asm/current.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/p2m.h>

enum pt_level {
    pt_level_zero,
    pt_level_one,
    pt_level_two,
    pt_level_three,
    pt_level_four,
#if CONFIG_PAGING_LEVELS > 5
    #error "need to update enum pt_level"
#endif
};

struct mmu_desc {
    unsigned int num_levels;
    unsigned int pgtbl_count;
    pte_t *next_pgtbl;
    pte_t *pgtbl_base;
} mmu_desc = { CONFIG_PAGING_LEVELS, 0, NULL, 0 };

unsigned long __ro_after_init phys_offset;

#define LOAD_TO_LINK(addr) ((unsigned long)(addr) - phys_offset)
#define LINK_TO_LOAD(addr) ((unsigned long)(addr) + phys_offset)

/*
 * It is expected that Xen won't be more then 2 MB.
 * The check in xen.lds.S guarantees that.
 * At least 3 page tables (in case of Sv39 ) are needed to cover 2 MB.
 * One for each page level table with PAGE_SIZE = 4 Kb.
 *
 * One L0 page table can cover 2 MB(512 entries of one page table * PAGE_SIZE).
 *
 * It might be needed one more page table in case when Xen load address
 * isn't 2 MB aligned.
 *
 * (CONFIG_PAGING_LEVELS - 1) page tables are needed for identity mapping.
 * 
 * (CONFIG_PAGING_LEVELS) page tables are needed for device tree mapping:
 * In case of Sv39: 1 pt -> L1, 1-2pt -> L0 ( depends on FDT address )
 */
#define PGTBL_INITIAL_COUNT ((CONFIG_PAGING_LEVELS - 1) * 3 + 1 + 1)

unsigned long max_page;

pte_t __section(".bss.page_aligned") __aligned(PAGE_SIZE)
stage1_pgtbl_root[PAGETABLE_ENTRIES];

pte_t __section(".bss.page_aligned") __aligned(PAGE_SIZE)
stage1_pgtbl_nonroot[PGTBL_INITIAL_COUNT * PAGETABLE_ENTRIES];

pte_t __section(".bss.page_aligned") __aligned(PAGE_SIZE)
xen_fixmap[PAGETABLE_ENTRIES];

#define HANDLE_PGTBL(curr_lvl_num)                                          \
    index = pt_index(curr_lvl_num, page_addr);                              \
    if ( pte_is_valid(pgtbl[index]) )                                       \
    {                                                                       \
        /* Find L{ 0-3 } table */                                           \
        pgtbl = (pte_t *)pte_to_paddr(pgtbl[index]);                        \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        /* Allocate new L{0-3} page table */                                \
        if ( mmu_desc->pgtbl_count == PGTBL_INITIAL_COUNT )                 \
        {                                                                   \
            early_printk("(XEN) No initial table available\n");             \
            /* panic(), BUG() or ASSERT() aren't ready now. */              \
            die();                                                          \
        }                                                                   \
        mmu_desc->pgtbl_count++;                                            \
        pgtbl[index] = paddr_to_pte((unsigned long)mmu_desc->next_pgtbl,    \
                                    PTE_VALID);                             \
        pgtbl = mmu_desc->next_pgtbl;                                       \
        mmu_desc->next_pgtbl += PAGETABLE_ENTRIES;                          \
    }

static void __init setup_initial_mapping(struct mmu_desc *mmu_desc,
                                         unsigned long map_start,
                                         unsigned long map_end,
                                         unsigned long pa_start)
{
    unsigned int index;
    pte_t *pgtbl;
    unsigned long page_addr;
    bool is_identity_mapping = map_start == pa_start;

    if ( (unsigned long)_start % XEN_PT_LEVEL_SIZE(0) )
    {
        early_printk("(XEN) Xen should be loaded at 4k boundary\n");
        die();
    }

    if ( (map_start & ~XEN_PT_LEVEL_MAP_MASK(0)) ||
         (pa_start & ~XEN_PT_LEVEL_MAP_MASK(0)) )
    {
        early_printk("(XEN) map and pa start addresses should be aligned\n");
        /* panic(), BUG() or ASSERT() aren't ready now. */
        die();
    }

    for ( page_addr = map_start;
          page_addr < map_end;
          page_addr += XEN_PT_LEVEL_SIZE(0) )
    {
        pgtbl = mmu_desc->pgtbl_base;

        switch ( mmu_desc->num_levels )
        {
        case 4: /* Level 3 */
            HANDLE_PGTBL(3);
        case 3: /* Level 2 */
            HANDLE_PGTBL(2);
        case 2: /* Level 1 */
            HANDLE_PGTBL(1);
        case 1: /* Level 0 */
            {
                unsigned long paddr = (page_addr - map_start) + pa_start;
                unsigned int permissions = PTE_LEAF_DEFAULT;
                unsigned long addr = is_identity_mapping
                                     ? page_addr : LINK_TO_LOAD(page_addr);
                pte_t pte_to_be_written;

                index = pt_index(0, page_addr);

                if ( is_kernel_text(addr) ||
                     is_kernel_inittext(addr) )
                        permissions =
                            PTE_EXECUTABLE | PTE_READABLE | PTE_VALID;

                if ( is_kernel_rodata(addr) )
                    permissions = PTE_READABLE | PTE_VALID;

                pte_to_be_written = paddr_to_pte(paddr, permissions);

                if ( !pte_is_valid(pgtbl[index]) )
                    pgtbl[index] = pte_to_be_written;
                else
                {
                    if ( (pgtbl[index].pte ^ pte_to_be_written.pte) &
                         ~(PTE_DIRTY | PTE_ACCESSED) )
                    {
                        early_printk("PTE overridden has occurred\n");
                        /* panic(), <asm/bug.h> aren't ready now. */
                        die();
                    }
                }
            }
        }
    }
}
#undef HANDLE_PGTBL

static bool __init check_pgtbl_mode_support(struct mmu_desc *mmu_desc,
                                            unsigned long load_start)
{
    bool is_mode_supported = false;
    unsigned int index;
    unsigned int page_table_level = (mmu_desc->num_levels - 1);
    unsigned level_map_mask = XEN_PT_LEVEL_MAP_MASK(page_table_level);

    unsigned long aligned_load_start = load_start & level_map_mask;
    unsigned long aligned_page_size = XEN_PT_LEVEL_SIZE(page_table_level);
    unsigned long xen_size = (unsigned long)(_end - start);

    if ( (load_start + xen_size) > (aligned_load_start + aligned_page_size) )
    {
        early_printk("please place Xen to be in range of PAGE_SIZE "
                     "where PAGE_SIZE is XEN_PT_LEVEL_SIZE( {L3 | L2 | L1} ) "
                     "depending on expected SATP_MODE \n"
                     "XEN_PT_LEVEL_SIZE is defined in <asm/page.h>\n");
        die();
    }

    index = pt_index(page_table_level, aligned_load_start);
    stage1_pgtbl_root[index] = paddr_to_pte(aligned_load_start,
                                            PTE_LEAF_DEFAULT | PTE_EXECUTABLE);

    sfence_vma();
    csr_write(CSR_SATP,
              PFN_DOWN((unsigned long)stage1_pgtbl_root) |
              RV_STAGE1_MODE << SATP_MODE_SHIFT);

    if ( (csr_read(CSR_SATP) >> SATP_MODE_SHIFT) == RV_STAGE1_MODE )
        is_mode_supported = true;

    csr_write(CSR_SATP, 0);

    sfence_vma();

    /* Clean MMU root page table */
    stage1_pgtbl_root[index] = paddr_to_pte(0x0, 0x0);

    return is_mode_supported;
}

void __init setup_fixmap_mappings(void)
{
    pte_t *pte;
    unsigned int i = 0;

    pte = &stage1_pgtbl_root[pt_index(HYP_PT_ROOT_LEVEL, FIXMAP_ADDR(0))];

    /* get pointer to L1 */
    for ( i = 1; i < HYP_PT_ROOT_LEVEL; i++ )
    {
        BUG_ON( !pte_is_valid(*pte) );

        pte = (pte_t *)pte_to_paddr(*pte);
        pte = &pte[pt_index(convert_level(i), FIXMAP_ADDR(0))];
    }

    BUG_ON( pte_is_valid(*pte) );

    if ( !pte_is_valid(*pte) )
    {
        pte_t tmp = paddr_to_pte((unsigned long)&xen_fixmap, PTE_TABLE);

        write_pte(pte, tmp);

        early_printk("(XEN) fixmap is mapped\n");
    }

    /*
     * We only need the zeroeth table allocated, but not the PTEs set, because
     * set_fixmap() will set them on the fly.
     */
}

/*
 * setup_initial_pagetables:
 *
 * Build the page tables for Xen that map the following:
 *  1. Calculate page table's level numbers.
 *  2. Init mmu description structure.
 *  3. Check that linker addresses range doesn't overlap
 *     with load addresses range
 *  4. Map all linker addresses and load addresses ( it shouldn't
 *     be 1:1 mapped and will be 1:1 mapped only in case if
 *     linker address is equal to load address ) with
 *     RW permissions by default.
 *  5. Setup proper PTE permissions for each section.
 */
void __init setup_initial_pagetables(void)
{
    /*
     * Access to _start, _end is always PC-relative thereby when access
     * them we will get load adresses of start and end of Xen.
     * To get linker addresses LOAD_TO_LINK() is required to use.
     */
    unsigned long load_start    = (unsigned long)_start;
    unsigned long load_end      = (unsigned long)_end;
    unsigned long linker_start  = LOAD_TO_LINK(load_start);
    unsigned long linker_end    = LOAD_TO_LINK(load_end);

    if ( (linker_start != load_start) &&
         (linker_start <= load_end) && (load_start <= linker_end) )
    {
        early_printk("(XEN) linker and load address ranges overlap\n");
        die();
    }

    if ( !check_pgtbl_mode_support(&mmu_desc, load_start) )
    {
        early_printk("requested MMU mode isn't supported by CPU\n"
                     "Please choose different in <asm/config.h>\n");
        die();
    }

    mmu_desc.pgtbl_base = stage1_pgtbl_root;
    mmu_desc.next_pgtbl = stage1_pgtbl_nonroot;

    setup_initial_mapping(&mmu_desc,
                          linker_start,
                          linker_end,
                          load_start);

    if ( linker_start == load_start )
        return;

    setup_initial_mapping(&mmu_desc,
                          load_start,
                          load_end,
                          load_start);
}

void __init enable_mmu(void)
{
    /* Ensure page table writes precede loading the SATP */
    sfence_vma();

    /* Enable the MMU and load the new pagetable for Xen */
    csr_write(CSR_SATP,
              PFN_DOWN((unsigned long)stage1_pgtbl_root) |
              RV_STAGE1_MODE << SATP_MODE_SHIFT);
}

void __init remove_identity_mapping(void)
{
    unsigned int i;
    pte_t *pgtbl;
    unsigned int index, xen_index;
    unsigned long load_addr = LINK_TO_LOAD(_start);

    for ( pgtbl = stage1_pgtbl_root, i = 0;
          i <= (CONFIG_PAGING_LEVELS - 1);
          i++ )
    {
        index = pt_index(CONFIG_PAGING_LEVELS - 1 - i, load_addr);
        xen_index = pt_index(CONFIG_PAGING_LEVELS - 1 - i, XEN_VIRT_START);

        if ( index != xen_index )
        {
            pgtbl[index].pte = 0;
            break;
        }

        pgtbl = (pte_t *)pte_to_paddr(pgtbl[index]);
    }
}

/*
 * calc_phys_offset() should be used before MMU is enabled because access to
 * start() is PC-relative and in case when load_addr != linker_addr phys_offset
 * will have an incorrect value
 */
void __init calc_phys_offset(void)
{
    phys_offset = (unsigned long)start - XEN_VIRT_START;
}

void* __init early_fdt_map(paddr_t fdt_paddr)
{
    unsigned long dt_phys_base = fdt_paddr;
    unsigned long dt_virt_base;
    unsigned long dt_virt_size;

    dt_virt_base = LOAD_TO_LINK((unsigned long)_start) - fdt_totalsize(fdt_paddr);
    dt_virt_base &= XEN_PT_LEVEL_MAP_MASK(0);
    dt_virt_size = LOAD_TO_LINK((unsigned long)_start) - dt_virt_base;

    /* Map device tree */
    setup_initial_mapping(&mmu_desc, dt_virt_base,
                    dt_virt_base + dt_virt_size,
                    dt_phys_base);

    return (void *)dt_virt_base;
}

unsigned long get_upper_mfn_bound(void)
{
    /* No memory hotplug yet, so current memory limit is the final one. */
    return max_page - 1;
}

void put_page(struct page_info *page)
{
    put_page_nr(page, 1);
}

static struct domain *page_get_owner_and_nr_reference(struct page_info *page,
                                                      unsigned long nr)
{
    unsigned long x, y = page->count_info;
    struct domain *owner;

    /* Restrict nr to avoid "double" overflow */
    if ( nr >= PGC_count_mask )
    {
        ASSERT_UNREACHABLE();
        return NULL;
    }

    do {
        x = y;
        /*
         * Count ==  0: Page is not allocated, so we cannot take a reference.
         * Count == -1: Reference count would wrap, which is invalid.
         */
        if ( unlikely(((x + nr) & PGC_count_mask) <= nr) )
            return NULL;
    }
    while ( (y = cmpxchg(&page->count_info, x, x + nr)) != x );

    owner = page_get_owner(page);
    ASSERT(owner);

    return owner;
}

void put_page_nr(struct page_info *page, unsigned long nr)
{
    unsigned long nx, x, y = page->count_info;

    do {
        ASSERT((y & PGC_count_mask) >= nr);
        x  = y;
        nx = x - nr;
    }
    while ( unlikely((y = cmpxchg(&page->count_info, x, nx)) != x) );

    if ( unlikely((nx & PGC_count_mask) == 0) )
    {
        if ( unlikely(nx & PGC_static) )
            free_domstatic_page(page);
        else
            free_domheap_page(page);
    }
}

bool get_page_nr(struct page_info *page, const struct domain *domain,
                 unsigned long nr)
{
    const struct domain *owner = page_get_owner_and_nr_reference(page, nr);

    if ( likely(owner == domain) )
        return true;

    if ( owner != NULL )
        put_page_nr(page, nr);

    return false;
}

bool get_page(struct page_info *page, const struct domain *domain)
{
    return get_page_nr(page, domain, 1);
}

void put_page_type(struct page_info *page)
{
    return;
}

/* Common code requires get_page_type and put_page_type.
 * We don't care about typecounts so we just do the minimum to make it
 * happy. */
int get_page_type(struct page_info *page, unsigned long type)
{
    return 1;
}

int page_is_ram_type(unsigned long mfn, unsigned long mem_type)
{
    ASSERT_UNREACHABLE();
    return 0;
}

unsigned long domain_get_maximum_gpfn(struct domain *d)
{
    assert_failed("need to be implented\n");
    return 0;
}

int xenmem_add_to_physmap_one(struct domain *d, unsigned int space,
                              union add_to_physmap_extra extra,
                              unsigned long idx, gfn_t gfn)
{
    WARN();

    return 0;
}

struct domain *page_get_owner_and_reference(struct page_info *page)
{
    assert_failed("need to be implented\n");

    return NULL;
}

paddr_t __virt_to_maddr(vaddr_t va)
{
    assert_failed("need to be implented\n");

    return 0;
}

long arch_memory_op(int op, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    WARN();

    return 0;
}

int steal_page(struct domain *d, struct page_info *page, unsigned int memflags)
{
    return -EOPNOTSUPP;
}

void arch_dump_shared_mem_info(void)
{
    WARN();
}

static inline pte_t mfn_to_pte(mfn_t mfn)
{
    unsigned long pte = mfn_x(mfn) << PTE_PPN_SHIFT;
    return (pte_t){ .pte = pte};
}

inline pte_t mfn_to_xen_entry(mfn_t mfn, unsigned int attr)
{
    /* there is no attr field in RISC-V's pte */
    (void) attr;

    return mfn_to_pte(mfn);
}

/* Return the level where mapping should be done */
int xen_pt_mapping_level(unsigned long vfn, mfn_t mfn, unsigned long nr,
                                unsigned int flags)
{
    unsigned int level = 0;
    unsigned long mask;
    unsigned int i = 0;

    /*
     * Don't take into account the MFN when removing mapping (i.e
     * MFN_INVALID) to calculate the correct target order.
     *
     * Per the Arm Arm, `vfn` and `mfn` must be both superpage aligned.
     * They are or-ed together and then checked against the size of
     * each level.
     *
     * `left` is not included and checked separately to allow
     * superpage mapping even if it is not properly aligned (the
     * user may have asked to map 2MB + 4k).
     */
    mask = !mfn_eq(mfn, INVALID_MFN) ? mfn_x(mfn) : 0;
    mask |= vfn;

    /*
    * Always use level 3 mapping unless the caller request block
    * mapping.
    */
    if ( likely(!(flags & _PAGE_BLOCK)) )
        return level;

    for ( i = 0; i < CONFIG_PAGING_LEVELS; i++ )
    {
        if ( !(mask & (BIT(XEN_PT_LEVEL_ORDER(convert_level(i)), UL) - 1)) &&
            (nr >= BIT(XEN_PT_LEVEL_ORDER(convert_level(i)), UL)) )
        {
            level = convert_level(i);
            break;
        }
    }

    return level;
}

/*
 * Check whether the contiguous bit can be set. Return the number of
 * contiguous entry allowed. If not allowed, return 1.
 */
unsigned int xen_pt_check_contig(unsigned long vfn, mfn_t mfn,
                                 unsigned int level, unsigned long left,
                                 unsigned int flags)
{
    /* there is no contig bit in RISC-V */
    return 1;
}

void set_pte_table_bit(pte_t *pte, unsigned int tbl_bit_val)
{
    /* table bit for RISC-V is always equal to PTE_TABLE */
    (void) tbl_bit_val;

    pte->pte |= PTE_TABLE;
}

bool sanity_arch_specific_pte_checks(pte_t entry)
{
    /* there is no RISC-V specific PTE checks */
    return true;
}

unsigned int get_contig_bit(pte_t entry)
{
    /* there is no contig bit */
    (void) entry;

    return 0;
}

void set_pte_permissions(pte_t *pte, unsigned int flags)
{
    pte->bits.r = PAGE_RO_MASK(flags);
    pte->bits.x = ~PAGE_XN_MASK(flags);
    pte->bits.w = PAGE_W_MASK(flags);
}

const mfn_t get_root_page(void)
{
    unsigned long root_maddr = csr_read(CSR_SATP) << PAGE_SHIFT;

    return maddr_to_mfn(root_maddr);
}

inline void flush_xen_tlb_range_va(vaddr_t va,
                                   unsigned long size)
{
    /* TODO: implement  flush of specific range va */
    (void) va;
    (void) size;

    asm volatile("sfence.vma");
}

/*
 * Map the table that pte points to.
 */
void *map_xen_table(pte_t *pte)
{
    return (pte_t*)maddr_to_virt(pte_to_paddr(*pte));
}

/*
 * Map the table that pte points to.
 */
void *map_domain_table(pte_t *pte)
{
    return map_domain_page(maddr_to_mfn((paddr_t)pte_to_paddr(*pte)));
}

void unmap_domain_table(pte_t *table)
{
    return unmap_domain_page(table);
}

static void clean_page_info(struct page_info *page)
{
    void *p = __map_domain_page(page);

    clear_page(p);
    unmap_domain_page(p);
}

/* Creates a table using the correct allocator */
static int create_table(pte_t *pte, bool use_xenheap, struct domain *d)
{
    pte_t new;
    paddr_t phys_addr;

    BUG_ON( !d && !use_xenheap );
    BUG_ON( SYS_STATE_boot <= SYS_STATE_early_boot );
    BUG_ON( !pte );

    if ( !pte )
        return -EINVAL;

    if ( use_xenheap )
    {
        void *new_table = alloc_xenheap_page();

        if ( !new_table )
            return -ENOMEM;

        clear_page(new_table);
        phys_addr = virt_to_maddr(new_table);
    }
    else
    {
        struct page_info *page = alloc_domheap_pages(NULL, 1, 0);

        if ( !page )
            return -ENOMEM;

        page_list_add(page, &p2m_get_hostp2m(d)->pages);
        clean_page_info(page);
        phys_addr = page_to_maddr(page);
    }

    BUG_ON( !phys_addr );

    new = paddr_to_pte(phys_addr, 0x00);
    new.pte |= PTE_TABLE;
    write_pte(pte, new);

    return 0;
}


/*
 * Returns the page table pointed to by entry in table, indexed by va.
 *
 * table: the current page table
 * va: the virtual address to be mapped from
 * current_level: the level of arg table (l2, l1, l0 for sv39)
 * use_xenheap: use the xen heap if yes, otherwise yes
 *              the dom heap for allocating new tables
 * d: the domain the page table is for
 *
 * d is not used if uxe_xenheap == true.
 *
 * The table returned is mapped in (by map_domain_page if !use_xenheap, or
 * automatically if from xenheap), therefore if !use_xenheap, then the caller
 * must unmap the table using unmap_domain_page() after use.
 *
 * Returns the virtual address to the table.
 */
static pte_t *pt_next_level(pte_t *table, vaddr_t va, enum pt_level current_level,
                            bool use_xenheap, struct domain *d)
{
    pte_t *pte;
    unsigned long index;
    int rc;

    BUG_ON( SYS_STATE_boot <= SYS_STATE_early_boot );

    switch ( current_level )
    {
        case pt_level_zero:
            BUG();
            break;
        default:
            index = pt_index(current_level, va);
    }

    pte = &table[index];

    if ( pte_is_superpage(*pte, current_level) )
    {
        printk(XENLOG_ERR "Breaking up super pages not supported\n");
        return ERR_PTR(-EOPNOTSUPP);
    }

    if ( !pte_is_table(*pte, current_level) && current_level != pt_level_zero )
    {
        rc = create_table(pte, use_xenheap, d);

        if ( rc )
            return ERR_PTR(rc);
    }

    if ( use_xenheap )
        return (pte_t*)maddr_to_virt(pte_to_paddr(*pte));

    return (pte_t*)map_domain_page(maddr_to_mfn(pte_to_paddr(*pte)));
}

/*
 * Updates the page tables found at root with a mapping
 * from va to pa.
 *
 * root: the virtual address of the top level page table
 * va: the virtual address to be mapped from
 * pa: the physical address to be mapped to
 * use_xenheap: use the xen heap if yes, otherwise yes
 *              the dom heap for allocating new tables
 * d: the domain the page table is for
 *
 * d is not used if uxe_xenheap == true.
 *
 * Returns 0 on success, otherwise returns negative errno.
 */
int pt_update(vaddr_t root, vaddr_t va, paddr_t pa,
              bool use_xenheap, struct domain *d, unsigned long flags)
{
    pte_t new;
    pte_t *pte[CONFIG_PAGING_LEVELS] = { NULL };
    unsigned int i;
    int res = 0;

    BUG_ON( !root );
    BUG_ON( SYS_STATE_boot <= SYS_STATE_early_boot );

    for ( i = CONFIG_PAGING_LEVELS - 1, pte[i] = (pte_t *)root; i != 0; i-- )
    {
        pte[i - 1] = pt_next_level(pte[i], va, i, use_xenheap, d);
        if ( IS_ERR(pte[i - 1]) )
        {
            res = PTR_ERR(pte[i - 1]);
            goto out;
        }
    }

    new = paddr_to_pte(pa, PTE_VALID | flags);
    write_pte(&pte[0][pt_index(0, va)], new);

out:
    if ( !use_xenheap )
    {
        for ( i = 0; i < (CONFIG_PAGING_LEVELS - 1); i++)
        {
            if ( pte[i] )
                unmap_domain_page(pte[i]);
        }
    }

    return res;
}

/*
 * Returns a virtual to physical address mapping.
 *
 * root:   virtual address of the page table
 * va:     the virtual address
 * is_xen: set to true if the tables are off the xen heap, otherwise false.
 */
paddr_t pt_walk(vaddr_t root, vaddr_t va, bool is_xen)
{
    paddr_t pa;
    int i;
    pte_t *pte;
    unsigned long index;

    for ( i = CONFIG_PAGING_LEVELS - 1, pte = (pte_t *)root; i != 0 ; i--)
    {
        index = pt_index(i, va);

        if ( !pte_is_valid(pte[index]) || !pte_is_table(pte[index], i) )
        {
            pa = 0;
            goto out;
        }

        pte = &pte[index];
        pte = is_xen ? map_xen_table(pte) : map_domain_table(pte);
    }

    index = pt_index(i, va);

    if ( !pte_is_valid(pte[index]) )
    {
        pa = 0;
        goto out;
    }

    pa = pte_to_paddr(pte[index]) | (va & (PAGE_SIZE - 1));

out:
    if ( !is_xen )
    {
        int j = CONFIG_PAGING_LEVELS - 1;
        for ( pte = (pte_t *)root; j >= i; j--)
        {
            unmap_domain_table(pte);

            index = pt_index(j, va);
            pte = &pte[index];

        }
    }
    return pa;
}

/* Map a 4k page in a fixmap entry */
void set_fixmap(unsigned map, mfn_t mfn, unsigned int flags)
{
    pte_t pte;

    pte = mfn_to_xen_entry(mfn, 0x0);
    pte.pte |= PTE_LEAF_DEFAULT;
    write_pte(&xen_fixmap[pt_index(0, FIXMAP_ADDR(map))], pte);
}

/* Remove a mapping from a fixmap entry */
void clear_fixmap(unsigned map)
{
    pte_t pte = {0};
    write_pte(&xen_fixmap[pt_index(0, FIXMAP_ADDR(map))], pte);
}

