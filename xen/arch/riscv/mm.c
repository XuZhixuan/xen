/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/cache.h>
#include <xen/compiler.h>
#include <xen/domain_page.h>
#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/pfn.h>
#include <xen/lib.h>
#include <xen/libfdt/libfdt.h>
#include <xen/mm.h>
#include <xen/page-size.h>
#include <xen/pmap.h>
#include <asm/early_printk.h>

#include <asm/early_printk.h>
#include <asm/csr.h>
#include <asm/current.h>
#include <asm/page.h>
#include <asm/processor.h>

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
    assert_failed("need to implement");
}

bool get_page(struct page_info *page, const struct domain *domain)
{
    assert_failed("need to implement");

    return false;
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

int destroy_xen_mappings(unsigned long v, unsigned long e)
{
    (void) v;
    (void) e;

    assert_failed(__func__);

    return 0;
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

/* Returns a virtual to physical address mapping.
 *
 * root:   virtual address of the page table
 * va:     the virtual address
 * is_xen: set to true if the tables are off the xen heap, otherwise false.
 */
paddr_t pt_walk(vaddr_t root, vaddr_t va, bool is_xen)
{
    paddr_t pa;
    pte_t *second, *first, *zeroeth;
    unsigned long index0, index1, index2;

    BUILD_BUG_ON(CONFIG_PAGING_LEVELS != 3);

    /* TODO: make the func more generic */

    second = (pte_t*)root;
    index2 = pt_index(2, va);

    if ( !pte_is_valid(second[index2]) || !pte_is_table(second[index2], 2) )
    {
        pa = 0;
        goto out;
    }

    first = &second[index2];
    first = is_xen ? map_xen_table(first) : map_domain_table(first);

    index1 = pt_index(1, va);

    if ( !pte_is_valid(first[index1]) || !pte_is_table(first[index1], 1) )
    {
        pa = 0;
        goto out;
    }

    zeroeth = &first[index1];
    zeroeth = is_xen ? map_xen_table(zeroeth) : map_domain_table(zeroeth);

    index0 = pt_index(0, va);

    if ( !pte_is_valid(zeroeth[index0]) )
    {
        pa = 0;
        goto out;
    }

    pa = pte_to_paddr(zeroeth[index0]) | (va & (PAGE_SIZE - 1));

out:
    if ( !is_xen ) {
        unmap_domain_table(second);
        unmap_domain_table(first);
        unmap_domain_table(zeroeth);
    }
    return pa;
}

