#include <xen/bug.h>
#include <xen/device_tree.h>
#include <xen/libfdt/libfdt.h>
#include <xen/mm.h>
#include <xen/pdx.h>
#include <xen/pfn.h>
#include <xen/setup.h>

#ifdef CONFIG_ACPI
extern bool acpi_disabled;
/* Basic configuration for ACPI */
static inline void disable_acpi(void)
{
    acpi_disabled = true;
}

static inline void enable_acpi(void)
{
    acpi_disabled = false;
}
#else
#define acpi_disabled (true)
#define disable_acpi()
#define enable_acpi()
#endif

/*
 * boot_cmdline_find_by_kind can only be used to return Xen modules (e.g
 * XSM, DTB) or Dom0 modules. This is not suitable for looking up guest
 * modules.
 */
struct bootcmdline * __init boot_cmdline_find_by_kind(bootmodule_kind kind)
{
    struct bootcmdlines *cmds = &bootinfo.cmdlines;
    struct bootcmdline *cmd;
    int i;

    for ( i = 0 ; i < cmds->nr_mods ; i++ )
    {
        cmd = &cmds->cmdline[i];
        if ( cmd->kind == kind && !cmd->domU )
            return cmd;
    }
    return NULL;
}

void __init add_boot_cmdline(const char *name, const char *cmdline,
                             bootmodule_kind kind, paddr_t start, bool domU)
{
    struct bootcmdlines *cmds = &bootinfo.cmdlines;
    struct bootcmdline *cmd;

    if ( cmds->nr_mods == MAX_MODULES )
    {
        printk("Ignoring %s cmdline (too many)\n", name);
        return;
    }

    cmd = &cmds->cmdline[cmds->nr_mods++];
    cmd->kind = kind;
    cmd->domU = domU;
    cmd->start = start;

    ASSERT(strlen(name) <= DT_MAX_NAME);
    safe_strcpy(cmd->dt_name, name);

    if ( strlen(cmdline) > BOOTMOD_MAX_CMDLINE )
        panic("module %s command line too long\n", name);
    safe_strcpy(cmd->cmdline, cmdline);
}

struct bootmodule __init *add_boot_module(bootmodule_kind kind,
                                          paddr_t start, paddr_t size,
                                          bool domU)
{
    struct bootmodules *mods = &bootinfo.modules;
    struct bootmodule *mod;
    unsigned int i;

    if ( mods->nr_mods == MAX_MODULES )
    {
        printk("Ignoring %s boot module at %"PRIpaddr"-%"PRIpaddr" (too many)\n",
               boot_module_kind_as_string(kind), start, start + size);
        return NULL;
    }
    for ( i = 0 ; i < mods->nr_mods ; i++ )
    {
        mod = &mods->module[i];
        if ( mod->kind == kind && mod->start == start )
        {
            if ( !domU )
                mod->domU = false;
            return mod;
        }
    }

    mod = &mods->module[mods->nr_mods++];
    mod->kind = kind;
    mod->start = start;
    mod->size = size;
    mod->domU = domU;

    return mod;
}

const char * __init boot_module_kind_as_string(bootmodule_kind kind)
{
    switch ( kind )
    {
    case BOOTMOD_XEN:     return "Xen";
    case BOOTMOD_FDT:     return "Device Tree";
    case BOOTMOD_KERNEL:  return "Kernel";
    case BOOTMOD_RAMDISK: return "Ramdisk";
    case BOOTMOD_XSM:     return "XSM";
    case BOOTMOD_GUEST_DTB:     return "DTB";
    case BOOTMOD_UNKNOWN: return "Unknown";
    default: BUG();
    }
}

static void __init dt_unreserved_regions(paddr_t s, paddr_t e,
                                         void (*cb)(paddr_t, paddr_t),
                                         unsigned int first)
{
    unsigned int i, nr;
    int rc;

    rc = fdt_num_mem_rsv(device_tree_flattened);
    if ( rc < 0 )
        panic("Unable to retrieve the number of reserved regions (rc=%d)\n",
              rc);

    nr = rc;

    for ( i = first; i < nr ; i++ )
    {
        paddr_t r_s, r_e;

        if ( fdt_get_mem_rsv(device_tree_flattened, i, &r_s, &r_e ) < 0 )
            /* If we can't read it, pretend it doesn't exist... */
            continue;

        r_e += r_s; /* fdt_get_mem_rsv returns length */

        if ( s < r_e && r_s < e )
        {
            dt_unreserved_regions(r_e, e, cb, i+1);
            dt_unreserved_regions(s, r_s, cb, i+1);
            return;
        }
    }

    /*
     * i is the current bootmodule we are evaluating across all possible
     * kinds.
     *
     * When retrieving the corresponding reserved-memory addresses
     * below, we need to index the bootinfo.reserved_mem bank starting
     * from 0, and only counting the reserved-memory modules. Hence,
     * we need to use i - nr.
     */
    for ( ; i - nr < bootinfo.reserved_mem.nr_banks; i++ )
    {
        paddr_t r_s = bootinfo.reserved_mem.bank[i - nr].start;
        paddr_t r_e = r_s + bootinfo.reserved_mem.bank[i - nr].size;

        if ( s < r_e && r_s < e )
        {
            dt_unreserved_regions(r_e, e, cb, i + 1);
            dt_unreserved_regions(s, r_s, cb, i + 1);
            return;
        }
    }

    cb(s, e);
}

void __init fw_unreserved_regions(paddr_t s, paddr_t e,
                                  void (*cb)(paddr_t, paddr_t),
                                  unsigned int first)
{
    if ( acpi_disabled )
        dt_unreserved_regions(s, e, cb, first);
    else
        cb(s, e);
}

/*
 * Return the end of the non-module region starting at s. In other
 * words return s the start of the next modules after s.
 *
 * On input *end is the end of the region which should be considered
 * and it is updated to reflect the end of the module, clipped to the
 * end of the region if it would run over.
 */
static paddr_t __init next_module(paddr_t s, paddr_t *end)
{
    struct bootmodules *mi = &bootinfo.modules;
    paddr_t lowest = ~(paddr_t)0;
    int i;

    for ( i = 0; i < mi->nr_mods; i++ )
    {
        paddr_t mod_s = mi->module[i].start;
        paddr_t mod_e = mod_s + mi->module[i].size;

        if ( !mi->module[i].size )
            continue;

        if ( mod_s < s )
            continue;
        if ( mod_s > lowest )
            continue;
        if ( mod_s > *end )
            continue;
        lowest = mod_s;
        *end = min(*end, mod_e);
    }
    return lowest;
}

static void __init init_pdx(void)
{
    paddr_t bank_start, bank_size, bank_end;

    /*
     * Arm does not have any restrictions on the bits to compress. Pass 0 to
     * let the common code further restrict the mask.
     *
     * If the logic changes in pfn_pdx_hole_setup we might have to
     * update this function too.
     */
    uint64_t mask = pdx_init_mask(0x0);
    int bank;

    for ( bank = 0 ; bank < bootinfo.mem.nr_banks; bank++ )
    {
        bank_start = bootinfo.mem.bank[bank].start;
        bank_size = bootinfo.mem.bank[bank].size;

        mask |= bank_start | pdx_region_mask(bank_start, bank_size);
    }

    for ( bank = 0 ; bank < bootinfo.mem.nr_banks; bank++ )
    {
        bank_start = bootinfo.mem.bank[bank].start;
        bank_size = bootinfo.mem.bank[bank].size;

        if (~mask & pdx_region_mask(bank_start, bank_size))
            mask = 0;
    }

    pfn_pdx_hole_setup(mask >> PAGE_SHIFT);

    for ( bank = 0 ; bank < bootinfo.mem.nr_banks; bank++ )
    {
        bank_start = bootinfo.mem.bank[bank].start;
        bank_size = bootinfo.mem.bank[bank].size;
        bank_end = bank_start + bank_size;

        set_pdx_range(paddr_to_pfn(bank_start),
                      paddr_to_pfn(bank_end));
    }
}

/* Static memory initialization */
static void __init init_staticmem_pages(void)
{
#ifdef CONFIG_STATIC_MEMORY
    unsigned int bank;

    for ( bank = 0 ; bank < bootinfo.reserved_mem.nr_banks; bank++ )
    {
        if ( bootinfo.reserved_mem.bank[bank].type == MEMBANK_STATIC_DOMAIN )
        {
            mfn_t bank_start = _mfn(PFN_UP(bootinfo.reserved_mem.bank[bank].start));
            unsigned long bank_pages = PFN_DOWN(bootinfo.reserved_mem.bank[bank].size);
            mfn_t bank_end = mfn_add(bank_start, bank_pages);

            if ( mfn_x(bank_end) <= mfn_x(bank_start) )
                return;

            unprepare_staticmem_pages(mfn_to_page(bank_start),
                                      bank_pages, false);
        }
    }
#endif
}

/*
 * Populate the boot allocator.
 * If a static heap was not provided by the admin, all the RAM but the
 * following regions will be added:
 *  - Modules (e.g., Xen, Kernel)
 *  - Reserved regions
 *  - Xenheap (arm32 only)
 * If a static heap was provided by the admin, populate the boot
 * allocator with the corresponding regions only, but with Xenheap excluded
 * on arm32.
 */
static void __init populate_boot_allocator(void)
{
    unsigned int i;
    const struct meminfo *banks = &bootinfo.mem;
    paddr_t s, e;

    if ( bootinfo.static_heap )
    {
        for ( i = 0 ; i < bootinfo.reserved_mem.nr_banks; i++ )
        {
            if ( bootinfo.reserved_mem.bank[i].type != MEMBANK_STATIC_HEAP )
                continue;

            s = bootinfo.reserved_mem.bank[i].start;
            e = s + bootinfo.reserved_mem.bank[i].size;
#ifdef CONFIG_ARM_32
            /* Avoid the xenheap, note that the xenheap cannot across a bank */
            if ( s <= mfn_to_maddr(directmap_mfn_start) &&
                 e >= mfn_to_maddr(directmap_mfn_end) )
            {
                init_boot_pages(s, mfn_to_maddr(directmap_mfn_start));
                init_boot_pages(mfn_to_maddr(directmap_mfn_end), e);
            }
            else
#endif
                init_boot_pages(s, e);
        }

        return;
    }

    for ( i = 0; i < banks->nr_banks; i++ )
    {
        const struct membank *bank = &banks->bank[i];
        paddr_t bank_end = bank->start + bank->size;

        s = bank->start;
        while ( s < bank_end )
        {
            paddr_t n = bank_end;

            e = next_module(s, &n);

            if ( e == ~(paddr_t)0 )
                e = n = bank_end;

            /*
             * Module in a RAM bank other than the one which we are
             * not dealing with here.
             */
            if ( e > bank_end )
                e = bank_end;

#ifdef CONFIG_ARM_32
            /* Avoid the xenheap */
            if ( s < mfn_to_maddr(directmap_mfn_end) &&
                 mfn_to_maddr(directmap_mfn_start) < e )
            {
                e = mfn_to_maddr(directmap_mfn_start);
                n = mfn_to_maddr(directmap_mfn_end);
            }
#endif

            fw_unreserved_regions(s, e, init_boot_pages, 0);
            s = n;
        }
    }
}

#ifdef CONFIG_ARM_32
void __init setup_mm(void)
{
    paddr_t ram_start, ram_end, ram_size, e, bank_start, bank_end, bank_size;
    paddr_t static_heap_end = 0, static_heap_size = 0;
    unsigned long heap_pages, xenheap_pages, domheap_pages;
    unsigned int i;
    const uint32_t ctr = READ_CP32(CTR);

    if ( !bootinfo.mem.nr_banks )
        panic("No memory bank\n");

    /* We only supports instruction caches implementing the IVIPT extension. */
    if ( ((ctr >> CTR_L1IP_SHIFT) & CTR_L1IP_MASK) == ICACHE_POLICY_AIVIVT )
        panic("AIVIVT instruction cache not supported\n");

    init_pdx();

    ram_start = bootinfo.mem.bank[0].start;
    ram_size  = bootinfo.mem.bank[0].size;
    ram_end   = ram_start + ram_size;

    for ( i = 1; i < bootinfo.mem.nr_banks; i++ )
    {
        bank_start = bootinfo.mem.bank[i].start;
        bank_size = bootinfo.mem.bank[i].size;
        bank_end = bank_start + bank_size;

        ram_size  = ram_size + bank_size;
        ram_start = min(ram_start,bank_start);
        ram_end   = max(ram_end,bank_end);
    }

    total_pages = ram_size >> PAGE_SHIFT;

    if ( bootinfo.static_heap )
    {
        for ( i = 0 ; i < bootinfo.reserved_mem.nr_banks; i++ )
        {
            if ( bootinfo.reserved_mem.bank[i].type != MEMBANK_STATIC_HEAP )
                continue;

            bank_start = bootinfo.reserved_mem.bank[i].start;
            bank_size = bootinfo.reserved_mem.bank[i].size;
            bank_end = bank_start + bank_size;

            static_heap_size += bank_size;
            static_heap_end = max(static_heap_end, bank_end);
        }

        heap_pages = static_heap_size >> PAGE_SHIFT;
    }
    else
        heap_pages = total_pages;

    /*
     * If the user has not requested otherwise via the command line
     * then locate the xenheap using these constraints:
     *
     *  - must be contiguous
     *  - must be 32 MiB aligned
     *  - must not include Xen itself or the boot modules
     *  - must be at most 1GB or 1/32 the total RAM in the system (or static
          heap if enabled) if less
     *  - must be at least 32M
     *
     * We try to allocate the largest xenheap possible within these
     * constraints.
     */
    if ( opt_xenheap_megabytes )
        xenheap_pages = opt_xenheap_megabytes << (20-PAGE_SHIFT);
    else
    {
        xenheap_pages = (heap_pages/32 + 0x1fffUL) & ~0x1fffUL;
        xenheap_pages = max(xenheap_pages, 32UL<<(20-PAGE_SHIFT));
        xenheap_pages = min(xenheap_pages, 1UL<<(30-PAGE_SHIFT));
    }

    do
    {
        e = bootinfo.static_heap ?
            fit_xenheap_in_static_heap(pfn_to_paddr(xenheap_pages), MB(32)) :
            consider_modules(ram_start, ram_end,
                             pfn_to_paddr(xenheap_pages),
                             32<<20, 0);
        if ( e )
            break;

        xenheap_pages >>= 1;
    } while ( !opt_xenheap_megabytes && xenheap_pages > 32<<(20-PAGE_SHIFT) );

    if ( ! e )
        panic("Not enough space for xenheap\n");

    domheap_pages = heap_pages - xenheap_pages;

    printk("Xen heap: %"PRIpaddr"-%"PRIpaddr" (%lu pages%s)\n",
           e - (pfn_to_paddr(xenheap_pages)), e, xenheap_pages,
           opt_xenheap_megabytes ? ", from command-line" : "");
    printk("Dom heap: %lu pages\n", domheap_pages);

    /*
     * We need some memory to allocate the page-tables used for the
     * directmap mappings. So populate the boot allocator first.
     *
     * This requires us to set directmap_mfn_{start, end} first so the
     * direct-mapped Xenheap region can be avoided.
     */
    directmap_mfn_start = _mfn((e >> PAGE_SHIFT) - xenheap_pages);
    directmap_mfn_end = mfn_add(directmap_mfn_start, xenheap_pages);

    populate_boot_allocator();

    setup_directmap_mappings(mfn_x(directmap_mfn_start), xenheap_pages);

    /* Frame table covers all of RAM region, including holes */
    setup_frametable_mappings(ram_start, ram_end);
    max_page = PFN_DOWN(ram_end);

    /*
     * The allocators may need to use map_domain_page() (such as for
     * scrubbing pages). So we need to prepare the domheap area first.
     */
    if ( !init_domheap_mappings(smp_processor_id()) )
        panic("CPU%u: Unable to prepare the domheap page-tables\n",
              smp_processor_id());

    /* Add xenheap memory that was not already added to the boot allocator. */
    init_xenheap_pages(mfn_to_maddr(directmap_mfn_start),
                       mfn_to_maddr(directmap_mfn_end));

    init_staticmem_pages();
}
#else /* CONFIG_ARM_64 */
void __init setup_mm(void)
{
    const struct meminfo *banks = &bootinfo.mem;
    paddr_t ram_start = INVALID_PADDR;
    paddr_t ram_end = 0;
    paddr_t ram_size = 0;
    unsigned int i;

    init_pdx();

    /*
     * We need some memory to allocate the page-tables used for the directmap
     * mappings. But some regions may contain memory already allocated
     * for other uses (e.g. modules, reserved-memory...).
     *
     * For simplicity, add all the free regions in the boot allocator.
     */
    populate_boot_allocator();

    total_pages = 0;

    for ( i = 0; i < banks->nr_banks; i++ )
    {
        const struct membank *bank = &banks->bank[i];
        paddr_t bank_end = bank->start + bank->size;

        ram_size = ram_size + bank->size;
        ram_start = min(ram_start, bank->start);
        ram_end = max(ram_end, bank_end);

        setup_directmap_mappings(PFN_DOWN(bank->start),
                                 PFN_DOWN(bank->size));
    }

    total_pages += ram_size >> PAGE_SHIFT;

    directmap_virt_end = XENHEAP_VIRT_START + ram_end - ram_start;
    directmap_mfn_start = maddr_to_mfn(ram_start);
    directmap_mfn_end = maddr_to_mfn(ram_end);

    setup_frametable_mappings(ram_start, ram_end);
    max_page = PFN_DOWN(ram_end);

    init_staticmem_pages();
}
#endif

