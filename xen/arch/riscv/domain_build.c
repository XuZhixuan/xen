#include <asm/domain_build.h>
#include <asm/guest_access.h>
#include <xen/domain.h>
#include <xen/err.h>
#include <xen/grant_table.h>
#include <xen/mm.h>
#include <xen/vmap.h>
#include <xen/param.h>
#include <xen/sched.h>
#include <xen/setup.h>
#include <xen/sizes.h>
#include <xen/warning.h>
#include <xen/libfdt/libfdt.h>
#include <xen/iocap.h>

#include <asm/fdtdump.h>
#include <asm/gic.h>
#include <asm/kernel.h>
#include <asm/vsbi_uart.h>

static unsigned int __initdata opt_dom0_max_vcpus;
integer_param("dom0_max_vcpus", opt_dom0_max_vcpus);

static u64 __initdata dom0_mem;
static bool __initdata dom0_mem_set;

int __init parse_arch_dom0_param(const char *s, const char *e)
{
    printk("%s: nothing to parse for now?\n", __func__);

    return -EINVAL;
}

/*
 * Amount of extra space required to dom0's device tree.  No new nodes
 * are added (yet) but one terminating reserve map entry (16 bytes) is
 * added.
 */
#define DOM0_FDT_EXTRA_SIZE (128 + sizeof(struct fdt_reserve_entry))

static int __init parse_dom0_mem(const char *s)
{
    dom0_mem_set = true;

    dom0_mem = parse_size_and_unit(s, &s);

    return *s ? -EINVAL : 0;
}
custom_param("dom0_mem", parse_dom0_mem);

unsigned int __init dom0_max_vcpus(void)
{
    if ( opt_dom0_max_vcpus == 0 )
    {
        ASSERT(cpupool0);
        opt_dom0_max_vcpus = cpumask_weight(cpupool_valid_cpus(cpupool0));
    }
    if ( opt_dom0_max_vcpus > NR_VCPUS )
        opt_dom0_max_vcpus = NR_VCPUS;

    return opt_dom0_max_vcpus;
}

static unsigned int __init get_allocation_size(paddr_t size)
{
    /*
     * get_order_from_bytes returns the order greater than or equal to
     * the given size, but we need less than or equal. Adding one to
     * the size pushes an evenly aligned size into the next order, so
     * we can then unconditionally subtract 1 from the order which is
     * returned.
     */
    return get_order_from_bytes(size + 1) - 1;
}

/*
 * Insert the given pages into a memory bank, banks are ordered by address.
 *
 * Returns false if the memory would be below bank 0 or we have run
 * out of banks. In this case it will free the pages.
 */
static bool __init insert_11_bank(struct domain *d,
                                  struct kernel_info *kinfo,
                                  struct page_info *pg,
                                  unsigned int order)
{
    unsigned int i;
    int res;
    mfn_t smfn;
    paddr_t start, size;

    smfn = page_to_mfn(pg);
    start = mfn_to_maddr(smfn);
    size = pfn_to_paddr(1UL << order);

    printk("Allocated %#"PRIpaddr"-%#"PRIpaddr" (%ldMB/%ldMB, order %d)\n",
             start, start + size,
             1UL << (order + PAGE_SHIFT - 20),
             /* Don't want format this as PRIpaddr (16 digit hex) */
             (unsigned long)(kinfo->unassigned_mem >> 20),
             order);

    if ( kinfo->mem.nr_banks > 0 &&
         size < MB(128) &&
         start + size < kinfo->mem.bank[0].start )
    {
        printk("Allocation below bank 0 is too small, not using\n");
        goto fail;
    }

    res = guest_physmap_add_page(d, _gfn(mfn_x(smfn)), smfn, order);
    if ( res )
        panic("Failed map pages to DOM0: %d\n", res);

    kinfo->unassigned_mem -= size;

    if ( kinfo->mem.nr_banks == 0 )
    {
        kinfo->mem.bank[0].start = start;
        kinfo->mem.bank[0].size = size;
        kinfo->mem.nr_banks = 1;
        return true;
    }

    for( i = 0; i < kinfo->mem.nr_banks; i++ )
    {
        struct membank *bank = &kinfo->mem.bank[i];

        /* If possible merge new memory into the start of the bank */
        if ( bank->start == start+size )
        {
            bank->start = start;
            bank->size += size;
            return true;
        }

        /* If possible merge new memory onto the end of the bank */
        if ( start == bank->start + bank->size )
        {
            bank->size += size;
            return true;
        }

        /*
         * Otherwise if it is below this bank insert new memory in a
         * new bank before this one. If there was a lower bank we
         * could have inserted the memory into/before we would already
         * have done so, so this must be the right place.
         */
        if ( start + size < bank->start && kinfo->mem.nr_banks < NR_MEM_BANKS )
        {
            memmove(bank + 1, bank,
                    sizeof(*bank) * (kinfo->mem.nr_banks - i));
            kinfo->mem.nr_banks++;
            bank->start = start;
            bank->size = size;
            return true;
        }
    }

    if ( i == kinfo->mem.nr_banks && kinfo->mem.nr_banks < NR_MEM_BANKS )
    {
        struct membank *bank = &kinfo->mem.bank[kinfo->mem.nr_banks];

        bank->start = start;
        bank->size = size;
        kinfo->mem.nr_banks++;
        return true;
    }

    /* If we get here then there are no more banks to fill. */

fail:
    free_domheap_pages(pg, order);
    return false;
}

/*
 * This is all pretty horrible.
 *
 * Requirements:
 *
 * 1. The dom0 kernel should be loaded within the first 128MB of RAM. This
 *    is necessary at least for Linux zImage kernels, which are all we
 *    support today.
 * 2. We want to put the dom0 kernel, ramdisk and DTB in the same
 *    bank. Partly this is just easier for us to deal with, but also
 *    the ramdisk and DTB must be placed within a certain proximity of
 *    the kernel within RAM.
 * 3. For dom0 we want to place as much of the RAM as we reasonably can
 *    below 4GB, so that it can be used by non-LPAE enabled kernels (32-bit).
 * 4. Some devices assigned to dom0 can only do 32-bit DMA access or
 *    even be more restricted. We want to allocate as much of the RAM
 *    as we reasonably can that can be accessed from all the devices..
 * 5. For 32-bit dom0 the kernel must be located below 4GB.
 * 6. We want to have a few largers banks rather than many smaller ones.
 *
 * For the first two requirements we need to make sure that the lowest
 * bank is sufficiently large.
 *
 * For convenience we also sort the banks by physical address.
 *
 * The memory allocator does not really give us the flexibility to
 * meet these requirements directly. So instead of proceed as follows:
 *
 * We first allocate the largest allocation we can as low as we
 * can. This then becomes the first bank. This bank must be at least
 * 128MB (or dom0_mem if that is smaller).
 *
 * Then we start allocating more memory, trying to allocate the
 * largest possible size and trying smaller sizes until we
 * successfully allocate something.
 *
 * We then try and insert this memory in to the list of banks. If it
 * can be merged into an existing bank then this is trivial.
 *
 * If the new memory is before the first bank (and cannot be merged into it)
 * and is at least 128M then we allow it, otherwise we give up. Since the
 * allocator prefers to allocate high addresses first and the first bank has
 * already been allocated to be as low as possible this likely means we
 * wouldn't have been able to allocate much more memory anyway.
 *
 * Otherwise we insert a new bank. If we've reached MAX_NR_BANKS then
 * we give up.
 *
 * For 32-bit domain we require that the initial allocation for the
 * first bank is part of the low mem. For 64-bit, the first bank is preferred
 * to be allocated in the low mem. Then for subsequent allocation, we
 * initially allocate memory only from low mem. Once that runs out out
 * (as described above) we allow higher allocations and continue until
 * that runs out (or we have allocated sufficient dom0 memory).
 */
static void __init allocate_memory_11(struct domain *d,
                                      struct kernel_info *kinfo)
{
    const unsigned int min_low_order =
        get_order_from_bytes(min_t(paddr_t, dom0_mem, MB(128)));
    const unsigned int min_order = get_order_from_bytes(MB(4));
    struct page_info *pg;
    unsigned int order = get_allocation_size(kinfo->unassigned_mem);
    unsigned int i;

    bool lowmem = true;
    unsigned int lowmem_bitsize = min(32U, arch_get_dma_bitsize());
    unsigned int bits;

    /*
     * TODO: Implement memory bank allocation when DOM0 is not direct
     * mapped
     */
    BUG_ON(!is_domain_direct_mapped(d));

    printk("Allocating 1:1 mappings totalling %ldMB for dom0:\n",
           /* Don't want format this as PRIpaddr (16 digit hex) */
           (unsigned long)(kinfo->unassigned_mem >> 20));

    kinfo->mem.nr_banks = 0;

    /*
     * First try and allocate the largest thing we can as low as
     * possible to be bank 0.
     */
    while ( order >= min_low_order )
    {
        for ( bits = order ; bits <= lowmem_bitsize; bits++ )
        {
            pg = alloc_domheap_pages(d, order, MEMF_bits(bits));
            if ( pg != NULL )
            {
                if ( !insert_11_bank(d, kinfo, pg, order) )
                    BUG(); /* Cannot fail for first bank */

                goto got_bank0;
            }
        }
        order--;
    }

    /* Failed to allocate bank0 in the lowmem region. */
    if ( is_32bit_domain(d) )
        panic("Unable to allocate first memory bank\n");

    /* Try to allocate memory from above the lowmem region */
    printk(XENLOG_INFO "No bank has been allocated below %u-bit.\n",
           lowmem_bitsize);
    lowmem = false;

 got_bank0:

    /*
     * If we failed to allocate bank0 in the lowmem region,
     * continue allocating from above the lowmem and fill in banks.
     */
    order = get_allocation_size(kinfo->unassigned_mem);
    while ( kinfo->unassigned_mem && kinfo->mem.nr_banks < NR_MEM_BANKS )
    {
        pg = alloc_domheap_pages(d, order,
                                 lowmem ? MEMF_bits(lowmem_bitsize) : 0);
        if ( !pg )
        {
            order --;

            if ( lowmem && order < min_low_order)
            {
                printk("Failed at min_low_order, allow high allocations\n");
                order = get_allocation_size(kinfo->unassigned_mem);
                lowmem = false;
                continue;
            }
            if ( order >= min_order )
                continue;

            /* No more we can do */
            break;
        }

        if ( !insert_11_bank(d, kinfo, pg, order) )
        {
            if ( kinfo->mem.nr_banks == NR_MEM_BANKS )
                /* Nothing more we can do. */
                break;

            if ( lowmem )
            {
                printk("Allocation below bank 0, allow high allocations\n");
                order = get_allocation_size(kinfo->unassigned_mem);
                lowmem = false;
                continue;
            }
            else
            {
                printk("Allocation below bank 0\n");
                break;
            }
        }

        /*
         * Success, next time around try again to get the largest order
         * allocation possible.
         */
        order = get_allocation_size(kinfo->unassigned_mem);
    }

    if ( kinfo->unassigned_mem )
        /* Don't want format this as PRIpaddr (16 digit hex) */
        panic("Failed to allocate requested dom0 memory. %ldMB unallocated\n",
              (unsigned long)kinfo->unassigned_mem >> 20);

    for( i = 0; i < kinfo->mem.nr_banks; i++ )
    {
        printk("BANK[%d] %#"PRIpaddr"-%#"PRIpaddr" (%ldMB)\n",
               i,
               kinfo->mem.bank[i].start,
               kinfo->mem.bank[i].start + kinfo->mem.bank[i].size,
               /* Don't want format this as PRIpaddr (16 digit hex) */
               (unsigned long)(kinfo->mem.bank[i].size >> 20));
    }
}

static bool __init allocate_bank_memory(struct domain *d,
                                        struct kernel_info *kinfo,
                                        gfn_t sgfn,
                                        paddr_t tot_size)
{
    int res;
    struct page_info *pg;
    struct membank *bank;
    unsigned int max_order = ~0;

    bank = &kinfo->mem.bank[kinfo->mem.nr_banks];
    bank->start = gfn_to_gaddr(sgfn);
    bank->size = tot_size;

    while ( tot_size > 0 )
    {
        unsigned int order = get_allocation_size(tot_size);

        order = min(max_order, order);

        pg = alloc_domheap_pages(d, order, 0);
        if ( !pg )
        {
            /*
             * If we can't allocate one page, then it is unlikely to
             * succeed in the next iteration. So bail out.
             */
            if ( !order )
                return false;

            /*
             * If we can't allocate memory with order, then it is
             * unlikely to succeed in the next iteration.
             * Record the order - 1 to avoid re-trying.
             */
            max_order = order - 1;
            continue;
        }

        res = guest_physmap_add_page(d, sgfn, page_to_mfn(pg), order);
        if ( res )
        {
            dprintk(XENLOG_ERR, "Failed map pages to DOMU: %d", res);
            return false;
        }

        sgfn = gfn_add(sgfn, 1UL << order);
        tot_size -= (1ULL << (PAGE_SHIFT + order));
    }

    kinfo->mem.nr_banks++;
    kinfo->unassigned_mem -= bank->size;

    return true;
}

static void __init allocate_memory(struct domain *d, struct kernel_info *kinfo)
{
    unsigned int i;
    paddr_t bank_size;

    printk(XENLOG_INFO "Allocating mappings totalling %ldMB for %pd:\n",
           /* Don't want format this as PRIpaddr (16 digit hex) */
           (unsigned long)(kinfo->unassigned_mem >> 20), d);

    kinfo->mem.nr_banks = 0;
    bank_size = MIN(GUEST_RAM0_SIZE, kinfo->unassigned_mem);
    if ( !allocate_bank_memory(d, kinfo, gaddr_to_gfn(GUEST_RAM0_BASE),
                               bank_size) )
        goto fail;

    if ( kinfo->unassigned_mem )
        goto fail;

    for( i = 0; i < kinfo->mem.nr_banks; i++ )
    {
        printk(XENLOG_INFO "%pd BANK[%d] %#"PRIpaddr"-%#"PRIpaddr" (%ldMB)\n",
               d,
               i,
               kinfo->mem.bank[i].start,
               kinfo->mem.bank[i].start + kinfo->mem.bank[i].size,
               /* Don't want format this as PRIpaddr (16 digit hex) */
               (unsigned long)(kinfo->mem.bank[i].size >> 20));
    }

    return;

fail:
    panic("Failed to allocate requested domain memory."
          /* Don't want format this as PRIpaddr (16 digit hex) */
          " %ldKB unallocated. Fix the VMs configurations.\n",
          (unsigned long)kinfo->unassigned_mem >> 10);
}

static int __init write_properties(struct domain *d, struct kernel_info *kinfo,
                                   const struct dt_device_node *node)
{
    const char *bootargs = NULL;
    const struct dt_property *prop, *status = NULL;
    int res = 0;
    int had_dom0_bootargs = 0;
    struct dt_device_node *iommu_node;

    if ( kinfo->cmdline && kinfo->cmdline[0] )
        bootargs = &kinfo->cmdline[0];

    /*
     * We always skip the IOMMU device when creating DT for hwdom if there is
     * an appropriate driver for it in Xen (device_get_class(iommu_node)
     * returns DEVICE_IOMMU).
     * We should also skip the IOMMU specific properties of the master device
     * behind that IOMMU in order to avoid exposing an half complete IOMMU
     * bindings to hwdom.
     * Use "iommu_node" as an indicator of the master device which properties
     * should be skipped.
     */
    iommu_node = dt_parse_phandle(node, "iommus", 0);
    if ( iommu_node && device_get_class(iommu_node) != DEVICE_IOMMU )
        iommu_node = NULL;

    dt_for_each_property_node (node, prop)
    {
        const void *prop_data = prop->value;
        u32 prop_len = prop->length;

        /*
         * In chosen node:
         *
         * * remember xen,dom0-bootargs if we don't already have
         *   bootargs (from module #1, above).
         * * remove bootargs,  xen,dom0-bootargs, xen,xen-bootargs,
         *   linux,initrd-start and linux,initrd-end.
         * * remove stdout-path.
         * * remove bootargs, linux,uefi-system-table,
         *   linux,uefi-mmap-start, linux,uefi-mmap-size,
         *   linux,uefi-mmap-desc-size, and linux,uefi-mmap-desc-ver
         *   (since EFI boot is not currently supported in dom0).
         */
        if ( dt_node_path_is_equal(node, "/chosen") )
        {
            if ( dt_property_name_is_equal(prop, "xen,xen-bootargs") ||
                 dt_property_name_is_equal(prop, "linux,initrd-start") ||
                 dt_property_name_is_equal(prop, "linux,initrd-end") ||
                 dt_property_name_is_equal(prop, "stdout-path") ||
                 dt_property_name_is_equal(prop, "linux,uefi-system-table") ||
                 dt_property_name_is_equal(prop, "linux,uefi-mmap-start") ||
                 dt_property_name_is_equal(prop, "linux,uefi-mmap-size") ||
                 dt_property_name_is_equal(prop, "linux,uefi-mmap-desc-size") ||
                 dt_property_name_is_equal(prop, "linux,uefi-mmap-desc-ver"))
                continue;

            if ( dt_property_name_is_equal(prop, "xen,dom0-bootargs") )
            {
                had_dom0_bootargs = 1;
                bootargs = prop->value;
                continue;
            }
            if ( dt_property_name_is_equal(prop, "bootargs") )
            {
                if ( !bootargs  && !had_dom0_bootargs )
                    bootargs = prop->value;
                continue;
            }
        }

        /* Don't expose the property "xen,passthrough" to the guest */
        if ( dt_property_name_is_equal(prop, "xen,passthrough") )
            continue;

        /* Remember and skip the status property as Xen may modify it later */
        if ( dt_property_name_is_equal(prop, "status") )
        {
            status = prop;
            continue;
        }

        if ( iommu_node )
        {
            /* Don't expose IOMMU specific properties to hwdom */
            if ( dt_property_name_is_equal(prop, "iommus") )
                continue;

            if ( dt_property_name_is_equal(prop, "iommu-map") )
                continue;

            if ( dt_property_name_is_equal(prop, "iommu-map-mask") )
                continue;
        }

        res = fdt_property(kinfo->fdt, prop->name, prop_data, prop_len);

        if ( res )
            return res;
    }

    /*
    res = handle_linux_pci_domain(kinfo, node);

    if ( res )
        return res;
    */

    /*
     * Override the property "status" to disable the device when it's
     * marked for passthrough.
     */
    if ( dt_device_for_passthrough(node) )
        res = fdt_property_string(kinfo->fdt, "status", "disabled");
    else if ( status )
        res = fdt_property(kinfo->fdt, "status", status->value,
                           status->length);

    if ( res )
        return res;

    if ( dt_node_path_is_equal(node, "/chosen") )
    {
        const struct bootmodule *initrd = kinfo->initrd_bootmodule;

        if ( bootargs )
        {
            res = fdt_property(kinfo->fdt, "bootargs", bootargs,
                               strlen(bootargs) + 1);
            if ( res )
                return res;
        }

        /*
         * If the bootloader provides an initrd, we must create a placeholder
         * for the initrd properties. The values will be replaced later.
         */
        if ( initrd && initrd->size )
        {
            u64 a = 0;
            res = fdt_property(kinfo->fdt, "linux,initrd-start", &a, sizeof(a));
            if ( res )
                return res;

            res = fdt_property(kinfo->fdt, "linux,initrd-end", &a, sizeof(a));
            if ( res )
                return res;
        }
    }

    return 0;
}

void __init evtchn_allocate(struct domain *d)
{
    (void) d;

    printk("%s: need to be implemented\n", __func__);
}

static int __init map_irq_to_domain(struct domain *d, unsigned int irq,
                             bool need_mapping, const char *devname)
{
    int res;

    res = irq_permit_access(d, irq);
    if ( res )
    {
        printk(XENLOG_ERR "Unable to permit to %pd access to IRQ %u\n", d, irq);
        return res;
    }

    if ( need_mapping )
    {
        /*
         * Checking the return of vgic_reserve_virq is not
         * necessary. It should not fail except when we try to map
         * the IRQ twice. This can legitimately happen if the IRQ is shared
         */
        // vgic_reserve_virq(d, irq);

        // res = route_irq_to_guest(d, irq, irq, devname);
        // if ( res < 0 )
        // {
        //     printk(XENLOG_ERR "Unable to map IRQ%u to %pd\n", irq, d);
        //     return res;
        // }
    }

    dt_dprintk("  - IRQ: %u\n", irq);
    return 0;
}

/*
 * handle_device_interrupts retrieves the interrupts configuration from
 * a device tree node and maps those interrupts to the target domain.
 *
 * Returns:
 *   < 0 error
 *   0   success
 */
static int __init handle_device_interrupts(struct domain *d,
                                           struct dt_device_node *dev,
                                           bool need_mapping)
{
    unsigned int i, nirq;
    int res;
    struct dt_raw_irq rirq;

    nirq = dt_number_of_irq(dev);

    /* Give permission and map IRQs */
    for ( i = 0; i < nirq; i++ )
    {
        res = dt_device_get_raw_irq(dev, i, &rirq);
        if ( res )
        {
            printk(XENLOG_ERR "Unable to retrieve irq %u for %s\n",
                   i, dt_node_full_name(dev));
            return res;
        }

        /*
         * Don't map IRQ that have no physical meaning
         * ie: IRQ whose controller is not the GIC
         */
        if ( rirq.controller != dt_interrupt_controller )
        {
            dt_dprintk("irq %u not connected to primary controller. Connected to %s\n",
                      i, dt_node_full_name(rirq.controller));
            continue;
        }

        res = platform_get_irq(dev, i);
        if ( res < 0 )
        {
            printk(XENLOG_ERR "Unable to get irq %u for %s\n",
                   i, dt_node_full_name(dev));
            return res;
        }

        res = map_irq_to_domain(d, res, need_mapping, dt_node_name(dev));
        if ( res )
            return res;
    }

    return 0;
}

static int __init handle_device(struct domain *d, struct dt_device_node *dev,
                                p2m_type_t p2mt)
{
    (void) d;
    (void) dev;
    (void) p2mt;

    printk("%s: need to be implemented\n", __func__);

    return 0;
}

static int __init make_gic_node(struct domain *d, void *fdt,
                                const struct dt_device_node *node)
{
    /*
     * Xen currently supports only a single GIC. Discard any secondary
     * GIC entries.
     */
    if ( node != dt_interrupt_controller )
    {
        dt_dprintk("Skipping (secondary GIC)\n");
        return 0;
    }

    return  gic_make_hwdom_dt_node(d, node, fdt);
}

static int __init make_timer_node(const struct kernel_info *kinfo)
{
    printk("%s: need to be implemented\n", __func__);

    return 0;
}

static int __init make_hypervisor_node(struct domain *d,
                                       const struct kernel_info *kinfo,
                                       int addrcells, int sizecells)
{
    printk("%s: need to be implemented\n", __func__);

    return 0;
}

static int __init make_cpus_node(const struct domain *d, void *fdt)
{
    int res;
    const struct dt_device_node *cpus = dt_find_node_by_path("/cpus");
    const struct dt_device_node *npcpu;
    unsigned int cpu;
    const void *compatible = NULL, *isa = NULL, *mmu = NULL;
    u32 len_compatible, len_isa, len_mmu;
    u32 timebase_frequency;
    bool frequency_valid;

    dt_dprintk("Create cpus node\n");

    if ( !cpus )
    {
        dprintk(XENLOG_ERR, "Missing /cpus node in the device tree?\n");
        return -ENOENT;
    }

    frequency_valid = dt_property_read_u32(cpus, "timebase-frequency",
                                           &timebase_frequency);

    /*
     * Get the compatible property of CPUs from the device tree.
     * We are assuming that all CPUs are the same so we are just look
     * for the first one.
     * TODO: Handle compatible per VCPU
     */
    dt_for_each_child_node(cpus, npcpu)
    {
        if ( dt_device_type_is_equal(npcpu, "cpu") )
        {
            compatible = dt_get_property(npcpu, "compatible", &len_compatible);
            isa = dt_get_property(npcpu, "riscv,isa", &len_isa);
            mmu = dt_get_property(npcpu, "mmu-type", &len_mmu);
            break;
        }
    }

    BUG_ON(!compatible || !mmu || !isa);

    if ( !compatible )
    {
        dprintk(XENLOG_ERR, "Can't find cpu in the device tree?\n");
        return -ENOENT;
    }

    /* See Linux Documentation/devicetree/booting-without-of.txt
     * section III.5.b
     */
    res = fdt_begin_node(fdt, "cpus");
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "#address-cells", 1);
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "#size-cells", 0);
    if ( res )
        return res;
    
    if ( frequency_valid )
    {
        res = fdt_property_cell(fdt, "timebase-frequency", timebase_frequency);
    }

    for ( cpu = 0; cpu < d->max_vcpus; cpu++ )
    {
        char buf[64];
        uint32_t reg = cpu_to_fdt32(cpu);
        uint32_t phandle = 0;

        snprintf(buf, sizeof(buf), "cpu@%u", cpu);
        res = fdt_begin_node(fdt, buf);
        if ( res )
            return res;
        
        res = fdt_property(fdt, "reg", &reg, sizeof(uint32_t));
        if ( res )
            return res;

        res = fdt_property_string(fdt, "status", "okay");
        if ( res )
            return res;

        res = fdt_property(fdt, "compatible", compatible, len_compatible);
        if ( res )
            return res;

        res = fdt_property(fdt, "mmu-type", mmu, len_mmu);
        if ( res )
            return res;

        res = fdt_property(fdt, "riscv,isa", isa, len_isa);
        if ( res )
            return res;

        res = fdt_property_string(fdt, "device_type", "cpu");
        if ( res )
            return res;

        res = fdt_begin_node(fdt, "interrupt-controller");
        if ( res )
            return res;

        res = fdt_property_string(fdt, "compatible", "riscv,cpu-intc");
        if ( res )
            return res;

        res = fdt_property_cell(fdt, "#interrupt-cells", 1);
        if ( res )
            return res;

        res = fdt_property(fdt, "interrupt-controller", NULL, 0);
        if ( res )
            return res;

        res = fdt_generate_phandle(fdt, &phandle);
        if ( res )
            return res;

        res = fdt_property_u32(fdt, "phandle", phandle);
        if ( res )
            return res;

        /* end of interrupt-controller */
        res = fdt_end_node(fdt);
        if ( res )
            return res;

        res = fdt_end_node(fdt);
        if ( res )
            return res;
    }

    res = fdt_end_node(fdt);

    return res;
}

/*
 * Wrapper to convert physical address from paddr_t to uint64_t and
 * invoke fdt_begin_node(). This is required as the physical address
 * provided as part of node name should not contain any leading
 * zeroes. Thus, one should use PRIx64 (instead of PRIpaddr) to append
 * unit (which contains the physical address) with name to generate a
 * node name.
 */
static int __init domain_fdt_begin_node(void *fdt, const char *name,
                                        uint64_t unit)
{
    /*
     * The size of the buffer to hold the longest possible string (i.e.
     * interrupt-controller@ + a 64-bit number + \0).
     */
    char buf[38];
    int ret;

    /* ePAPR 3.4 */
    ret = snprintf(buf, sizeof(buf), "%s@%"PRIx64, name, unit);

    if ( ret >= sizeof(buf) )
    {
        printk(XENLOG_ERR
               "Insufficient buffer. Minimum size required is %d\n",
               (ret + 1));

        return -FDT_ERR_TRUNCATED;
    }

    return fdt_begin_node(fdt, buf);
}

static int __init make_memory_node(const struct domain *d,
                                   void *fdt,
                                   int addrcells, int sizecells,
                                   struct meminfo *mem)
{
    unsigned int i;
    int res, reg_size = addrcells + sizecells;
    int nr_cells = 0;
    __be32 reg[NR_MEM_BANKS * 4 /* Worst case addrcells + sizecells */];
    __be32 *cells;

    if ( mem->nr_banks == 0 )
        return -ENOENT;

    /* find the first memory range that is reserved for device (or firmware) */
    for ( i = 0; i < mem->nr_banks &&
                 (mem->bank[i].type != MEMBANK_DEFAULT); i++ )
        ;

    if ( i == mem->nr_banks )
        return 0;

    dt_dprintk("Create memory node\n");

    res = domain_fdt_begin_node(fdt, "memory", mem->bank[i].start);
    if ( res )
        return res;

    res = fdt_property_string(fdt, "device_type", "memory");
    if ( res )
        return res;

    cells = &reg[0];
    for ( ; i < mem->nr_banks; i++ )
    {
        u64 start = mem->bank[i].start;
        u64 size = mem->bank[i].size;

        if ( mem->bank[i].type == MEMBANK_STATIC_DOMAIN )
            continue;

        dt_dprintk("  Bank %d: %#"PRIx64"->%#"PRIx64"\n",
                   i, start, start + size);

        nr_cells += reg_size;
        BUG_ON(nr_cells >= ARRAY_SIZE(reg));
        dt_child_set_range(&cells, addrcells, sizecells, start, size);
    }

    dt_dprintk("(reg size %d, nr cells %d)\n", reg_size, nr_cells);

    res = fdt_property(fdt, "reg", reg, nr_cells * sizeof(*reg));
    if ( res )
        return res;

    res = fdt_end_node(fdt);

    return res;
}

static int __init handle_node(struct domain *d, struct kernel_info *kinfo,
                              struct dt_device_node *node,
                              p2m_type_t p2mt)
{
    static const struct dt_device_match skip_matches[] __initconst =
    {
        DT_MATCH_COMPATIBLE("xen,xen"),
        DT_MATCH_COMPATIBLE("xen,multiboot-module"),
        DT_MATCH_COMPATIBLE("multiboot,module"),
        DT_MATCH_COMPATIBLE("syscon-poweroff"),
        DT_MATCH_COMPATIBLE("syscon-reboot"),
        DT_MATCH_COMPATIBLE("riscv,imsics"),
        DT_MATCH_PATH("/cpus"),
        DT_MATCH_TYPE("memory"),
        { /* sentinel */ },
    };
    static const struct dt_device_match timer_matches[] __initconst =
    {
        DT_MATCH_COMPATIBLE("riscv,clint"),
        { /* sentinel */ },
    };
    static const struct dt_device_match reserved_matches[] __initconst =
    {
        DT_MATCH_PATH("/memory"),
        DT_MATCH_PATH("/hypervisor"),
        { /* sentinel */ },
    };
    struct dt_device_node *child;
    const char *name;
    const char *path;
    int res;

    path = dt_node_full_name(node);

    dt_dprintk("handle %s\n", path);

    /* Skip theses nodes and the sub-nodes */
    if ( dt_match_node(skip_matches, node) )
    {
        dt_dprintk("  Skip it (matched)\n");
        return 0;
    }

    /*
     * Replace these nodes with our own. Note that the original may be
     * used_by DOMID_XEN so this check comes first.
     */
    if ( device_get_class(node) == DEVICE_GIC )
        return make_gic_node(d, kinfo->fdt, node);

    if ( dt_match_node(timer_matches, node) )
        return make_timer_node(kinfo);

    /* Skip nodes used by Xen */
    if ( dt_device_used_by(node) == DOMID_XEN )
    {
        dt_dprintk("  Skip it (used by Xen)\n");
        return 0;
    }

    /*
     * Even if the IOMMU device is not used by Xen, it should not be
     * passthrough to DOM0
     */
    if ( device_get_class(node) == DEVICE_IOMMU )
    {
        dt_dprintk("IOMMU, skip it\n");
        return 0;
    }

    /*
     * Xen is using some path for its own purpose. Warn if a node
     * already exists with the same path.
     */
    if ( dt_match_node(reserved_matches, node) )
        printk(XENLOG_WARNING
               "WARNING: Path %s is reserved, skip the node as we may re-use the path.\n",
               path);

    res = handle_device(d, node, p2mt);
    if ( res)
        return res;

    /*
     * The property "name" is used to have a different name on older FDT
     * version. We want to keep the name retrieved during the tree
     * structure creation, that is store in the node path.
     */
    name = strrchr(path, '/');
    name = name ? name + 1 : path;

    res = fdt_begin_node(kinfo->fdt, name);
    if ( res )
        return res;

    res = write_properties(d, kinfo, node);
    if ( res )
        return res;

    for ( child = node->child; child != NULL; child = child->sibling )
    {
        res = handle_node(d, kinfo, child, p2mt);
        if ( res )
            return res;
    }

    if ( node == dt_host )
    {
        int addrcells = dt_child_n_addr_cells(node);
        int sizecells = dt_child_n_size_cells(node);

        evtchn_allocate(d);

        /*
         * The hypervisor node should always be created after all nodes
         * from the host DT have been parsed.
         */
        res = make_hypervisor_node(d, kinfo, addrcells, sizecells);
        if ( res )
            return res;

        res = make_cpus_node(d, kinfo->fdt);
        if ( res )
            return res;

        res = make_memory_node(d, kinfo->fdt, addrcells, sizecells, &kinfo->mem);
        if ( res )
            return res;

        /*
         * Create a second memory node to store the ranges covering
         * reserved-memory regions.
         */
        if ( bootinfo.reserved_mem.nr_banks > 0 )
        {
            res = make_memory_node(d, kinfo->fdt, addrcells, sizecells,
                                   &bootinfo.reserved_mem);
            if ( res )
                return res;
        }

        /* there is no shm_mem in kinfo so skip for now */
        #if 0
        res = make_resv_memory_node(d, kinfo->fdt, addrcells, sizecells,
                                    &kinfo->shm_mem);
        if ( res )
            return res;
        #endif
    }

    res = fdt_end_node(kinfo->fdt);

    return res;
}

static int __init prepare_dtb_hwdom(struct domain *d, struct kernel_info *kinfo)
{
    const p2m_type_t default_p2mt = p2m_mmio_direct_c;
    const void *fdt;
    int new_size;
    int ret;

    ASSERT(dt_host && (dt_host->sibling == NULL));

    fdt = device_tree_flattened;

    new_size = fdt_totalsize(fdt) + DOM0_FDT_EXTRA_SIZE;
    kinfo->fdt = xmalloc_bytes(new_size);
    if ( kinfo->fdt == NULL )
        return -ENOMEM;

    ret = fdt_create(kinfo->fdt, new_size);
    if ( ret < 0 )
        goto err;

    fdt_finish_reservemap(kinfo->fdt);

    ret = handle_node(d, kinfo, dt_host, default_p2mt);
    if ( ret )
        goto err;

    ret = fdt_finish(kinfo->fdt);
    if ( ret < 0 )
        goto err;

#ifdef CONFIG_DEBUG_FDT
    fdt_dump(kinfo->fdt);
#endif

    return 0;

  err:
    printk("Device tree generation failed (%d).\n", ret);
    xfree(kinfo->fdt);
    return -EINVAL;
}

static void __init initrd_load(struct kernel_info *kinfo)
{
    const struct bootmodule *mod = kinfo->initrd_bootmodule;
    paddr_t load_addr = kinfo->initrd_paddr;
    paddr_t paddr, len;
    int node;
    int res;
    __be32 val[2];
    __be32 *cellp;
    void __iomem *initrd;

    if ( !mod || !mod->size )
        return;

    paddr = mod->start;
    len = mod->size;

    printk("Loading %pd initrd from %"PRIpaddr" to 0x%"PRIpaddr"-0x%"PRIpaddr"\n",
           kinfo->d, paddr, load_addr, load_addr + len);

    /* Fix up linux,initrd-start and linux,initrd-end in /chosen */
    node = fdt_path_offset(kinfo->fdt, "/chosen");
    if ( node < 0 )
        panic("Cannot find the /chosen node\n");

    cellp = (__be32 *)val;
    dt_set_cell(&cellp, ARRAY_SIZE(val), load_addr);
    res = fdt_setprop_inplace(kinfo->fdt, node, "linux,initrd-start",
                              val, sizeof(val));
    if ( res )
        panic("Cannot fix up \"linux,initrd-start\" property\n");

    cellp = (__be32 *)val;
    dt_set_cell(&cellp, ARRAY_SIZE(val), load_addr + len);
    res = fdt_setprop_inplace(kinfo->fdt, node, "linux,initrd-end",
                              val, sizeof(val));
    if ( res )
        panic("Cannot fix up \"linux,initrd-end\" property\n");

    initrd = ioremap_wc(paddr, len);
    if ( !initrd )
        panic("Unable to map the hwdom initrd\n");

    res = copy_to_guest_phys(kinfo->d, load_addr,
                                          initrd, len);
    if ( res != 0 )
        panic("Unable to copy the initrd in the hwdom memory\n");

    iounmap(initrd);
}

static void __init dtb_load(struct kernel_info *kinfo)
{
    unsigned long left;

    printk("Loading %pd DTB to 0x%"PRIpaddr"-0x%"PRIpaddr"\n",
           kinfo->d, kinfo->dtb_paddr,
           kinfo->dtb_paddr + fdt_totalsize(kinfo->fdt));

    left = copy_to_guest_phys(kinfo->d, kinfo->dtb_paddr,
                                           kinfo->fdt,
                                           fdt_totalsize(kinfo->fdt));

    if ( left != 0 )
        panic("Unable to copy the DTB to %pd memory (left = %lu bytes)\n",
              kinfo->d, left);
    xfree(kinfo->fdt);
}

static int __init construct_domain(struct domain *d, struct kernel_info *kinfo)
{
    unsigned int i;
    struct vcpu *v = d->vcpu[0];
    struct cpu_user_regs *regs = &v->arch.cpu_info->guest_cpu_user_regs;

    BUG_ON(d->vcpu[0] == NULL);
    BUG_ON(v->is_initialised);

    kernel_load(kinfo);
    initrd_load(kinfo);
    dtb_load(kinfo);

    memset(regs, 0, sizeof(*regs));

    regs->sepc = (register_t)kinfo->entry;

    /* guest boot hart ID = 0 */
    regs->a0 = 0;
    regs->a1 = kinfo->dtb_paddr;

    for ( i = 1; i < d->max_vcpus; i++ )
    {
        if ( vcpu_create(d, i) == NULL )
        {
            printk("Failed to allocate d%dv%d\n", d->domain_id, i);
            break;
        }
        else
        {
            printk("Created vcpu %d for d%d\n", i, d->domain_id);
        }
    }

    domain_update_node_affinity(d); 

    v->is_initialised = 1;
    clear_bit(_VPF_down, &v->pause_flags);
    return 0;
}


static int __init construct_dom0(struct domain *d)
{
    struct kernel_info kinfo = {};
    int rc;

    /* Sanity! */
    BUG_ON(d->domain_id != 0);

    printk("*** LOADING DOMAIN 0 ***\n");

    /* The ordering of operands is to work around a clang5 issue. */
    if ( CONFIG_DOM0_MEM[0] && !dom0_mem_set )
        parse_dom0_mem(CONFIG_DOM0_MEM);

    if ( dom0_mem <= 0 )
    {
#ifdef MCHP_HWEMU
        /* TO REMOVE: Even if I can give this parameter to xen, it will not possible with
         * the hardware emulation platform. Ugly tempporary fix
         */
        warning_add("PLEASE SPECIFY dom0_mem PARAMETER - USING 16M FOR NOW\n");
        dom0_mem = MB(16);
#else
        warning_add("PLEASE SPECIFY dom0_mem PARAMETER - USING 512M FOR NOW\n");
        dom0_mem = MB(512);
#endif
    }

    d->max_pages = dom0_mem >> PAGE_SHIFT;

    kinfo.unassigned_mem = dom0_mem;
    kinfo.d = d;

    rc = kernel_probe(&kinfo, NULL);
    if ( rc < 0 )
        return rc;

#ifdef CONFIG_RISCV_64
    /* type must be set before allocate_memory */
    d->arch.type = kinfo.type;
#endif
    allocate_memory_11(d, &kinfo);

    rc = prepare_dtb_hwdom(d, &kinfo);

    if ( rc < 0 )
        return rc;

    return construct_domain(d, &kinfo);
}

void __init create_dom0(void)
{
    struct domain *dom0;
    struct xen_domctl_createdomain dom0_cfg = {
        .flags = XEN_DOMCTL_CDF_hvm | XEN_DOMCTL_CDF_hap,
        .max_evtchn_port = -1,
        .max_grant_frames = gnttab_dom0_frames(),
        .max_maptrack_frames = -1,
        .grant_opts = XEN_DOMCTL_GRANT_version(opt_gnttab_max_version),
    };
    int rc;

    // /* The vGIC for DOM0 is exactly emulating the hardware GIC */
    // dom0_cfg.arch.gic_version = XEN_DOMCTL_CONFIG_GIC_NATIVE;
    // /*
    //  * Xen vGIC supports a maximum of 992 interrupt lines.
    //  * 32 are substracted to cover local IRQs.
    //  */
    // dom0_cfg.arch.nr_spis = min(gic_number_lines(), (unsigned int) 992) - 32;
    // if ( gic_number_lines() > 992 )
    //     printk(XENLOG_WARNING "Maximum number of vGIC IRQs exceeded.\n");
    // dom0_cfg.arch.tee_type = tee_get_type();
    dom0_cfg.max_vcpus = dom0_max_vcpus();

    // if ( iommu_enabled )
    //     dom0_cfg.flags |= XEN_DOMCTL_CDF_iommu;

    dom0 = domain_create(0, &dom0_cfg, true);
    if ( IS_ERR(dom0) )
        panic("Error creating domain 0 (rc = %ld)\n", PTR_ERR(dom0));

    if ( alloc_dom0_vcpu0(dom0) == NULL )
        panic("Error creating domain 0 vcpu0\n");

    rc = construct_dom0(dom0);
    if ( rc )
        panic("Could not set up DOM0 guest OS (rc = %d)\n", rc);
}

static unsigned long __init domain_p2m_pages(unsigned long maxmem_kb,
                                             unsigned int smp_cpus)
{
    /*
     * Keep in sync with libxl__get_required_paging_memory().
     * 256 pages (1MB) per vcpu, plus 1 page per MiB of RAM for the P2M map,
     * plus 128 pages to cover extended regions.
     */
    unsigned long memkb = 4 * (256 * smp_cpus + (maxmem_kb / 1024) + 128);

    BUILD_BUG_ON(PAGE_SIZE != SZ_4K);

    return DIV_ROUND_UP(memkb, 1024) << (20 - PAGE_SHIFT);
}

static int __init make_resv_memory_node(const struct domain *d,
                                        void *fdt,
                                        int addrcells, int sizecells,
                                        const struct meminfo *mem)
{
    int res = 0;
    /* Placeholder for reserved-memory\0 */
    const char resvbuf[16] = "reserved-memory";

    if ( mem->nr_banks == 0 )
        /* No shared memory provided. */
        return 0;

    dt_dprintk("Create reserved-memory node\n");

    res = fdt_begin_node(fdt, resvbuf);
    if ( res )
        return res;

    res = fdt_property(fdt, "ranges", NULL, 0);
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "#address-cells", addrcells);
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "#size-cells", sizecells);
    if ( res )
        return res;

    /* TODO: add shared memory node ? */
    // res = make_shm_memory_node(d, fdt, addrcells, sizecells, mem);
    // if ( res )
    //     return res;

    res = fdt_end_node(fdt);

    return res;
}

/*
 * This function is used as part of the device tree generation for Dom0
 * on ACPI systems, and DomUs started directly from Xen based on device
 * tree information.
 */
int __init make_chosen_node(const struct kernel_info *kinfo)
{
    int res;
    const char *bootargs = NULL;
    const struct bootmodule *mod = kinfo->kernel_bootmodule;
    void *fdt = kinfo->fdt;

    dt_dprintk("Create chosen node\n");
    res = fdt_begin_node(fdt, "chosen");
    if ( res )
        return res;

    if ( kinfo->cmdline && kinfo->cmdline[0] )
    {
        bootargs = &kinfo->cmdline[0];
        res = fdt_property(fdt, "bootargs", bootargs, strlen(bootargs) + 1);
        if ( res )
           return res;
    }

    /*
     * If the bootloader provides an initrd, we must create a placeholder
     * for the initrd properties. The values will be replaced later.
     */
    if ( mod && mod->size )
    {
        u64 a = 0;
        res = fdt_property(kinfo->fdt, "linux,initrd-start", &a, sizeof(a));
        if ( res )
            return res;

        res = fdt_property(kinfo->fdt, "linux,initrd-end", &a, sizeof(a));
        if ( res )
            return res;
    }

    res = fdt_end_node(fdt);

    return res;
}

static int __init check_partial_fdt(void *pfdt, size_t size)
{
    int res;

    if ( fdt_magic(pfdt) != FDT_MAGIC )
    {
        dprintk(XENLOG_ERR, "Partial FDT is not a valid Flat Device Tree");
        return -EINVAL;
    }

    res = fdt_check_header(pfdt);
    if ( res )
    {
        dprintk(XENLOG_ERR, "Failed to check the partial FDT (%d)", res);
        return -EINVAL;
    }

    if ( fdt_totalsize(pfdt) > size )
    {
        dprintk(XENLOG_ERR, "Partial FDT totalsize is too big");
        return -EINVAL;
    }

    return 0;
}

static int __init handle_passthrough_prop(struct kernel_info *kinfo,
                                          const struct fdt_property *xen_reg,
                                          const struct fdt_property *xen_path,
                                          bool xen_force,
                                          uint32_t address_cells, uint32_t size_cells)
{
    const __be32 *cell;
    unsigned int i, len;
    struct dt_device_node *node;
    int res;
    paddr_t mstart, size, gstart;

    /* xen,reg specifies where to map the MMIO region */
    cell = (const __be32 *)xen_reg->data;
    len = fdt32_to_cpu(xen_reg->len) / ((address_cells * 2 + size_cells) *
                                        sizeof(uint32_t));

    for ( i = 0; i < len; i++ )
    {
        device_tree_get_reg(&cell, address_cells, size_cells,
                            &mstart, &size);
        gstart = dt_next_cell(address_cells, &cell);

        if ( gstart & ~PAGE_MASK || mstart & ~PAGE_MASK || size & ~PAGE_MASK )
        {
            printk(XENLOG_ERR
                    "DomU passthrough config has not page aligned addresses/sizes\n");
            return -EINVAL;
        }

        res = iomem_permit_access(kinfo->d, paddr_to_pfn(mstart),
                                  paddr_to_pfn(PAGE_ALIGN(mstart + size - 1)));
        if ( res )
        {
            printk(XENLOG_ERR "Unable to permit to dom%d access to"
                   " 0x%"PRIpaddr" - 0x%"PRIpaddr"\n",
                   kinfo->d->domain_id,
                   mstart & PAGE_MASK, PAGE_ALIGN(mstart + size) - 1);
            return res;
        }

        res = guest_physmap_add_entry(
            kinfo->d, gaddr_to_gfn(gstart),
            maddr_to_mfn(mstart),
            get_order_from_bytes(size),
            p2m_mmio_direct_c);
        if ( res < 0 )
        {
            printk(XENLOG_ERR
                   "Failed to map %"PRIpaddr" to the guest at%"PRIpaddr"\n",
                   mstart, gstart);
            return -EFAULT;
        }
    }

    /*
     * If xen_force, we let the user assign a MMIO region with no
     * associated path.
     */
    if ( xen_path == NULL )
        return xen_force ? 0 : -EINVAL;

    /*
     * xen,path specifies the corresponding node in the host DT.
     * Both interrupt mappings and IOMMU settings are based on it,
     * as they are done based on the corresponding host DT node.
     */
    node = dt_find_node_by_path(xen_path->data);
    if ( node == NULL )
    {
        printk(XENLOG_ERR "Couldn't find node %s in host_dt!\n",
               (char *)xen_path->data);
        return -EINVAL;
    }

    res = handle_device_interrupts(kinfo->d, node, true);
    if ( res < 0 )
        return res;

    return res;

    // // res = iommu_add_dt_device(node);
    // // if ( res < 0 )
    // //     return res;

    // /* If xen_force, we allow assignment of devices without IOMMU protection. */
    // if ( xen_force && !dt_device_is_protected(node) )
    //     return 0;
    // else {
    //     panic("TODO: IOMMU is not implemented");
    // }
    // return iommu_assign_dt_device(kinfo->d, node);
}

static int __init handle_prop_pfdt(struct kernel_info *kinfo,
                                   const void *pfdt, int nodeoff,
                                   uint32_t address_cells, uint32_t size_cells,
                                   bool scan_passthrough_prop)
{
    void *fdt = kinfo->fdt;
    int propoff, nameoff, res;
    const struct fdt_property *prop, *xen_reg = NULL, *xen_path = NULL;
    const char *name;
    bool found, xen_force = false;

    fdt_for_each_property_offset(propoff,pfdt, nodeoff)
    {
        if ( !(prop = fdt_get_property_by_offset(pfdt, propoff, NULL)) )
            return -FDT_ERR_INTERNAL;

        found = false;
        nameoff = fdt32_to_cpu(prop->nameoff);
        name = fdt_string(pfdt, nameoff);

        if ( scan_passthrough_prop )
        {
            if ( dt_prop_cmp("xen,reg", name) == 0 )
            {
                xen_reg = prop;
                found = true;
            }
            else if ( dt_prop_cmp("xen,path", name) == 0 )
            {
                xen_path = prop;
                found = true;
            }
            else if ( dt_prop_cmp("xen,force-assign-without-iommu", name) == 0 )
            {
                xen_force = true;
                found = true;
            }
        }

        /*
         * Copy properties other than the ones above: xen,reg, xen,path,
         * and xen,force-assign-without-iommu.
         */
        if ( !found )
        {
            /* enable the interrupts for this domain */
            if ( dt_prop_cmp("interrupts", name) == 0 )
            {
                int field = kinfo->d->arch.irq_cell_size * sizeof(__be32);
                
                for ( int i = 0; i < be32_to_cpu(prop->len) / field; i++ )
                {
                    int irq_num = be32_to_cpu(*(__be32*)(prop->data + (i * field)));
                    kinfo->d->arch.auth_irq_bmp[irq_num / 32] |= 1 << (irq_num % 32);
                }
            }

            /* replace the phandle with the true interrupt controler phandle */
            if ( dt_prop_cmp("interrupt-parent", name) == 0 )
            {
                struct fdt_property *tmp = (struct fdt_property *)prop;

                *(__be32*)(tmp->data) = __cpu_to_be32(kinfo->d->arch.phandle_gic);

                res = fdt_property(fdt, name, tmp->data, fdt32_to_cpu(tmp->len));
                if ( res )
                    return res;
            }
            else if ( dt_prop_cmp("interrupts-extended", name) == 0 )
            {
                struct fdt_property *tmp = (struct fdt_property *)prop;
                int field = (kinfo->d->arch.irq_cell_size + 1) * sizeof(__be32);

                for ( int i = 0; i < be32_to_cpu(prop->len) / field; i++ )
                {
                    int irq_num = be32_to_cpu(*(__be32*)(prop->data + (i * field) + sizeof(__be32)));
                    *(__be32*)(tmp->data + (i * field)) = __cpu_to_be32(kinfo->d->arch.phandle_gic);
                    kinfo->d->arch.auth_irq_bmp[irq_num / 32] |= 1 << (irq_num % 32);
                }

                res = fdt_property(fdt, name, tmp->data, fdt32_to_cpu(tmp->len));
                if ( res )
                    return res;
            }
            else
            {
                res = fdt_property(fdt, name, prop->data, fdt32_to_cpu(prop->len));
                if ( res )
                    return res;
            }
        }
    }

    /*
     * Only handle passthrough properties if both xen,reg and xen,path
     * are present, or if xen,force-assign-without-iommu is specified.
     */
    if ( xen_reg != NULL && (xen_path != NULL || xen_force) )
    {
        res = handle_passthrough_prop(kinfo, xen_reg, xen_path, xen_force,
                                      address_cells, size_cells);
        if ( res < 0 )
        {
            printk(XENLOG_ERR "Failed to assign device to %pd\n", kinfo->d);
            return res;
        }
    }
    else if ( (xen_path && !xen_reg) || (xen_reg && !xen_path && !xen_force) )
    {
        printk(XENLOG_ERR "xen,reg or xen,path missing for %pd\n",
               kinfo->d);
        return -EINVAL;
    }

    /* FDT_ERR_NOTFOUND => There is no more properties for this node */
    return ( propoff != -FDT_ERR_NOTFOUND ) ? propoff : 0;
}

static int __init scan_pfdt_node(struct kernel_info *kinfo, const void *pfdt,
                                 int nodeoff,
                                 uint32_t address_cells, uint32_t size_cells,
                                 bool scan_passthrough_prop)
{
    int rc = 0;
    void *fdt = kinfo->fdt;
    int node_next;

    rc = fdt_begin_node(fdt, fdt_get_name(pfdt, nodeoff, NULL));
    if ( rc )
        return rc;

    rc = handle_prop_pfdt(kinfo, pfdt, nodeoff, address_cells, size_cells,
                          scan_passthrough_prop);
    if ( rc )
        return rc;

    address_cells = device_tree_get_u32(pfdt, nodeoff, "#address-cells",
                                        DT_ROOT_NODE_ADDR_CELLS_DEFAULT);
    size_cells = device_tree_get_u32(pfdt, nodeoff, "#size-cells",
                                     DT_ROOT_NODE_SIZE_CELLS_DEFAULT);

    node_next = fdt_first_subnode(pfdt, nodeoff);
    while ( node_next > 0 )
    {
        scan_pfdt_node(kinfo, pfdt, node_next, address_cells, size_cells,
                       scan_passthrough_prop);
        node_next = fdt_next_subnode(pfdt, node_next);
    }

    return fdt_end_node(fdt);
}

static int __init domain_handle_dtb_bootmodule(struct domain *d,
                                               struct kernel_info *kinfo)
{
    void *pfdt;
    int res, node_next;

    pfdt = ioremap_cache(kinfo->dtb_bootmodule->start,
                         kinfo->dtb_bootmodule->size);
    if ( pfdt == NULL )
        return -EFAULT;

    res = check_partial_fdt(pfdt, kinfo->dtb_bootmodule->size);
    if ( res < 0 )
        return res;

    for ( node_next = fdt_first_subnode(pfdt, 0); 
          node_next > 0;
          node_next = fdt_next_subnode(pfdt, node_next) )
    {
        const char *name = fdt_get_name(pfdt, node_next, NULL);

        if ( name == NULL )
            continue;

        /*
         * Only scan /gic /aliases /passthrough, ignore the rest.
         * They don't have to be parsed in order.
         *
         * Take the GIC phandle value from the special /gic node in the
         * DTB fragment.
         */
        if ( dt_node_cmp(name, "gic") == 0 )
        {
            int len;
            const fdt32_t *irq_cell;
            irq_cell = fdt_getprop(pfdt, node_next, "#interrupt-cells", &len);
            if (!irq_cell) {
                printk(XENLOG_WARNING "Missing '#interrupt-cellS' field in gic node\n");
            } else {
                kinfo->d->arch.irq_cell_size = fdt32_to_cpu(*irq_cell);
            }
            continue;
        }

        if ( dt_node_cmp(name, "aliases") == 0 )
        {
            res = scan_pfdt_node(kinfo, pfdt, node_next,
                                 DT_ROOT_NODE_ADDR_CELLS_DEFAULT,
                                 DT_ROOT_NODE_SIZE_CELLS_DEFAULT,
                                 false);
            if ( res )
                return res;
            continue;
        }
        if ( dt_node_cmp(name, "passthrough") == 0 )
        {
            res = scan_pfdt_node(kinfo, pfdt, node_next,
                                 DT_ROOT_NODE_ADDR_CELLS_DEFAULT,
                                 DT_ROOT_NODE_SIZE_CELLS_DEFAULT,
                                 true);
            if ( res )
                return res;
            continue;
        }
    }

    iounmap(pfdt);

    return res;
}

static int __init make_gic_domU_node(struct kernel_info *kinfo)
{
    gic_make_domu_dt_node(kinfo->d, kinfo->fdt);

    return 0;
}

/*
 * The max size for DT is 2MB. However, the generated DT is small, 4KB
 * are enough for now, but we might have to increase it in the future.
 */
#define DOMU_DTB_SIZE 4096
static int __init prepare_dtb_domU(struct domain *d, struct kernel_info *kinfo)
{
    int addrcells, sizecells;
    int ret;
    struct meminfo tmp;

    #define GUEST_ROOT_ADDRESS_CELLS 2
    #define GUEST_ROOT_SIZE_CELLS 2

    addrcells = GUEST_ROOT_ADDRESS_CELLS;
    sizecells = GUEST_ROOT_SIZE_CELLS;

    kinfo->fdt = xmalloc_bytes(DOMU_DTB_SIZE);
    if ( kinfo->fdt == NULL )
        return -ENOMEM;

    ret = fdt_create(kinfo->fdt, DOMU_DTB_SIZE);
    if ( ret < 0 )
        goto err;

    ret = fdt_finish_reservemap(kinfo->fdt);
    if ( ret < 0 )
        goto err;

    ret = fdt_begin_node(kinfo->fdt, "");
    if ( ret < 0 )
        goto err;

    ret = fdt_property_cell(kinfo->fdt, "#address-cells", addrcells);
    if ( ret )
        goto err;

    ret = fdt_property_cell(kinfo->fdt, "#size-cells", sizecells);
    if ( ret )
        goto err;

    ret = make_chosen_node(kinfo);
    if ( ret )
        goto err;

    ret = make_cpus_node(d, kinfo->fdt);
    if ( ret )
        goto err;

    ret = make_memory_node(d, kinfo->fdt, addrcells, sizecells, &kinfo->mem);
    if ( ret )
        goto err;

    tmp.nr_banks = 0;
    /* TODO: add shm_mem to kinfo ? */
    ret = make_resv_memory_node(d, kinfo->fdt, addrcells, sizecells,
                                &tmp /* &kinfo->shm_mem */);
    if ( ret )
        goto err;

    ret = make_gic_domU_node(kinfo);
    if ( ret )
        goto err;

    /*
     * domain_handle_dtb_bootmodule has to be called before the rest of
     * the device tree is generated because it depends on the value of
     * the field phandle_gic.
     */
    if ( kinfo->dtb_bootmodule )
    {
        ret = domain_handle_dtb_bootmodule(d, kinfo);
        if ( ret )
            return ret;
    }

    ret = make_timer_node(kinfo);
    if ( ret )
        goto err;

    if ( kinfo->dom0less_feature & DOM0LESS_ENHANCED_NO_XS )
    {
        ret = make_hypervisor_node(d, kinfo, addrcells, sizecells);
        if ( ret )
            goto err;
    }

    ret = fdt_end_node(kinfo->fdt);
    if ( ret < 0 )
        goto err;

    ret = fdt_finish(kinfo->fdt);
    if ( ret < 0 )
        goto err;

#ifdef CONFIG_DEBUG_FDT
    fdt_dump(kinfo->fdt);
#endif

    return 0;

  err:
    printk("Device tree generation failed (%d).\n", ret);
    xfree(kinfo->fdt);

    return -EINVAL;
}

static void __init allocate_static_memory(struct domain *d,
                                          struct kernel_info *kinfo,
                                          const struct dt_device_node *node)
{
    ASSERT_UNREACHABLE();
}

static void __init assign_static_memory_11(struct domain *d,
                                           struct kernel_info *kinfo,
                                           const struct dt_device_node *node)
{
    ASSERT_UNREACHABLE();
}

static int __init construct_domU(struct domain *d,
                                 const struct dt_device_node *node)
{
    struct kernel_info kinfo = {};
    const char *dom0less_enhanced;
    int rc;
    u64 mem;
    u32 p2m_mem_mb;
    unsigned long p2m_pages;

    rc = dt_property_read_u64(node, "memory", &mem);
    if ( !rc )
    {
        printk("Error building DomU: cannot read \"memory\" property\n");
        return -EINVAL;
    }
    kinfo.unassigned_mem = (paddr_t)mem * SZ_1K;

    rc = dt_property_read_u32(node, "xen,domain-p2m-mem-mb", &p2m_mem_mb);
    /* If xen,domain-p2m-mem-mb is not specified, use the default value. */
    p2m_pages = rc ?
                p2m_mem_mb << (20 - PAGE_SHIFT) :
                domain_p2m_pages(mem, d->max_vcpus);

    spin_lock(&d->arch.paging.lock);
    rc = p2m_set_allocation(d, p2m_pages, NULL);
    spin_unlock(&d->arch.paging.lock);
    if ( rc != 0 )
        return rc;

    printk("*** LOADING DOMU cpus=%u memory=%#"PRIx64"KB ***\n",
           d->max_vcpus, mem);

    kinfo.vsbi_uart = dt_property_read_bool(node, "vsbi_uart");

    rc = dt_property_read_string(node, "xen,enhanced", &dom0less_enhanced);
    if ( rc == -EILSEQ ||
         rc == -ENODATA ||
         (rc == 0 && !strcmp(dom0less_enhanced, "enabled")) )
    {
        if ( hardware_domain )
            kinfo.dom0less_feature = DOM0LESS_ENHANCED;
        else
            panic("At the moment, Xenstore support requires dom0 to be present\n");
    }
    else if ( rc == 0 && !strcmp(dom0less_enhanced, "no-xenstore") )
        kinfo.dom0less_feature = DOM0LESS_ENHANCED_NO_XS;

    rc = gic_register_domain(d);
    if ( rc )
        return rc;

    if ( vcpu_create(d, 0) == NULL )
        return -ENOMEM;

    d->max_pages = ((paddr_t)mem * SZ_1K) >> PAGE_SHIFT;

    kinfo.d = d;

    rc = kernel_probe(&kinfo, node);
    if ( rc < 0 )
        return rc;

#ifdef CONFIG_RISCV_64
    /* type must be set before allocate memory */
    d->arch.type = kinfo.type;
#endif
    if ( !dt_find_property(node, "xen,static-mem", NULL) )
        allocate_memory(d, &kinfo);
    else if ( !is_domain_direct_mapped(d) )
        allocate_static_memory(d, &kinfo, node);
    else
        assign_static_memory_11(d, &kinfo, node);

#ifdef CONFIG_STATIC_SHM
    rc = process_shm(d, &kinfo, node);
    if ( rc < 0 )
        return rc;
#endif

    if ( kinfo.vsbi_uart )
    {
        rc = domain_vsbi_uart_init(d, NULL);
        if ( rc < 0 )
            return rc;
    }

    rc = prepare_dtb_domU(d, &kinfo);
    if ( rc < 0 )
        goto construct_domU_err;

    rc = construct_domain(d, &kinfo);
    if ( rc )
        goto construct_domU_err;
    return 0;

construct_domU_err:
    gic_unregister_domain(d);
    return rc;
}

void __init create_domUs(void)
{
    struct dt_device_node *node;
    const struct dt_device_node *cpupool_node,
                                *chosen = dt_find_node_by_path("/chosen");

    BUG_ON(chosen == NULL);
    dt_for_each_child_node(chosen, node)
    {
        struct domain *d;
        struct xen_domctl_createdomain d_cfg = {
            .flags = XEN_DOMCTL_CDF_hvm | XEN_DOMCTL_CDF_hap,
            /*
             * The default of 1023 should be sufficient for guests because
             * on ARM we don't bind physical interrupts to event channels.
             * The only use of the evtchn port is inter-domain communications.
             * 1023 is also the default value used in libxl.
             */
            .max_evtchn_port = 1023,
            .max_grant_frames = -1,
            .max_maptrack_frames = -1,
            .grant_opts = XEN_DOMCTL_GRANT_version(opt_gnttab_max_version),
        };
        unsigned int flags = 0U;
        uint32_t val;
        int rc;

        if ( !dt_device_is_compatible(node, "xen,domain") )
            continue;

        if ( (max_init_domid + 1) >= DOMID_FIRST_RESERVED )
            panic("No more domain IDs available\n");

        if ( dt_find_property(node, "xen,static-mem", NULL) )
            flags |= CDF_staticmem;

        // if ( dt_property_read_bool(node, "direct-map") )
        // {
        //     if ( !(flags & CDF_staticmem) )
        //         panic("direct-map is not valid for domain %s without static allocation.\n",
        //               dt_node_name(node));

        //     flags |= CDF_directmap;
        // }

        if ( !dt_property_read_u32(node, "cpus", &d_cfg.max_vcpus) )
            panic("Missing property 'cpus' for domain %s\n",
                  dt_node_name(node));

        if ( dt_find_compatible_node(node, NULL, "multiboot,device-tree") &&
             iommu_enabled )
            d_cfg.flags |= XEN_DOMCTL_CDF_iommu;

        /* Get the optional property domain-cpupool */
        cpupool_node = dt_parse_phandle(node, "domain-cpupool", 0);
        if ( cpupool_node )
        {
            int pool_id = btcpupools_get_domain_pool_id(cpupool_node);
            if ( pool_id < 0 )
                panic("Error getting cpupool id from domain-cpupool (%d)\n",
                      pool_id);
            d_cfg.cpupool_id = pool_id;
        }

        if ( dt_property_read_u32(node, "max_grant_version", &val) )
            d_cfg.grant_opts = XEN_DOMCTL_GRANT_version(val);

        if ( dt_property_read_u32(node, "max_grant_frames", &val) )
        {
            if ( val > INT32_MAX )
                panic("max_grant_frames (%"PRIu32") overflow\n", val);
            d_cfg.max_grant_frames = val;
        }

        if ( dt_property_read_u32(node, "max_maptrack_frames", &val) )
        {
            if ( val > INT32_MAX )
                panic("max_maptrack_frames (%"PRIu32") overflow\n", val);
            d_cfg.max_maptrack_frames = val;
        }

        /*
         * The variable max_init_domid is initialized with zero, so here it's
         * very important to use the pre-increment operator to call
         * domain_create() with a domid > 0. (domid == 0 is reserved for Dom0)
         */
        d = domain_create(++max_init_domid, &d_cfg, flags);
        if ( IS_ERR(d) )
            panic("Error creating domain %s (rc = %ld)\n",
                  dt_node_name(node), PTR_ERR(d));

        d->is_console = true;
        dt_device_set_used_by(node, d->domain_id);

        rc = construct_domU(d, node);
        if ( rc )
            panic("Could not set up domain %s (rc = %d)\n",
                  dt_node_name(node), rc);
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
