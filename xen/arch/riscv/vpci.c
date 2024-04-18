#include <xen/sched.h>
#include <xen/vpci.h>

#include <asm/mmio.h>

static pci_sbdf_t vpci_sbdf_from_gpa(const struct pci_host_bridge *bridge,
                                     paddr_t gpa)
{
    pci_sbdf_t sbdf;

    if ( bridge )
    {
        sbdf.sbdf = VPCI_ECAM_BDF(gpa - bridge->cfg->phys_addr);
        sbdf.seg = bridge->segment;
        sbdf.bus += bridge->cfg->busn_start;
    }
    else
        sbdf.sbdf = VPCI_ECAM_BDF(gpa - GUEST_VPCI_ECAM_BASE);

    return sbdf;
}

static int vpci_mmio_read(struct vcpu *v, mmio_info_t *info,
                          register_t *r, void *p)
{
    struct pci_host_bridge *bridge = p;
    pci_sbdf_t sbdf = vpci_sbdf_from_gpa(bridge, info->gpa);
    /* data is needed to prevent a pointer cast on 32bit */
    unsigned long data;

    if ( vpci_ecam_read(sbdf, ECAM_REG_OFFSET(info->gpa),
                        1U << info->dabt.size, &data) )
    {
        *r = data;
        return 1;
    }

    *r = ~0ul;

    return 0;
}

static int vpci_mmio_write(struct vcpu *v, mmio_info_t *info,
                           register_t r, void *p)
{
    struct pci_host_bridge *bridge = p;
    pci_sbdf_t sbdf = vpci_sbdf_from_gpa(bridge, info->gpa);

    return vpci_ecam_write(sbdf, ECAM_REG_OFFSET(info->gpa),
                           1U << info->dabt.size, r);
}

static const struct mmio_handler_ops vpci_mmio_handler = {
    .read  = vpci_mmio_read,
    .write = vpci_mmio_write,
};

static int vpci_setup_mmio_handler_cb(struct domain *d,
                                      struct pci_host_bridge *bridge)
{
    struct pci_config_window *cfg = bridge->cfg;

    register_mmio_handler(d, &vpci_mmio_handler,
                          cfg->phys_addr, cfg->size, bridge);

    /* We have registered a single MMIO handler. */
    return 1;
}

int domain_vpci_init(struct domain *d)
{
    if ( !has_vpci(d) )
        return 0;

    /*
     * The hardware domain gets as many MMIOs as required by the
     * physical host bridge.
     * Guests get the virtual platform layout: one virtual host bridge for now.
     */
    if ( is_hardware_domain(d) )
    {
        int ret;

        ret = pci_host_iterate_bridges_and_count(d, vpci_setup_mmio_handler_cb);
        if ( ret < 0 )
            return ret;
    }
    else
        register_mmio_handler(d, &vpci_mmio_handler,
                              GUEST_VPCI_ECAM_BASE, GUEST_VPCI_ECAM_SIZE, NULL);

    return 0;
}
