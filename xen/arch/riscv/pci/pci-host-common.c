#include <xen/pci.h>
#include <xen/vmap.h>
#include <xen/init.h>
#include <xen/config.h>
#include <xen/device_tree.h>
#include <xen/list.h>
#include <xen/xmalloc.h>

/*
 * struct to hold pci device bar.
 */
struct pdev_bar_check
{
    paddr_t start;
    paddr_t end;
    bool is_valid;
};

// list of all host bridges.
static LIST_HEAD(pci_host_bridges);
static atomic_t domain_nr = ATOMIC_INIT(-1);
static int use_dt_domains = -1;

static void pci_add_host_bridge(struct pci_host_bridge *bridge) {
    list_add_tail(&bridge->node, &pci_host_bridges);
}

int pci_get_new_domain_nr(void)
{
    if ( use_dt_domains )
        return -1;

    return atomic_inc_return(&domain_nr);
}

static inline void __iomem *pci_remap_cfgspace(paddr_t start, size_t len)
{
    return ioremap_nocache(start, len);
}

static void pci_ecam_free(struct pci_config_window *cfg)
{
    if ( cfg->win )
        iounmap(cfg->win);

    xfree(cfg);
}

/*
 * Allocate memory for pci host bridge struct.
 * @param bridge pointer to a (struct pci_host_bridge *bridge) pointer.
 * 
 * @return 0 if success else fail.
*/
static int pci_alloc_host_bridge(struct pci_host_bridge **bridge)
{
    *bridge = xzalloc(struct pci_host_bridge);

    if ( !bridge )
        return -ENOMEM;

    INIT_LIST_HEAD(&(*bridge)->node);

    return 0;
}

static struct pci_config_window * gen_pci_init(struct dt_device_node *dev, const struct pci_ecam_ops *ops) {
    int res, cfg_reg_idx;
    u32 bus_range[2];
    struct pci_config_window *cfg = xzalloc(struct pci_config_window);

    if (!cfg) return NULL;

    res = dt_property_read_u32_array(dev, "bus-range", bus_range, ARRAY_SIZE(bus_range));
    if (res) {
        cfg->busn_start = 0;
        cfg->busn_end = 0xff;
        printk(XENLOG_INFO "%s: No bus range found for pci controller\n", dt_node_full_name(dev));
    } else {
        cfg->busn_start = bus_range[0];
        cfg->busn_end = bus_range[1];
        if (cfg->busn_end > cfg->busn_start + 0xff)  cfg->busn_end = cfg->busn_start + 0xff;
    }

    if (ops->cfg_reg_index) {
        cfg_reg_idx = ops->cfg_reg_index(dev);
        if (cfg_reg_idx < 0) goto err;
    } else cfg_reg_idx = 0;

    res = dt_device_get_paddr(dev, cfg_reg_idx, &cfg->phys_addr, &cfg->size);
    if (res) goto err;

    cfg->win = pci_remap_cfgspace(cfg->phys_addr, cfg->size);
    if ( !cfg->win )
    {
        printk(XENLOG_ERR "ECAM ioremap failed\n");
        goto err;
    }

    printk("ECAM at [mem 0x%"PRIpaddr"-0x%"PRIpaddr"] for [bus %x-%x] \n",
            cfg->phys_addr, cfg->phys_addr + cfg->size - 1,
            cfg->busn_start, cfg->busn_end);

    if ( ops->init )
    {
        res = ops->init(cfg);
        if ( res )
            goto err;
    }

    return cfg;

err:
    pci_ecam_free(cfg);
    return NULL;
}

static int pci_bus_find_domain_nr(struct dt_device_node *dev) {
    int domain;

    domain = dt_get_pci_domain_nr(dev);

    /*
     * Check DT domain and use_dt_domains values.
     *
     * If DT domain property is valid (domain >= 0) and
     * use_dt_domains != 0, the DT assignment is valid since this means
     * we have not previously allocated a domain number by using
     * pci_get_new_domain_nr(); we should also update use_dt_domains to
     * 1, to indicate that we have just assigned a domain number from
     * DT.
     *
     * If DT domain property value is not valid (ie domain < 0), and we
     * have not previously assigned a domain number from DT
     * (use_dt_domains != 1) we should assign a domain number by
     * using the:
     *
     * pci_get_new_domain_nr()
     *
     * API and update the use_dt_domains value to keep track of method we
     * are using to assign domain numbers (use_dt_domains = 0).
     *
     * All other combinations imply we have a platform that is trying
     * to mix domain numbers obtained from DT and pci_get_new_domain_nr(),
     * which is a recipe for domain mishandling and it is prevented by
     * invalidating the domain value (domain = -1) and printing a
     * corresponding error.
     */
    if ( domain >= 0 && use_dt_domains )
    {
        use_dt_domains = 1;
    }
    else if ( domain < 0 && use_dt_domains != 1 )
    {
        use_dt_domains = 0;
        domain = pci_get_new_domain_nr();
    }
    else
    {
        domain = -1;
    }

    return domain;
}

int pci_host_common_probe(struct dt_device_node *dev, const struct pci_ecam_ops *ops) {
    struct pci_host_bridge *bridge;

    int res;

    res = pci_alloc_host_bridge(&bridge);
    if (res != 0) {
        printk(XENLOG_ERR "failed to allocate pci host bridge struct. retval=%d", res);
        BUG();
    }

    bridge->cfg = gen_pci_init(dev, ops);
    if (!bridge->cfg) {
        res = -ENOMEM;
        goto err;
    }

    bridge->dt_node = dev;
    bridge->ops = &ops->pci_ops;

    bridge->segment = pci_bus_find_domain_nr(dev);
    if (bridge->segment < 0) {
        printk(XENLOG_ERR "Inconsistent \"linux,pci-domain\" property in DT\n");
        BUG();
    }
    pci_add_host_bridge(bridge);

    return 0;

err:
    xfree(bridge);
    return res;
}

/*
 * Get host bridge node given a device attached to it.
 */
const struct dt_device_node *pci_find_host_bridge_node(const struct pci_dev *pdev)
{
    struct pci_host_bridge *bridge;

    bridge = pci_find_host_bridge(pdev->seg, pdev->bus);
    if ( unlikely(!bridge) )
    {
        printk(XENLOG_ERR "Unable to find PCI bridge for %pp\n", &pdev->sbdf);
        return NULL;
    }
    return bridge->dt_node;
}
/*
 * This function will lookup an hostbridge based on the segment and bus
 * number.
 */
struct pci_host_bridge *pci_find_host_bridge(u16 segment, u8 bus)
{
    struct pci_host_bridge *bridge;

    list_for_each_entry( bridge, &pci_host_bridges, node )
    {
        if ( bridge->segment != segment )
            continue;
        if ( (bus < bridge->cfg->busn_start) || (bus > bridge->cfg->busn_end) )
            continue;
        return bridge;
    }

    return NULL;
}

/*
 * This function will lookup an hostbridge based on config space address.
 */
int pci_get_host_bridge_segment(const struct dt_device_node *node, u16 *segment)
{
    struct pci_host_bridge *bridge;

    list_for_each_entry( bridge, &pci_host_bridges, node )
    {
        if ( bridge->dt_node != node )
            continue;

        *segment = bridge->segment;
        return 0;
    }

    return -EINVAL;
}

int pci_host_iterate_bridges_and_count(struct domain *d, cb_func_t func) {
    struct pci_host_bridge *bridge;
    int count = 0;

    list_for_each_entry(bridge, &pci_host_bridges, node) {
        int res;

        res = func(d, bridge);
        if (res < 0) return res;
        count += res;
    }

    return count;
}

/**
 * For each PCI host bridge we need to only map those ranges
 * which are used by Domain-0 to properly initialize the bridge,
 * e.g. we do not want to map ECAM configuration space which lives in
 * "reg" device tree property, but we want to map other regions of
 * the host bridge. The PCI aperture defined by the "ranges" device
 * tree property should also be skipped.
*/
int __init pci_host_bridge_mappings(struct domain *d) {
    struct pci_host_bridge *bridge;

    list_for_each_entry(bridge, &pci_host_bridges, node) {
        const struct dt_device_node *dev = bridge->dt_node;

        for (size_t i = 0; i < dt_number_of_address(dev); i++)
        {
            paddr_t addr, size; int res;

            res = dt_device_get_paddr(dev, i, &addr, &size);
            if (res) {
                printk(XENLOG_ERR
                       "Unable to retrieve address range index=%lu for %s\n",
                       i, dt_node_full_name(dev));
                return res;
            }

            if (bridge->ops->need_p2m_hwdom_mapping(d, bridge, addr)) {
                res = map_mmio_regions(d, gaddr_to_gfn(addr), size / PAGE_SIZE, maddr_to_mfn(addr));
                if (res) return res;
            }
        }        
    }
    
    return 0;
}

/*
 * TODO: BAR addresses and Root Complex window addresses are not guaranteed
 * to be page aligned. We should check for alignment but this is not the
 * right place for alignment check.
 */
static int is_bar_valid(const struct dt_device_node *dev,
                        uint64_t addr, uint64_t len, void *data)
{
    struct pdev_bar_check *bar_data = data;
    paddr_t s = bar_data->start;
    paddr_t e = bar_data->end;

    if ( (s >= addr) && (e <= (addr + len - 1)) )
        bar_data->is_valid =  true;

    return 0;
}

// ACPI ?
bool pci_check_bar(const struct pci_dev *pdev, mfn_t start, mfn_t end) {
    int ret;
    const struct dt_device_node *dt_node;
    paddr_t s = mfn_to_maddr(start);
    paddr_t e = mfn_to_maddr(end);
    struct pdev_bar_check bar_data =  {
        .start = s,
        .end = e,
        .is_valid = false
    };

    if ( s >= e )
        return false;

    dt_node = pci_find_host_bridge_node(pdev);
    if ( !dt_node )
        return false;

    ret = dt_for_each_range(dt_node, &is_bar_valid, &bar_data);
    if ( ret < 0 )
        return false;

    return bar_data.is_valid;
}
