#include <xen/device_tree.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/param.h>
#include <xen/pci.h>

/*
 * PIRQ event channels are not supported on RISC-V, so nothing to do.
 */
int inline arch_pci_clean_pirqs(struct domain *d)
{
    return 0;
}

struct pci_dev *dev_to_pci(struct device *dev)
{
    ASSERT(dev->type == DEV_PCI);

    return container_of(dev, struct pci_dev, arch.dev);
}

void arch_pci_init_pdev(struct pci_dev *pdev)
{
    pci_to_dev(pdev)->type = DEV_PCI;
}

static int __init dt_pci_init(void)
{
    struct dt_device_node *np;
    int rc;

    dt_for_each_device_node(dt_host, np)
    {
        rc = device_init(np, DEVICE_PCI_HOSTBRIDGE, NULL);
        /*
         * Ignore the following error codes:
         *   - EBADF: Indicate the current device is not a pci device.
         *   - ENODEV: The pci device is not present or cannot be used by
         *     Xen.
         */
        if( !rc || rc == -EBADF || rc == -ENODEV )
            continue;

        return rc;
    }

    return 0;
}

/* By default pci passthrough is disabled. */
bool __read_mostly pci_passthrough_enabled;
boolean_param("pci-passthrough", pci_passthrough_enabled);

static int __init pci_init(void)
{
    /*
     * Enable PCI passthrough when has been enabled explicitly
     * (pci-passthrough=on).
     */
    if ( !pci_passthrough_enabled )
        return 0;

    pci_segments_init();

    return dt_pci_init();
    
}
__initcall(pci_init);
