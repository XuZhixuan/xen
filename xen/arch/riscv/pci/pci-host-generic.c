#include <xen/init.h>
#include <xen/pci.h>
#include <asm/device.h>
#include <asm/pci.h>

static const struct dt_device_match __initconstrel gen_pci_dt_match[] =
{
    { .compatible = "pci-host-ecam-generic" },
    { },
};

static int __init pci_host_generic_probe(struct dt_device_node *dev,
                                         const void *data)
{
    return pci_host_common_probe(dev, &pci_generic_ecam_ops);
}

DT_DEVICE_START(pci_gen, "PCI HOST GENERIC", DEVICE_PCI_HOSTBRIDGE)
.dt_match = gen_pci_dt_match,
.init = pci_host_generic_probe,
DT_DEVICE_END
