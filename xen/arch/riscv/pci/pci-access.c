#include <xen/pci.h>
#include <asm/io.h>

#define INVALID_VALUE (~0U)
#define PCI_ERR_VALUE(len) GENMASK(0, len * 8)

int pci_generic_config_read(struct pci_host_bridge *bridge, pci_sbdf_t sbdf, u32 reg, u32 len, u32 *value)
{
    void __iomem *addr = bridge->ops->map_bus(bridge, sbdf, reg);

    if ( !addr )
    {
        *value = INVALID_VALUE;
        return -ENODEV;
    }

    switch ( len )
    {
    case 1:
        *value = readb(addr);
        break;
    case 2:
        *value = readw(addr);
        break;
    case 4:
        *value = readl(addr);
        break;
    default:
        ASSERT_UNREACHABLE();
    }

    return 0;
}

int pci_generic_config_write(struct pci_host_bridge *bridge, pci_sbdf_t sbdf, u32 reg, u32 len, u32 value)
{
    void __iomem *addr = bridge->ops->map_bus(bridge, sbdf, reg);

    if ( !addr )
        return -ENODEV;

    switch ( len )
    {
    case 1:
        writeb(value, addr);
        break;
    case 2:
        writew(value, addr);
        break;
    case 4:
        writel(value, addr);
        break;
    default:
        ASSERT_UNREACHABLE();
    }

    return 0;
}

static u32 pci_config_read(pci_sbdf_t sbdf, unsigned int reg, unsigned int len)
{
    u32 val = PCI_ERR_VALUE(len);
    struct pci_host_bridge *bridge = pci_find_host_bridge(sbdf.seg, sbdf.bus);

    if ( unlikely(!bridge) )
        return val;

    if ( unlikely(!bridge->ops->read) )
        return val;

    bridge->ops->read(bridge, sbdf, reg, len, &val);

    return val;
}

static void pci_config_write(pci_sbdf_t sbdf, unsigned int reg, unsigned int len, u32 val)
{
    struct pci_host_bridge *bridge = pci_find_host_bridge(sbdf.seg, sbdf.bus);

    if ( unlikely(!bridge) )
        return;

    if ( unlikely(!bridge->ops->write) )
        return;

    bridge->ops->write(bridge, sbdf, reg, len, val);
}

/*
 * Wrappers for all PCI configuration access functions.
 */

#define PCI_OP_WRITE(size, type)                            \
    void pci_conf_write##size(pci_sbdf_t sbdf,              \
                              unsigned int reg, type val)   \
{                                                           \
    pci_config_write(sbdf, reg, size / 8, val);             \
}

#define PCI_OP_READ(size, type)                             \
    type pci_conf_read##size(pci_sbdf_t sbdf,               \
                              unsigned int reg)             \
{                                                           \
    return pci_config_read(sbdf, reg, size / 8);            \
}

PCI_OP_READ(8, u8)
PCI_OP_READ(16, u16)
PCI_OP_READ(32, u32)
PCI_OP_WRITE(8, u8)
PCI_OP_WRITE(16, u16)
PCI_OP_WRITE(32, u32)
