#ifndef __RISCV_PCI_H__
#define __RISCV_PCI_H__

#ifdef CONFIG_HAS_PCI

#include <asm/p2m.h>
#include <xen/config.h>

#define pci_to_dev(pcidev) (&(pcidev)->arch.dev)

extern bool pci_passthrough_enabled;

/* Arch pci dev struct */
struct arch_pci_dev {
    struct device dev;
};

/* Arch-specific MSI data for vPCI. */
struct vpci_arch_msi {
};

/* Arch-specific MSI-X entry data for vPCI. */
struct vpci_arch_msix_entry {
};

/*
 * Because of the header cross-dependencies, e.g. we need both
 * struct pci_dev and struct arch_pci_dev at the same time, this cannot be
 * done with an inline here. Macro can be implemented, but looks scary.
 */
struct pci_dev *dev_to_pci(struct device *dev);

/*
 * struct to hold the mappings of a config space window. This
 * is expected to be used as sysdata for PCI controllers that
 * use ECAM.
 */
struct pci_config_window {
    paddr_t         phys_addr;
    paddr_t         size;
    uint8_t         busn_start;
    uint8_t         busn_end;
    void __iomem    *win;
};

/*
 * struct to hold pci host bridge information
 * for a PCI controller.
 */
struct pci_host_bridge {
    struct dt_device_node *dt_node;  /* Pointer to the associated DT node */
    struct list_head node;           /* Node in list of host bridges */
    uint16_t segment;                /* Segment number */
    struct pci_config_window* cfg;   /* Pointer to the bridge config window */
    const struct pci_ops *ops;
};

struct pci_ops {
    void __iomem *(*map_bus)(struct pci_host_bridge *bridge, pci_sbdf_t sbdf,
                             uint32_t offset);
    int (*read)(struct pci_host_bridge *bridge, pci_sbdf_t sbdf,
                uint32_t reg, uint32_t len, uint32_t *value);
    int (*write)(struct pci_host_bridge *bridge, pci_sbdf_t sbdf,
                 uint32_t reg, uint32_t len, uint32_t value);
    bool (*need_p2m_hwdom_mapping)(struct domain *d,
                                   struct pci_host_bridge *bridge,
                                   uint64_t addr);
};

/*
 * struct to hold pci ops and bus shift of the config window
 * for a PCI controller.
 */
struct pci_ecam_ops {
    unsigned int            bus_shift;
    struct pci_ops          pci_ops;
    int (*cfg_reg_index)(struct dt_device_node *dev);
    int (*init)(struct pci_config_window *);
};

/* Default ECAM ops */
extern const struct pci_ecam_ops pci_generic_ecam_ops;

typedef  int(*cb_func_t)(struct domain *, struct pci_host_bridge *);

// Provided in xen/arch/riscv/pci/pci-common-host.c
int pci_host_common_probe(struct dt_device_node *dev, const struct pci_ecam_ops *ops);
struct pci_host_bridge *pci_find_host_bridge(u16 segment, u8 bus);
const struct dt_device_node *pci_find_host_bridge_node(const struct pci_dev *pdev);
int pci_get_host_bridge_segment(const struct dt_device_node *node, u16 *segment);
int pci_host_iterate_bridges_and_count(struct domain *d, cb_func_t);
int pci_host_bridge_mappings(struct domain *d);
void arch_pci_init_pdev(struct pci_dev *pdev);
bool pci_check_bar(const struct pci_dev *pdev, mfn_t start, mfn_t end);
int pci_get_new_domain_nr(void);

// Provided in xen/arch/riscv/pci/pci-access.c
int pci_generic_config_read(struct pci_host_bridge *bridge, pci_sbdf_t sbdf, u32 reg, u32 len, u32 *val);
int pci_generic_config_write(struct pci_host_bridge *bridge, pci_sbdf_t sbdf, u32 reg, u32 len, u32 val);

// Provided in xen/arch/riscv/pci/ecam.c
void __iomem *pci_ecam_map_bus(struct pci_host_bridge *bridge, pci_sbdf_t sbdf, u32 where);
bool pci_ecam_need_p2m_hwdom_mapping(struct domain *d, struct pci_host_bridge *bridge, paddr_t addr);

static always_inline bool is_pci_passthrough_enabled(void)
{
    return pci_passthrough_enabled;
}

#else   /*!CONFIG_HAS_PCI*/

struct arch_pci_dev { };

static always_inline bool is_pci_passthrough_enabled(void)
{
    return false;
}

struct pci_dev;

static inline void arch_pci_init_pdev(struct pci_dev *pdev) {}

static inline int pci_get_host_bridge_segment(const struct dt_device_node *node,
                                              uint16_t *segment)
{
    ASSERT_UNREACHABLE();
    return -EINVAL;
}

static inline int pci_get_new_domain_nr(void)
{
    ASSERT_UNREACHABLE();
    return -1;
}

#endif /* !CONFIG_HAS_PCI */

#endif /* __RISCV_PCI_H__ */
