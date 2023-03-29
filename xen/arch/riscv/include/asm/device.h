#ifndef __ASM_RISCV_DEVICE_H
#define __ASM_RISCV_DEVICE_H

enum device_type
{
    DEV_DT,
};

struct dev_archdata {
    void *iommu;    /* IOMMU private data */
};

/* struct device - The basic device structure */
struct device
{
    enum device_type type;
    struct dt_device_node *of_node; /* Used by drivers imported from Linux */
    struct dev_archdata archdata;
    struct iommu_fwspec *iommu_fwspec; /* per-device IOMMU instance data */
};

typedef struct device device_t;

#endif /* __ASM_RISCV_DEVICE_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
