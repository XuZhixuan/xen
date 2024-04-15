/*
 * xen/include/asm/riscv/iommu_fwspec.h
 *
 * Contains a common structure to hold the per-device firmware data and
 * declaration of functions used to maintain that data
 *
 * Based on Linux's iommu_fwspec support you can find at:
 *    include/linux/iommu.h
 *
 * Copyright (C) 2007-2008 Advanced Micro Devices, Inc.
 *
 * Copyright (C) 2019 EPAM Systems Inc.
 * 
 * Copyright (C) 2024 Microchip
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __ARCH_RISCV_IOMMU_FWSPEC_H__
#define __ARCH_RISCV_IOMMU_FWSPEC_H__

/* per-device IOMMU instance data */
struct iommu_fwspec {
    /* this device's IOMMU */
    struct device *iommu_dev;
    /* IOMMU driver private data for this device */
    void *iommu_priv;
    /* number of associated device IDs */
    unsigned int num_ids;
    /* IDs/options which this device may present to the IOMMU 
     * the upper 32 bits represent the device identifier
     * the lower 32 bits represent the tc (translation control options)
     *
     * transaction control options are available if <iommu_cells> is set to 2
     * int the device tree otherwise is <iommu_cells> is set to 1 (only device ID)
     * for available option see RISCV_IOMMU_OPTS_xx in iommu.h
     * 
     */
    uint64_t ids[];
};

int iommu_fwspec_init(struct device *dev, struct device *iommu_dev);
void iommu_fwspec_free(struct device *dev);
int iommu_fwspec_add_ids(struct device *dev, const uint64_t *ids,
                         unsigned int num_ids);

static inline struct iommu_fwspec *dev_iommu_fwspec_get(struct device *dev)
{
    return dev->iommu_fwspec;
}

static inline void dev_iommu_fwspec_set(struct device *dev,
                                        struct iommu_fwspec *fwspec)
{
    dev->iommu_fwspec = fwspec;
}

#endif /* __ARCH_RISCV_IOMMU_FWSPEC_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
