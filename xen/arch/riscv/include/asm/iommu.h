/* SPDX-License-Identifier: MIT */
/* Copyright 2019 (C) Alistair Francis <alistair.francis@wdc.com> */

#ifndef __ARCH_RISCV_IOMMU_H__
#define __ARCH_RISCV_IOMMU_H__

struct arch_iommu
{
    /* Private information for the IOMMU drivers */
    void *priv;
};

#endif /* __ARCH_RISCV_IOMMU_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
