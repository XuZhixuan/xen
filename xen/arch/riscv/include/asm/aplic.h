/* SPDX-License-Identifier: MIT */
/*
 * xen/arch/riscv/aplic.h
 *
 * RISC-V Advanced Platform-Level Interrupt Controller support
 *
 * Copyright (c) 2024 Microchip.
 *
 */

#ifndef __ASM_RISCV_APLIC_H__
#define __ASM_RISCV_APLIC_H__

#include <xen/const.h>
#include <xen/types.h>

#include <asm/imsic.h>

#define APLIC_REG_GET(addr, offset) (*(uint32_t *)((uint64_t)addr + offset))
#define APLIC_REG_SET(addr, offset, value) ((*(uint32_t *)((uint64_t)addr + offset) = value))

#define APLIC_MAX_IDC           BIT(14, UL)
#define APLIC_MAX_SOURCE        1024
#define APLIC_REG_OFFSET_MASK   0x3FFF

#define APLIC_DOMAINCFG         0x0000
#define APLIC_DOMAINCFG_RDONLY  0x80000000
#define APLIC_DOMAINCFG_IE      BIT(8, UL)
#define APLIC_DOMAINCFG_DM      BIT(2, UL)
#define APLIC_DOMAINCFG_BE      BIT(0, UL)

#define APLIC_SOURCECFG_BASE            0x0004
#define APLIC_SOURCECFG_LAST            0x0ffc
#define APLIC_SOURCECFG_D               BIT(10,UL)
#define APLIC_SOURCECFG_CHILDIDX_MASK   0x000003ff
#define APLIC_SOURCECFG_SM_MASK         0x00000007
#define APLIC_SOURCECFG_SM_INACTIVE     0x0
#define APLIC_SOURCECFG_SM_DETACH       0x1
#define APLIC_SOURCECFG_SM_EDGE_RISE    0x4
#define APLIC_SOURCECFG_SM_EDGE_FALL    0x5
#define APLIC_SOURCECFG_SM_LEVEL_HIGH   0x6
#define APLIC_SOURCECFG_SM_LEVEL_LOW    0x7

#define APLIC_MMSICFGADDR       0x1bc0
#define APLIC_MMSICFGADDRH      0x1bc4
#define APLIC_SMSICFGADDR       0x1bc8
#define APLIC_SMSICFGADDRH      0x1bcc

#ifdef CONFIG_RISCV_M_MODE
#define APLIC_xMSICFGADDR       APLIC_MMSICFGADDR
#define APLIC_xMSICFGADDRH      APLIC_MMSICFGADDRH
#else
#define APLIC_xMSICFGADDR       APLIC_SMSICFGADDR
#define APLIC_xMSICFGADDRH      APLIC_SMSICFGADDRH
#endif

#define APLIC_xMSICFGADDRH_L            BIT(31, UL)
#define APLIC_xMSICFGADDRH_HHXS_MASK    0x1f
#define APLIC_xMSICFGADDRH_HHXS_SHIFT   24
#define APLIC_xMSICFGADDRH_LHXS_MASK    0x7
#define APLIC_xMSICFGADDRH_LHXS_SHIFT   20
#define APLIC_xMSICFGADDRH_HHXW_MASK    0x7
#define APLIC_xMSICFGADDRH_HHXW_SHIFT   16
#define APLIC_xMSICFGADDRH_LHXW_MASK    0xf
#define APLIC_xMSICFGADDRH_LHXW_SHIFT   12
#define APLIC_xMSICFGADDRH_BAPPN_MASK   0xfff

#define APLIC_xMSICFGADDR_PPN_SHIFT	12

#define APLIC_xMSICFGADDR_PPN_HART(lhxs) \
    (BIT(lhxs, UL) - 1)

#define APLIC_xMSICFGADDR_PPN_LHX_MASK(lhxw) \
    (BIT(lhxw, UL) - 1)
#define APLIC_xMSICFGADDR_PPN_LHX_SHIFT(lhxs) \
    ((lhxs))
#define APLIC_xMSICFGADDR_PPN_LHX(lhxw, lhxs) \
    (APLIC_xMSICFGADDR_PPN_LHX_MASK(lhxw) << \
     APLIC_xMSICFGADDR_PPN_LHX_SHIFT(lhxs))

#define APLIC_xMSICFGADDR_PPN_HHX_MASK(hhxw) \
    (BIT(hhxw, UL) - 1)
#define APLIC_xMSICFGADDR_PPN_HHX_SHIFT(hhxs) \
    ((hhxs) + APLIC_xMSICFGADDR_PPN_SHIFT)
#define APLIC_xMSICFGADDR_PPN_HHX(hhxw, hhxs) \
    (APLIC_xMSICFGADDR_PPN_HHX_MASK(hhxw) << \
     APLIC_xMSICFGADDR_PPN_HHX_SHIFT(hhxs))

#define APLIC_IRQBITS_PER_REG       32

#define APLIC_SETIP_BASE            0x1c00
#define APLIC_SETIP_LAST            0x1c7c
#define APLIC_SETIPNUM              0x1cdc

#define APLIC_CLRIP_BASE            0x1d00
#define APLIC_CLRIP_LAST            0x1d7c
#define APLIC_CLRIPNUM              0x1ddc

#define APLIC_SETIE_BASE            0x1e00
#define APLIC_SETIE_LAST            0x1e7c
#define APLIC_SETIENUM              0x1edc

#define APLIC_CLRIE_BASE            0x1f00
#define APLIC_CLRIE_LAST            0x1f7c
#define APLIC_CLRIENUM              0x1fdc

#define APLIC_SETIPNUM_LE           0x2000
#define APLIC_SETIPNUM_BE           0x2004

#define APLIC_GENMSI                0x3000

#define APLIC_TARGET_BASE           0x3004
#define APLIC_TARGET_LAST           0x3FFC
#define APLIC_TARGET_HART_IDX_SHIFT 18
#define APLIC_TARGET_HART_IDX_MASK  0x3fff
#define APLIC_TARGET_GUEST_IDX_SHIFT    12
#define APLIC_TARGET_GUEST_IDX_MASK 0x3f
#define APLIC_TARGET_IPRIO_MASK     0xff
#define APLIC_TARGET_EIID_MASK      0x7ff

#define APLIC_IDC_BASE              0x4000
#define APLIC_IDC_SIZE              32

#define APLIC_IDC_IDELIVERY         0x00

#define APLIC_IDC_IFORCE            0x04

#define APLIC_IDC_ITHRESHOLD        0x08

#define APLIC_IDC_TOPI              0x18
#define APLIC_IDC_TOPI_ID_SHIFT     16
#define APLIC_IDC_TOPI_ID_MASK      0x3ff
#define APLIC_IDC_TOPI_PRIO_MASK    0xff

#define APLIC_IDC_CLAIMI            0x1c

struct aplic_regs {
    uint32_t domaincfg;
    uint32_t sourcecfg[1023];
    uint8_t _reserved1[0xBC0];

    uint32_t mmsiaddrcfg;
    uint32_t mmsiaddrcfgh;
    uint32_t smsiaddrcfg;
    uint32_t smsiaddrcfgh;
    uint8_t  reserved2[0x30];

    uint32_t setip[32];
    uint8_t reserved3[92];

    uint32_t setipnum;
    uint8_t reserved4[0x20];

    uint32_t in_clrip[32];
    uint8_t reserved5[92];

    uint32_t clripnum;
    uint8_t reserved6[32];

    uint32_t setie[32];
    uint8_t reserved7[92];

    uint32_t setienum;
    uint8_t reserved8[32];

    uint32_t clrie[32];
    uint8_t reserved9[92];

    uint32_t clrienum;
    uint8_t reserved10[32];

    uint32_t setipnum_le;
    uint32_t setipnum_be;
    uint8_t reserved11[4088];

    uint32_t genmsi;
    uint32_t target[1023];
};

struct aplic_priv {
    /* number of irqs */
    uint32_t   nr_irqs;

    /* base physical address and size */
    paddr_t    paddr_start;
    paddr_t    paddr_end;
    uint64_t   size;

    /* registers */
    struct aplic_regs   *regs;

    /* imsic configuration */
    const struct imsic_config *imsic_cfg;
};

#endif
