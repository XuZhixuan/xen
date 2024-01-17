/* SPDX-License-Identifier: MIT */
/*
 * xen/arch/riscv/imsic.h
 *
 * RISC-V Incoming MSI Controller support
 *
 * (c) 2024 Microchip Technology Inc.
 *
 */

#ifndef __ASM_RISCV_IMSIC_H__
#define __ASM_RISCV_IMSIC_H__

#include <xen/types.h>

#define IMSIC_MMIO_PAGE_SHIFT	12
#define IMSIC_MMIO_PAGE_SZ		(1UL << IMSIC_MMIO_PAGE_SHIFT)
#define IMSIC_MMIO_PAGE_LE		0x00
#define IMSIC_MMIO_PAGE_BE		0x04

#define IMSIC_MIN_ID			63
#define IMSIC_MAX_ID			2048

#define IMSIC_EIDELIVERY		0x70

#define IMSIC_EITHRESHOLD		0x72

#define IMSIC_EIP0				0x80
#define IMSIC_EIP63				0xbf
#define IMSIC_EIPx_BITS			32

#define IMSIC_EIE0				0xc0
#define IMSIC_EIE63				0xff
#define IMSIC_EIEx_BITS			32

#define IMSIC_FIRST				IMSIC_EIDELIVERY
#define IMSIC_LAST				IMSIC_EIE63

#define IMSIC_MMIO_SETIPNUM_LE	0x00
#define IMSIC_MMIO_SETIPNUM_BE	0x04

#define IMSIC_GEILEN CONFIG_GEILEN
#define IMSIC_HART_OFFSET ((1 + IMSIC_GEILEN) * IMSIC_MMIO_PAGE_SZ)

struct imsic_msi {
    paddr_t base_addr;
    unsigned long offset;  
};

struct imsic_mmios {
	paddr_t base_addr;
	unsigned long size;
    bool harts[NR_CPUS];
};

struct imsic_config {
    /* base address */
    uint64_t base_addr;
	/* Bits representing Guest index, HART index, and Group index */
	uint32_t guest_index_bits;
	uint32_t hart_index_bits;
	uint32_t group_index_bits;
	uint32_t group_index_shift;

	/* imsic phandle */
	uint32_t phandle;

	/* number of parent irq */
	uint32_t nr_parent_irqs;

	/* number off interrupt identities */
	uint32_t nr_ids;

    /* mmios */
	uint32_t nr_mmios;
    struct imsic_mmios *mmios;

    /* MSI */
	struct imsic_msi msi[NR_CPUS];
};

struct dt_device_node;
struct domain;

int imsic_init(struct dt_device_node *node);
int imsic_register_domain(const struct domain *d);
int imsic_unregister_domain(const struct domain *d);
int imsic_make_dt_node(struct domain *d, void *fdt, const struct dt_device_node *node);
int imsic_get_guest_interrupt_file(const struct domain *d);
int imsic_iomem_deny_access(struct domain *d);

const struct imsic_config *imsic_get_config(void);

#endif /* __ASM_RISCV_IMSIC_H__ */
