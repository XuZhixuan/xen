/* SPDX-License-Identifier: MIT */
/*
 * xen/arch/riscv/vaplic.c
 *
 * Virtual RISC-V Advanced Platform-Level Interrupt Controller support
 *
 * Copyright (c) 2024 Microchip.
 *
 */

#ifndef __ASM_RISCV_VAPLIC_H__
#define __ASM_RISCV_VAPLIC_H__

#include <xen/types.h>

#include <asm/aplic.h>
#include <asm/gic.h>

#define to_vaplic(v) container_of(v, struct vaplic, base)

struct vaplic_regs {
    uint32_t domaincfg;
    uint32_t smsiaddrcfg;
    uint32_t smsiaddrcfgh;
};

struct vaplic {
    struct vgic base;
    struct vaplic_regs regs;
    int guest_file_id;
    uint32_t *auth_irq_bmp;
};

struct vaplic* vaplic_alloc(struct vcpu *vcpu);
void vaplic_free(struct vaplic *v);

#endif /* __ASM_RISCV_VAPLIC_H__ */
