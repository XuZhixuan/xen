/* SPDX-License-Identifier: MIT */
/*
 * xen/arch/riscv/insclude/asm/vsbi.h
 *
 * Handle sbi calls from guest
 *
 * Copyright (c) 2024 Microchip.
 *
 */

#ifndef __ASM_RISCV_VSBI_H__
#define __ASM_RISCV_VSBI_H__

struct vcpu;
struct regs;

void vsbi_handle_ecall(struct vcpu *vcpu, struct cpu_user_regs *regs);

#endif
