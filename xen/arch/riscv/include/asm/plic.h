/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * RISC-V Platform-Level Interrupt Controller support
 */

#ifndef __ASM_RISCV_PLIC_H__
#define __ASM_RISCV_PLIC_H__

/* TODO: should be got from DTS */
#define PLIC_BASE  0xc000000
#define PLIC_SIZE  0x0210000
#define PLIC_END (PLIC_BASE + PLIC_SIZE)

#endif
