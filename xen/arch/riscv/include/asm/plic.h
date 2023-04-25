/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * RISC-V Platform-Level Interrupt Controller support
 */

#ifndef __ASM_RISCV_PLIC_H__
#define __ASM_RISCV_PLIC_H__

/* Find the interrupt controller and set up the callback to translate
 * device tree IRQ.
 */
extern void plic_preinit(void);

#endif
