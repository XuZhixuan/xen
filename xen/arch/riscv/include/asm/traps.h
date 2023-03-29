/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_TRAPS_H__
#define __ASM_TRAPS_H__

#include <asm/processor.h>

#ifndef __ASSEMBLY__

struct riscv_trap {
    unsigned long sepc;
    unsigned long scause;
    unsigned long stval;
    unsigned long htval;
    unsigned long htinst;
};

void do_trap(struct cpu_user_regs *cpu_regs);
void handle_trap(void);
void trap_init(void);

#endif /* __ASSEMBLY__ */

#endif /* __ASM_TRAPS_H__ */
