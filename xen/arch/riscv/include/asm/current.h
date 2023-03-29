/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_CURRENT_H
#define __ASM_CURRENT_H

#include <xen/bug.h>
#include <xen/percpu.h>
#include <asm/processor.h>

#define switch_stack_and_jump(stack, fn) do {               \
    asm volatile (                                          \
            "mv sp, %0\n"                                   \
            "j " #fn :: "r" (stack), "X" (fn) : "memory" ); \
    unreachable();                                          \
} while ( false )

struct vcpu;

/* Which VCPU is "current" on this PCPU. */
DECLARE_PER_CPU(struct vcpu *, curr_vcpu);

#define current            (this_cpu(curr_vcpu))
#define get_cpu_current(cpu)  (per_cpu(curr_vcpu, cpu))

/* Per-VCPU state that lives at the top of the stack */
struct cpu_info {
    /* This should be the first member. */
    struct cpu_user_regs guest_cpu_user_regs;
};

static inline struct cpu_info *get_cpu_info(void)
{
    BUG();
    return NULL;
}

#define guest_cpu_user_regs() (&get_cpu_info()->guest_cpu_user_regs)

#endif /* __ASM_CURRENT_H */
