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

#define current              (this_cpu(curr_vcpu))
#define set_current(vcpu)    do { current = (vcpu); } while (0)
#define get_cpu_current(cpu) (per_cpu(curr_vcpu, cpu))

/* Per-VCPU state that lives at the top of the stack */
struct cpu_info {
    /* This should be the first member. */
    struct cpu_user_regs guest_cpu_user_regs;
};

/*
 * TODO: should be reworked! instead of using stack for cpu_info purposes
 *       tp register would be more proper way to implement get cpu info
 *       in RISC-V.
 */
static inline struct cpu_info *get_cpu_info(void)
{
#ifdef __clang__
    unsigned long sp;

    asm ("mov %0, sp" : "=r" (sp));
#else
    register unsigned long sp asm ("sp");
#endif

    return (struct cpu_info *)((sp & ~(STACK_SIZE - 1)) +
                               STACK_SIZE - sizeof(struct cpu_info));
}

#define guest_cpu_user_regs() (&get_cpu_info()->guest_cpu_user_regs)
#define guest_regs(vcpu) (&vcpu->arch.cpu_info->guest_cpu_user_regs)

#define reset_stack_and_jump(fn) switch_stack_and_jump(get_cpu_info(), fn)

#endif /* __ASM_CURRENT_H */
