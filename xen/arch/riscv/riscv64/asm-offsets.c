#define COMPILE_OFFSETS

#include <asm/processor.h>
#include <xen/sched.h>
#include <xen/types.h>

#include <asm/domain.h>

#define DEFINE(_sym, _val)                                                 \
    asm volatile ("\n.ascii\"==>#define " #_sym " %0 /* " #_val " */<==\"" \
                  : : "i" (_val) )
#define BLANK()                                                            \
    asm volatile ( "\n.ascii\"==><==\"" : : )
#define OFFSET(_sym, _str, _mem)                                           \
    DEFINE(_sym, offsetof(_str, _mem));

void asm_offsets(void)
{
    BLANK();
    DEFINE(CPU_USER_REGS_SIZE, sizeof(struct cpu_user_regs));
    OFFSET(CPU_USER_REGS_ZERO, struct cpu_user_regs, zero);
    OFFSET(CPU_USER_REGS_RA, struct cpu_user_regs, ra);
    OFFSET(CPU_USER_REGS_SP, struct cpu_user_regs, sp);
    OFFSET(CPU_USER_REGS_GP, struct cpu_user_regs, gp);
    OFFSET(CPU_USER_REGS_TP, struct cpu_user_regs, tp);
    OFFSET(CPU_USER_REGS_T0, struct cpu_user_regs, t0);
    OFFSET(CPU_USER_REGS_T1, struct cpu_user_regs, t1);
    OFFSET(CPU_USER_REGS_T2, struct cpu_user_regs, t2);
    OFFSET(CPU_USER_REGS_S0, struct cpu_user_regs, s0);
    OFFSET(CPU_USER_REGS_S1, struct cpu_user_regs, s1);
    OFFSET(CPU_USER_REGS_A0, struct cpu_user_regs, a0);
    OFFSET(CPU_USER_REGS_A1, struct cpu_user_regs, a1);
    OFFSET(CPU_USER_REGS_A2, struct cpu_user_regs, a2);
    OFFSET(CPU_USER_REGS_A3, struct cpu_user_regs, a3);
    OFFSET(CPU_USER_REGS_A4, struct cpu_user_regs, a4);
    OFFSET(CPU_USER_REGS_A5, struct cpu_user_regs, a5);
    OFFSET(CPU_USER_REGS_A6, struct cpu_user_regs, a6);
    OFFSET(CPU_USER_REGS_A7, struct cpu_user_regs, a7);
    OFFSET(CPU_USER_REGS_S2, struct cpu_user_regs, s2);
    OFFSET(CPU_USER_REGS_S3, struct cpu_user_regs, s3);
    OFFSET(CPU_USER_REGS_S4, struct cpu_user_regs, s4);
    OFFSET(CPU_USER_REGS_S5, struct cpu_user_regs, s5);
    OFFSET(CPU_USER_REGS_S6, struct cpu_user_regs, s6);
    OFFSET(CPU_USER_REGS_S7, struct cpu_user_regs, s7);
    OFFSET(CPU_USER_REGS_S8, struct cpu_user_regs, s8);
    OFFSET(CPU_USER_REGS_S9, struct cpu_user_regs, s9);
    OFFSET(CPU_USER_REGS_S10, struct cpu_user_regs, s10);
    OFFSET(CPU_USER_REGS_S11, struct cpu_user_regs, s11);
    OFFSET(CPU_USER_REGS_T3, struct cpu_user_regs, t3);
    OFFSET(CPU_USER_REGS_T4, struct cpu_user_regs, t4);
    OFFSET(CPU_USER_REGS_T5, struct cpu_user_regs, t5);
    OFFSET(CPU_USER_REGS_T6, struct cpu_user_regs, t6);
    OFFSET(CPU_USER_REGS_SEPC, struct cpu_user_regs, sepc);
    OFFSET(CPU_USER_REGS_SSTATUS, struct cpu_user_regs, sstatus);
    OFFSET(CPU_USER_REGS_PREGS, struct cpu_user_regs, pregs);
    BLANK();
    OFFSET(VCPU_ARCH_SAVED_CONTEXT, struct vcpu, arch.saved_context);
    OFFSET(VCPU_SAVED_CONTEXT_S0, struct arch_vcpu, saved_context.s0);
    OFFSET(VCPU_SAVED_CONTEXT_S1, struct arch_vcpu, saved_context.s1);
    OFFSET(VCPU_SAVED_CONTEXT_S2, struct arch_vcpu, saved_context.s2);
    OFFSET(VCPU_SAVED_CONTEXT_S3, struct arch_vcpu, saved_context.s3);
    OFFSET(VCPU_SAVED_CONTEXT_S4, struct arch_vcpu, saved_context.s4);
    OFFSET(VCPU_SAVED_CONTEXT_S5, struct arch_vcpu, saved_context.s5);
    OFFSET(VCPU_SAVED_CONTEXT_S6, struct arch_vcpu, saved_context.s6);
    OFFSET(VCPU_SAVED_CONTEXT_S7, struct arch_vcpu, saved_context.s7);
    OFFSET(VCPU_SAVED_CONTEXT_S8, struct arch_vcpu, saved_context.s8);
    OFFSET(VCPU_SAVED_CONTEXT_S9, struct arch_vcpu, saved_context.s9);
    OFFSET(VCPU_SAVED_CONTEXT_S10, struct arch_vcpu, saved_context.s10);
    OFFSET(VCPU_SAVED_CONTEXT_S11, struct arch_vcpu, saved_context.s11);
    OFFSET(VCPU_SAVED_CONTEXT_SP, struct arch_vcpu, saved_context.sp);
    OFFSET(VCPU_SAVED_CONTEXT_GP, struct arch_vcpu, saved_context.gp);
    OFFSET(VCPU_SAVED_CONTEXT_RA, struct arch_vcpu, saved_context.ra);
    BLANK();
    OFFSET(PCPU_INFO_GUEST_CPU_INFO, struct pcpu_info, guest_cpu_info);
    OFFSET(PCPU_INFO_TMP, struct pcpu_info, tmp);
    OFFSET(PCPU_INFO_STACK_CPU_REGS, struct pcpu_info, stack_cpu_regs);
}
