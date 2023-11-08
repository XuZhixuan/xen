#include <asm/asm.h>
#include <asm/asm-offsets.h>
#include <asm/domain.h>
#include <asm/processor.h>
#include <asm/riscv_encoding.h>
#include <asm/traps.h>

ENTRY(handle_trap)
        /*
        * swap sscratch and tp
        *
        * After the swap, if a guest trapped, tp will have a pointer to pcpu_info of the guest.
        * After the swap, If xen trapped, tp will be empty.
        */
        csrrw   tp, CSR_SSCRATCH, tp

        /* Based on Linux kenrel arch/riscv/entry.S */
        bnez    tp, .L_save_context

.L_restore_kernel_tpsp:
        csrr    tp, CSR_SSCRATCH
        REG_S   sp, PCPU_INFO_HYPERVISOR_SP(tp)

.L_save_context:
        REG_S   sp, PCPU_INFO_GUEST_SP(tp)
        REG_L   sp, PCPU_INFO_HYPERVISOR_SP(tp)
        addi    sp, sp, -(CPU_INFO_SIZE)

        /* Save registers */
        REG_S   ra, CPU_USER_REGS_RA(sp)
        REG_S   gp, CPU_USER_REGS_GP(sp)
        REG_S   t0, CPU_USER_REGS_T0(sp)

        REG_S   t1, CPU_USER_REGS_T1(sp)
        REG_S   t2, CPU_USER_REGS_T2(sp)
        REG_S   s0, CPU_USER_REGS_S0(sp)
        REG_S   s1, CPU_USER_REGS_S1(sp)
        REG_S   a0, CPU_USER_REGS_A0(sp)
        REG_S   a1, CPU_USER_REGS_A1(sp)
        REG_S   a2, CPU_USER_REGS_A2(sp)
        REG_S   a3, CPU_USER_REGS_A3(sp)
        REG_S   a4, CPU_USER_REGS_A4(sp)
        REG_S   a5, CPU_USER_REGS_A5(sp)
        REG_S   a6, CPU_USER_REGS_A6(sp)
        REG_S   a7, CPU_USER_REGS_A7(sp)
        REG_S   s2, CPU_USER_REGS_S2(sp)
        REG_S   s3, CPU_USER_REGS_S3(sp)
        REG_S   s4, CPU_USER_REGS_S4(sp)
        REG_S   s5, CPU_USER_REGS_S5(sp)
        REG_S   s6, CPU_USER_REGS_S6(sp)
        REG_S   s7, CPU_USER_REGS_S7(sp)
        REG_S   s8, CPU_USER_REGS_S8(sp)
        REG_S   s9, CPU_USER_REGS_S9(sp)
        REG_S   s10,CPU_USER_REGS_S10(sp)
        REG_S   s11,CPU_USER_REGS_S11(sp)
        REG_S   t3, CPU_USER_REGS_T3(sp)
        REG_S   t4, CPU_USER_REGS_T4(sp)
        REG_S   t5, CPU_USER_REGS_T5(sp)
        REG_S   t6, CPU_USER_REGS_T6(sp)

        REG_L s0, PCPU_INFO_GUEST_SP(tp)
        csrr s1, CSR_SSTATUS
        csrr s2, CSR_SEPC
        csrr s3, CSR_STVAL
        csrr s4, CSR_SCAUSE
        csrr s5, CSR_SSCRATCH
        csrr s6, CSR_HSTATUS

        REG_S s0, CPU_USER_REGS_SP(sp)
        REG_S s1, CPU_USER_REGS_SSTATUS(sp)
        REG_S s2, CPU_USER_REGS_SEPC(sp)

        /* REG_S s3, CPU_USER_REGS_BADADDR(sp) */
        /* REG_S s4, CPU_USER_REGS_SCAUSE(sp) */

        REG_S s5, CPU_USER_REGS_TP(sp)
        REG_S s6, CPU_USER_REGS_HSTATUS(sp)

        /*
         * Set the scratch register to 0, so that if a recursive exception
         * occurs, the exception vector knows it came from the kernel
         */
        csrw    CSR_SSCRATCH, x0

        mv      a0, sp
        jal     do_trap

        REG_L   t0, CPU_USER_REGS_HSTATUS(sp)
        andi    t0, t0, HSTATUS_SPV

        beqz    t0, .L_restore_registers

        /* Save unwound kernel stack pointer in thread_info */
        addi    s0, sp, CPU_INFO_SIZE
        REG_S   s0, PCPU_INFO_HYPERVISOR_SP(tp)

        /*
         * Save TP into the scratch register , so we can find the kernel data
         * structures again.
         */
        csrw    CSR_SSCRATCH, tp

.L_restore_registers:
        /* Restore HSSTATUS */
        REG_L	t0, CPU_USER_REGS_HSTATUS(sp)
        csrw	CSR_HSTATUS, t0

        /* Restore stack_cpu_regs */
        REG_L   t0, CPU_USER_REGS_SEPC(sp)
        csrw    CSR_SEPC, t0
        REG_L   t0, CPU_USER_REGS_SSTATUS(sp)
        csrw    CSR_SSTATUS, t0

        REG_L   ra, CPU_USER_REGS_RA(sp)
        REG_L   gp, CPU_USER_REGS_GP(sp)
        REG_L   t0, CPU_USER_REGS_T0(sp)
        REG_L   t1, CPU_USER_REGS_T1(sp)
        REG_L   t2, CPU_USER_REGS_T2(sp)
        REG_L   s0, CPU_USER_REGS_S0(sp)
        REG_L   s1, CPU_USER_REGS_S1(sp)
        REG_L   a0, CPU_USER_REGS_A0(sp)
        REG_L   a1, CPU_USER_REGS_A1(sp)
        REG_L   a2, CPU_USER_REGS_A2(sp)
        REG_L   a3, CPU_USER_REGS_A3(sp)
        REG_L   a4, CPU_USER_REGS_A4(sp)
        REG_L   a5, CPU_USER_REGS_A5(sp)
        REG_L   a6, CPU_USER_REGS_A6(sp)
        REG_L   a7, CPU_USER_REGS_A7(sp)
        REG_L   s2, CPU_USER_REGS_S2(sp)
        REG_L   s3, CPU_USER_REGS_S3(sp)
        REG_L   s4, CPU_USER_REGS_S4(sp)
        REG_L   s5, CPU_USER_REGS_S5(sp)
        REG_L   s6, CPU_USER_REGS_S6(sp)
        REG_L   s7, CPU_USER_REGS_S7(sp)
        REG_L   s8, CPU_USER_REGS_S8(sp)
        REG_L   s9, CPU_USER_REGS_S9(sp)
        REG_L   s10, CPU_USER_REGS_S10(sp)
        REG_L   s11, CPU_USER_REGS_S11(sp)
        REG_L   t3, CPU_USER_REGS_T3(sp)
        REG_L   t4, CPU_USER_REGS_T4(sp)
        REG_L   t5, CPU_USER_REGS_T5(sp)
        REG_L   t6, CPU_USER_REGS_T6(sp)

        /* Restore tp */
        REG_L   tp, CPU_USER_REGS_TP(sp)

        /* Restore sp */
        REG_L   sp, CPU_USER_REGS_SP(sp)

        sret

/* t0 is used as a temporary reg and is clobbered to oblivion */
ENTRY(return_to_new_vcpu64)
        //jal     leave_hypervisor_to_guest

        REG_L   sp, PCPU_INFO_HYPERVISOR_SP(tp)

        /* Backup tp into sscratch */
        csrrw   tp, CSR_SSCRATCH, tp

        /* Set vCPU registers */
        REG_L   t0, CPU_USER_REGS_SEPC(sp)
        csrw    sepc, t0

        /* Hartid goes to a0 */
        REG_L   a0, CPU_USER_REGS_A0(sp)

        /* DTB goes to a1 */
        REG_L   a1, CPU_USER_REGS_A1(sp)

        /* Set guest mode to supervisor */
        li      t0, SSTATUS_SPP
        csrs    CSR_SSTATUS, t0

        /* Enter guest */
        sret

/*
 * struct vcpu *__context_switch(struct vcpu *prev, struct vcpu *next)
 *
 * a0 - prev
 * a1 - next
 *
 * Returns prev in a0
 */
ENTRY(__context_switch)
        REG_S   s0, VCPU_SAVED_CONTEXT_OFFSET(S0)(a0)
        REG_S   s1, VCPU_SAVED_CONTEXT_OFFSET(S1)(a0)
        REG_S   s2, VCPU_SAVED_CONTEXT_OFFSET(S2)(a0)
        REG_S   s3, VCPU_SAVED_CONTEXT_OFFSET(S3)(a0)
        REG_S   s4, VCPU_SAVED_CONTEXT_OFFSET(S4)(a0)
        REG_S   s5, VCPU_SAVED_CONTEXT_OFFSET(S5)(a0)
        REG_S   s6, VCPU_SAVED_CONTEXT_OFFSET(S6)(a0)
        REG_S   s7, VCPU_SAVED_CONTEXT_OFFSET(S7)(a0)
        REG_S   s8, VCPU_SAVED_CONTEXT_OFFSET(S8)(a0)
        REG_S   s9, VCPU_SAVED_CONTEXT_OFFSET(S9)(a0)
        REG_S   s10, VCPU_SAVED_CONTEXT_OFFSET(S10)(a0)
        REG_S   s11, VCPU_SAVED_CONTEXT_OFFSET(S11)(a0)
        REG_S   sp, VCPU_SAVED_CONTEXT_OFFSET(SP)(a0)
        REG_S   gp, VCPU_SAVED_CONTEXT_OFFSET(GP)(a0)
        REG_S   ra, VCPU_SAVED_CONTEXT_OFFSET(RA)(a0)

        REG_L   s0, VCPU_SAVED_CONTEXT_OFFSET(S0)(a1)
        REG_L   s1, VCPU_SAVED_CONTEXT_OFFSET(S1)(a1)
        REG_L   s2, VCPU_SAVED_CONTEXT_OFFSET(S2)(a1)
        REG_L   s3, VCPU_SAVED_CONTEXT_OFFSET(S3)(a1)
        REG_L   s4, VCPU_SAVED_CONTEXT_OFFSET(S4)(a1)
        REG_L   s5, VCPU_SAVED_CONTEXT_OFFSET(S5)(a1)
        REG_L   s6, VCPU_SAVED_CONTEXT_OFFSET(S6)(a1)
        REG_L   s7, VCPU_SAVED_CONTEXT_OFFSET(S7)(a1)
        REG_L   s8, VCPU_SAVED_CONTEXT_OFFSET(S8)(a1)
        REG_L   s9, VCPU_SAVED_CONTEXT_OFFSET(S9)(a1)
        REG_L   s10, VCPU_SAVED_CONTEXT_OFFSET(S10)(a1)
        REG_L   s11, VCPU_SAVED_CONTEXT_OFFSET(S11)(a1)
        REG_L   sp, VCPU_SAVED_CONTEXT_OFFSET(SP)(a1)
        REG_L   gp, VCPU_SAVED_CONTEXT_OFFSET(GP)(a1)
        REG_L   ra, VCPU_SAVED_CONTEXT_OFFSET(RA)(a1)

        ret
