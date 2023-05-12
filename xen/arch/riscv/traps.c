/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 Vates
 *
 * RISC-V Trap handlers
 */

#include <xen/bug.h>
#include <xen/errno.h>
#include <xen/lib.h>
#include <xen/sched.h>

#include <asm/csr.h>
#include <asm/early_printk.h>
#include <asm/processor.h>
#include <asm/traps.h>

#define cast_to_bug_frame(addr) \
    (const struct bug_frame *)(addr)

/*
 * Initialize the trap handling.
 *
 * The function is called after MMU is enabled.
 */
void trap_init(void)
{
    /*
     * When the MMU is off, addr varialbe will be a physical address otherwise
     * it would be a virtual address.
     *
     * It will work fine as:
     *  - access to addr is PC-relative.
     *  - -nopie is used. -nopie really suppresses the compiler emitting
     *    code going through .got (which then indeed would mean using absolute
     *    addresses).
     */
    unsigned long addr = (unsigned long)&handle_trap;

    csr_write(CSR_STVEC, addr);
}

static const char *decode_trap_cause(unsigned long cause)
{
    static const char *const trap_causes[] = {
        [CAUSE_MISALIGNED_FETCH] = "Instruction Address Misaligned",
        [CAUSE_FETCH_ACCESS] = "Instruction Access Fault",
        [CAUSE_ILLEGAL_INSTRUCTION] = "Illegal Instruction",
        [CAUSE_BREAKPOINT] = "Breakpoint",
        [CAUSE_MISALIGNED_LOAD] = "Load Address Misaligned",
        [CAUSE_LOAD_ACCESS] = "Load Access Fault",
        [CAUSE_MISALIGNED_STORE] = "Store/AMO Address Misaligned",
        [CAUSE_STORE_ACCESS] = "Store/AMO Access Fault",
        [CAUSE_USER_ECALL] = "Environment Call from U-Mode",
        [CAUSE_SUPERVISOR_ECALL] = "Environment Call from S-Mode",
        [CAUSE_MACHINE_ECALL] = "Environment Call from M-Mode",
        [CAUSE_FETCH_PAGE_FAULT] = "Instruction Page Fault",
        [CAUSE_LOAD_PAGE_FAULT] = "Load Page Fault",
        [CAUSE_STORE_PAGE_FAULT] = "Store/AMO Page Fault",
        [CAUSE_FETCH_GUEST_PAGE_FAULT] = "Instruction Guest Page Fault",
        [CAUSE_LOAD_GUEST_PAGE_FAULT] = "Load Guest Page Fault",
        [CAUSE_VIRTUAL_INST_FAULT] = "Virtualized Instruction Fault",
        [CAUSE_STORE_GUEST_PAGE_FAULT] = "Guest Store/AMO Page Fault",
    };

    if ( cause < ARRAY_SIZE(trap_causes) && trap_causes[cause] )
        return trap_causes[cause];
    return "UNKNOWN";
}

static const char *decode_reserved_interrupt_cause(unsigned long irq_cause)
{
    switch ( irq_cause )
    {
    case IRQ_M_SOFT:
        return "M-mode Software Interrupt";
    case IRQ_M_TIMER:
        return "M-mode TIMER Interrupt";
    case IRQ_M_EXT:
        return "M-mode External Interrupt";
    default:
        return "UNKNOWN IRQ type";
    }
}

static const char *decode_interrupt_cause(unsigned long cause)
{
    unsigned long irq_cause = cause & ~CAUSE_IRQ_FLAG;

    switch ( irq_cause )
    {
    case IRQ_S_SOFT:
        return "Supervisor Software Interrupt";
    case IRQ_S_TIMER:
        return "Supervisor Timer Interrupt";
    case IRQ_S_EXT:
        return "Supervisor External Interrupt";
    default:
        return decode_reserved_interrupt_cause(irq_cause);
    }
}

static const char *decode_cause(unsigned long cause)
{
    if ( cause & CAUSE_IRQ_FLAG )
        return decode_interrupt_cause(cause);

    return decode_trap_cause(cause);
}

static void do_unexpected_trap(const struct cpu_user_regs *regs)
{
    unsigned long cause = csr_read(CSR_SCAUSE);

    printk("Unhandled exception: %s\n", decode_cause(cause));

    die();
}

void show_execution_state(const struct cpu_user_regs *regs)
{
    printk("implement show_execution_state(regs)\n");
}

/*
 * TODO: change early_printk's function to early_printk with format
 *       when s(n)printf() will be added.
 *
 * Probably the TODO won't be needed as generic do_bug_frame()
 * has been introduced and current implementation will be replaced
 * with generic one when panic(), printk() and find_text_region()
 * (virtual memory?) will be ready/merged
 */
int do_bug_frame(const struct cpu_user_regs *regs, vaddr_t pc)
{
    const struct bug_frame *start, *end;
    const struct bug_frame *bug = NULL;
    unsigned int id = 0;
    const char *filename, *predicate;
    int lineno;

    static const struct bug_frame* bug_frames[] = {
        &__start_bug_frames[0],
        &__stop_bug_frames_0[0],
        &__stop_bug_frames_1[0],
        &__stop_bug_frames_2[0],
        &__stop_bug_frames_3[0],
    };

    for ( id = 0; id < BUGFRAME_NR; id++ )
    {
        start = cast_to_bug_frame(bug_frames[id]);
        end   = cast_to_bug_frame(bug_frames[id + 1]);

        while ( start != end )
        {
            if ( (vaddr_t)bug_loc(start) == pc )
            {
                bug = start;
                goto found;
            }

            start++;
        }
    }

 found:
    if ( bug == NULL )
        return -ENOENT;

    if ( id == BUGFRAME_run_fn )
    {
        void (*fn)(const struct cpu_user_regs *) = bug_ptr(bug);

        fn(regs);

        goto end;
    }

    /* WARN, BUG or ASSERT: decode the filename pointer and line number. */
    filename = bug_ptr(bug);
    lineno = bug_line(bug);

    switch ( id )
    {
    case BUGFRAME_warn:
        printk("Xen WARN at %s:%d\n", filename, lineno);

        show_execution_state(regs);

        goto end;

    case BUGFRAME_bug:
        printk("Xen BUG at %s:%d\n", filename, lineno);

        show_execution_state(regs);

        printk("change wait_for_interrupt to panic() when common is available\n");
        die();

    case BUGFRAME_assert:
        /* ASSERT: decode the predicate string pointer. */
        predicate = bug_msg(bug);

        printk("Assertion %s failed at %s:%d\n", predicate, filename, lineno);

        show_execution_state(regs);

        printk("change wait_for_interrupt to panic() when common is available\n");
        die();
    }

    return -EINVAL;

 end:
    return 0;
}

static bool is_valid_bugaddr(uint32_t insn)
{
    return insn == BUG_INSN_32 ||
           (insn & COMPRESSED_INSN_MASK) == BUG_INSN_16;
}

static uint32_t read_instr(unsigned long pc)
{
    uint16_t instr16 = *(uint16_t *)pc;

    if ( GET_INSN_LENGTH(instr16) == 2 )
        return (uint32_t)instr16;
    else
        return *(uint32_t *)pc;
}

void context_save_csrs(struct vcpu *vcpu)
{
    vcpu->arch.hstatus = csr_read(CSR_HSTATUS);
    vcpu->arch.hedeleg = csr_read(CSR_HEDELEG);
    vcpu->arch.hideleg = csr_read(CSR_HIDELEG);
    vcpu->arch.hvip = csr_read(CSR_HVIP);
    vcpu->arch.hip = csr_read(CSR_HIP);
    vcpu->arch.hie = csr_read(CSR_HIE);
    vcpu->arch.hgeie = csr_read(CSR_HGEIE);
    vcpu->arch.henvcfg = csr_read(CSR_HENVCFG);
    vcpu->arch.hcounteren = csr_read(CSR_HCOUNTEREN);
    vcpu->arch.htimedelta = csr_read(CSR_HTIMEDELTA);
    vcpu->arch.htval = csr_read(CSR_HTVAL);
    vcpu->arch.htinst = csr_read(CSR_HTINST);
    vcpu->arch.hgatp = csr_read(CSR_HGATP);
#ifdef CONFIG_32BIT
    vcpu->arch.henvcfgh = csr_read(CSR_HENVCFGH);
    vcpu->arch.htimedeltah = csr_read(CSR_HTIMEDELTAH);
#endif

    vcpu->arch.vsstatus = csr_read(CSR_VSSTATUS);
    vcpu->arch.vsip = csr_read(CSR_VSIP);
    vcpu->arch.vsie = csr_read(CSR_VSIE);
    vcpu->arch.vstvec = csr_read(CSR_VSTVEC);
    vcpu->arch.vsscratch = csr_read(CSR_VSSCRATCH);
    vcpu->arch.vscause = csr_read(CSR_VSCAUSE);
    vcpu->arch.vstval = csr_read(CSR_VSTVAL);
    vcpu->arch.vsatp = csr_read(CSR_VSATP);
}

void context_restore_csrs(struct vcpu *vcpu)
{
    csr_write(CSR_HSTATUS, vcpu->arch.hstatus);
    csr_write(CSR_HEDELEG, vcpu->arch.hedeleg);
    csr_write(CSR_HIDELEG, vcpu->arch.hideleg);
    csr_write(CSR_HVIP, vcpu->arch.hvip);
    csr_write(CSR_HIP, vcpu->arch.hip);
    csr_write(CSR_HIE, vcpu->arch.hie);
    csr_write(CSR_HGEIE, vcpu->arch.hgeie);
    csr_write(CSR_HENVCFG, vcpu->arch.henvcfg);
    csr_write(CSR_HCOUNTEREN, vcpu->arch.hcounteren);
    csr_write(CSR_HTIMEDELTA, vcpu->arch.htimedelta);
    csr_write(CSR_HTVAL, vcpu->arch.htval);
    csr_write(CSR_HTINST, vcpu->arch.htinst);
    csr_write(CSR_HGATP, vcpu->arch.hgatp);
#ifdef CONFIG_32BIT
    csr_write(CSR_HENVCFGH, vcpu->arch.henvcfgh);
    csr_write(CSR_HTIMEDELTAH, vcpu->arch.htimedeltah);
#endif

    csr_write(CSR_VSSTATUS, vcpu->arch.vsstatus);
    csr_write(CSR_VSIP, vcpu->arch.vsip);
    csr_write(CSR_VSIE, vcpu->arch.vsie);
    csr_write(CSR_VSTVEC, vcpu->arch.vstvec);
    csr_write(CSR_VSSCRATCH, vcpu->arch.vsscratch);
    csr_write(CSR_VSCAUSE, vcpu->arch.vscause);
    csr_write(CSR_VSTVAL, vcpu->arch.vstval);
    csr_write(CSR_VSATP, vcpu->arch.vsatp);
}

void do_trap(struct cpu_user_regs *cpu_regs)
{
    register_t pc = cpu_regs->sepc;
    uint32_t instr = read_instr(pc);

    if ( is_valid_bugaddr(instr) )
    {
        if ( !do_bug_frame(cpu_regs, pc) )
        {
            cpu_regs->sepc += GET_INSN_LENGTH(instr);
            return;
        }
    }

    do_unexpected_trap(cpu_regs);
}

enum mc_disposition arch_do_multicall_call(struct mc_state *state)
{
    assert_failed("need to be implented");
    return mc_continue;
}

void arch_hypercall_tasklet_result(struct vcpu *v, long res)
{
    assert_failed("need to be implented");
}

void vcpu_show_execution_state(struct vcpu *v)
{
    assert_failed("need to be implented");
}

unsigned long __trap_from_guest(void)
{
    return tp->stack_cpu_regs == &tp->guest_cpu_info->guest_cpu_user_regs;
}
