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
#include <xen/softirq.h>

#include <asm/csr.h>
#include <asm/early_printk.h>
#include <asm/guest_access.h>
#include <asm/processor.h>
#include <asm/sbi.h>
#include <asm/setup.h>
#include <asm/traps.h>
#include <asm/vplic.h>
#include <asm/vtimer.h>

#define cast_to_bug_frame(addr) \
    (const struct bug_frame *)(addr)

#define print_csr(_csr) \
    do {    \
        printk("\t" #_csr ": 0x%02lx\n", csr_read(_csr)); \
    } while ( 0 )

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

// static void do_unexpected_trap(const struct cpu_user_regs *regs)
// {
//     unsigned long cause = csr_read(CSR_SCAUSE);

//     printk("Unhandled exception: %s\n", decode_cause(cause));

//     die();
// }

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

/*
 * Actions that needs to be done after entering the hypervisor from the
 * guest and before we handle any request.
 */
void enter_hypervisor_from_guest(void)
{
    context_save_csrs(current);
}

static void stay_in_hypervisor(void)
{
    local_irq_disable();

    /* Unset SPV in hstatus */
    csr_clear(CSR_HSTATUS, HSTATUS_SPV);
}

static void dump_csrs(unsigned long cause)
{
    unsigned long hstatus;
    bool gva;

    printk("\nUnhandled Exception! dumping CSRs...\n");

    printk("Supervisor CSRs\n");
    print_csr(CSR_STVEC);
    print_csr(CSR_SATP);
    print_csr(CSR_SEPC);

    hstatus = csr_read(CSR_HSTATUS);
    gva = !!(hstatus & HSTATUS_GVA);

    printk("\tCSR_STVAL: 0x%02lx%s\n",
            csr_read(CSR_STVAL),
            gva ? ", (guest virtual address)" : "");

    printk("\tCSR_SCAUSE: 0x%02lx\n", cause);
    printk("\t\tDescription: %s\n", decode_cause(cause));
    print_csr(CSR_SSTATUS);

    printk("\nVirtual Supervisor CSRs\n");
    print_csr(CSR_VSTVEC);
    print_csr(CSR_VSATP);
    print_csr(CSR_VSEPC);
    print_csr(CSR_VSTVAL);
    cause = csr_read(CSR_VSCAUSE);
    printk("\tCSR_VCAUSE: 0x%02lx\n", cause);
    printk("\t\tDescription: %s\n", decode_cause(cause));
    print_csr(CSR_VSSTATUS);

    printk("\nHypervisor CSRs\n");

    print_csr(CSR_HSTATUS);
    printk("\t\thstatus.VTSR=%d\n", !!(hstatus & HSTATUS_VTSR));
    printk("\t\thstatus.VTVM=%d\n", !!(hstatus & HSTATUS_VTVM));
    printk("\t\thstatus.HU=%d\n", !!(hstatus & HSTATUS_HU));
    printk("\t\thstatus.SPVP=%d\n", !!(hstatus & HSTATUS_SPVP));
    printk("\t\thstatus.SPV=%d\n", !!(hstatus & HSTATUS_SPV));
    printk("\t\thstatus.GVA=%d\n", !!(hstatus & HSTATUS_GVA));
    print_csr(CSR_HGATP);
    print_csr(CSR_HTVAL);
    print_csr(CSR_HTINST);
    print_csr(CSR_HEDELEG);
    print_csr(CSR_HIDELEG);

    panic(__func__);
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

static void check_for_pcpu_work(void)
{
    ASSERT(!local_irq_is_enabled());

    while ( softirq_pending(smp_processor_id()) )
    {
        local_irq_enable();
        do_softirq();
        local_irq_disable();
    }
}

/*
 * Actions that needs to be done before entering the guest. This is the
 * last thing executed before the guest context is fully restored.
 */
void leave_hypervisor_to_guest(void)
{
    local_irq_disable();

    check_for_pcpu_work();

    context_restore_csrs(current);
}

void timer_interrupt(unsigned long cause, struct cpu_user_regs *regs)
{
    /* Disable the timer to avoid more interrupts */
    csr_clear(CSR_SIE, 1ul << IRQ_S_TIMER);

    /* Signal the generic timer code to do its work */
    raise_softirq(TIMER_SOFTIRQ);
}

static void guest_sbi_set_timer(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    vtimer_set_timer(&v->arch.vtimer, regs->a0);
    regs->a0 = 0;
}

static void guest_sbi_putchar(struct cpu_user_regs *regs)
{
    sbi_console_putchar((int)regs->a0);
    regs->a0 = 0;
}

static void guest_sbi_getchar(struct cpu_user_regs *regs)
{
    regs->a0 = sbi_console_getchar();
}

static void guest_sbi_ext_base(struct cpu_user_regs *regs)
{
    unsigned long fid = regs->a6;

    switch (fid)
    {
    case SBI_EXT_BASE_GET_SPEC_VERSION:
        regs->a0 = 0;
        regs->a1 = sbi_spec_version;
        break;
    case SBI_EXT_BASE_GET_IMP_ID:
        regs->a0 = 0;
        regs->a1 = sbi_fw_id;
        break;
    case SBI_EXT_BASE_GET_IMP_VERSION:
        regs->a0 = 0;
        regs->a1 = sbi_fw_version;
        break;
    case SBI_EXT_BASE_PROBE_EXT:
        regs->a1 = sbi_probe_extension(regs->a0);
        regs->a0 = 0;
        break;

    default:
        printk("%s: Unsupport FID #%ld\n", __func__, fid);
        regs->a0 = SBI_ERR_NOT_SUPPORTED;
        break;
    }
}

// static inline void riscv_cpuid_to_hartid_mask(const struct cpumask *in,
// 					      struct cpumask *out)
// {
// 	cpumask_clear(out);
// 	cpumask_set_cpu(0, out);
// }

static void guest_sbi_rfence(struct cpu_user_regs *regs)
{
    unsigned long fid = regs->a6;

    switch (fid)
    {
    case SBI_EXT_RFENCE_REMOTE_FENCE_I:
        {
            sbi_remote_fence_i((const unsigned long *)&regs->a0);
            regs->a0 = SBI_SUCCESS;

            break;
        }
    case SBI_EXT_RFENCE_REMOTE_SFENCE_VMA:
        {
            sbi_remote_sfence_vma(&regs->a0, regs->a1, regs->a2);
            regs->a0 = SBI_SUCCESS;

            break;
        }

    default:
        printk("%s: Unsupport FID #%ld\n", __func__, fid);
        regs->a0 = SBI_ERR_NOT_SUPPORTED;
        break;
    }
}

static inline void advance_pc(struct cpu_user_regs *regs)
{
    regs->sepc += 4;
}

static void handle_guest_sbi(struct cpu_user_regs *regs)
{
    unsigned long eid = regs->a7;

    switch ( eid )
    {
    case SBI_EXT_TIME:
    case SBI_EXT_0_1_SET_TIMER:
        guest_sbi_set_timer(regs);
        break;
    case SBI_EXT_0_1_CONSOLE_PUTCHAR:
        guest_sbi_putchar(regs);
        break;
    case SBI_EXT_0_1_CONSOLE_GETCHAR:
        guest_sbi_getchar(regs);
        break;
    case SBI_EXT_0_1_CLEAR_IPI:
        printk("%s:%d: unimplemented: SBI_EXT_0_1_CLEAR_IPI\n",
               __FILE__, __LINE__);
        regs->a0 = SBI_ERR_NOT_SUPPORTED;
        break;
    case SBI_EXT_0_1_SEND_IPI:
        printk("%s:%d: unimplemented: SBI_EXT_0_1_SEND_IPI\n",
               __FILE__, __LINE__);
        regs->a0 = SBI_ERR_NOT_SUPPORTED;
        break;
    case SBI_EXT_0_1_SHUTDOWN:
        printk("%s:%d: unimplemented: SBI_EXT_0_1_SHUTDOWN\n",
               __FILE__, __LINE__);
        regs->a0 = SBI_ERR_NOT_SUPPORTED;
        break;
    case SBI_EXT_0_1_REMOTE_FENCE_I:
        printk("%s:%d: unimplemented: SBI_EXT_0_1_REMOTE_FENCE_I\n",
               __FILE__, __LINE__);
        regs->a0 = SBI_ERR_NOT_SUPPORTED;
        break;
    case SBI_EXT_0_1_REMOTE_SFENCE_VMA:
        printk("%s:%d: unimplemented: SBI_EXT_0_1_REMOTE_SFENCE_VMA\n",
               __FILE__, __LINE__);
        regs->a0 = SBI_ERR_NOT_SUPPORTED;
        break;
    case SBI_EXT_0_1_REMOTE_SFENCE_VMA_ASID:
        printk("%s:%d: unimplemented: SBI_EXT_0_1_REMOTE_SFENCE_VMA_ASID\n",
               __FILE__, __LINE__);
        regs->a0 = SBI_ERR_NOT_SUPPORTED;
        break;
    case SBI_EXT_BASE:
        guest_sbi_ext_base(regs);
        break;
    case SBI_EXT_RFENCE:
        guest_sbi_rfence(regs);
        break;
    default:
        printk("UNKNOWN Guest SBI extension id 0x%lx, FID #%lu\n", eid, regs->a1);
        regs->a0 = SBI_ERR_NOT_SUPPORTED;
        break;
    };

    advance_pc(regs);
}

static inline unsigned long get_faulting_gpa(void)
{
    return (csr_read(CSR_HTVAL) << 2) | (csr_read(CSR_STVAL) & 0x3);
}

static bool is_plic_access(unsigned long addr)
{
    return PLIC_BASE < addr && addr < PLIC_END;
}

static int emulate_load(struct vcpu *vcpu, unsigned long fault_addr,
                        unsigned long htinst)
{
    uint8_t data8;
    uint16_t data16;
    uint32_t data32;
    uint64_t data64;
    int rc;
	unsigned long insn;
	int shift = 0, len = 0, insn_len = 0;
	struct riscv_trap utrap = { 0 };

	/* Determine trapped instruction */
	if (htinst & 0x1) {
		/*
		 * Bit[0] == 1 implies trapped instruction value is
		 * transformed instruction or custom instruction.
		 */
		insn = htinst | INSN_16BIT_MASK;
		insn_len = (htinst & BIT(1, UL)) ? INSN_LEN(insn) : 2;
	} else {
		/*
		 * Bit[0] == 0 implies trapped instruction value is
		 * zero or special value.
		 */
		insn = riscv_vcpu_unpriv_read(vcpu, true, guest_regs(vcpu)->sepc,
                                      &utrap);
		if (utrap.scause) {
			/* Redirect trap if we failed to read instruction */
			utrap.sepc = guest_regs(vcpu)->sepc;
            printk("TODO: we failed to read the trapped insns, "
                   "so redirect trap to guest\n");
			return 1;
		}
		insn_len = INSN_LEN(insn);
	}

	/* Decode length of MMIO and shift */
	if ((insn & INSN_MASK_LW) == INSN_MATCH_LW) {
		len = 4;
		shift = 8 * (sizeof(unsigned long) - len);
	} else if ((insn & INSN_MASK_LB) == INSN_MATCH_LB) {
		len = 1;
		shift = 8 * (sizeof(unsigned long) - len);
	} else if ((insn & INSN_MASK_LBU) == INSN_MATCH_LBU) {
		len = 1;
		shift = 8 * (sizeof(unsigned long) - len);
#ifdef CONFIG_64BIT
	} else if ((insn & INSN_MASK_LD) == INSN_MATCH_LD) {
		len = 8;
		shift = 8 * (sizeof(unsigned long) - len);
	} else if ((insn & INSN_MASK_LWU) == INSN_MATCH_LWU) {
		len = 4;
#endif
	} else if ((insn & INSN_MASK_LH) == INSN_MATCH_LH) {
		len = 2;
		shift = 8 * (sizeof(unsigned long) - len);
	} else if ((insn & INSN_MASK_LHU) == INSN_MATCH_LHU) {
		len = 2;
#ifdef CONFIG_64BIT
	} else if ((insn & INSN_MASK_C_LD) == INSN_MATCH_C_LD) {
		len = 8;
		shift = 8 * (sizeof(unsigned long) - len);
		insn = RVC_RS2S(insn) << SH_RD;
	} else if ((insn & INSN_MASK_C_LDSP) == INSN_MATCH_C_LDSP &&
		   ((insn >> SH_RD) & 0x1f)) {
		len = 8;
		shift = 8 * (sizeof(unsigned long) - len);
#endif
	} else if ((insn & INSN_MASK_C_LW) == INSN_MATCH_C_LW) {
		len = 4;
		shift = 8 * (sizeof(unsigned long) - len);
		insn = RVC_RS2S(insn) << SH_RD;
	} else if ((insn & INSN_MASK_C_LWSP) == INSN_MATCH_C_LWSP &&
		   ((insn >> SH_RD) & 0x1f)) {
		len = 4;
		shift = 8 * (sizeof(unsigned long) - len);
	} else {
		return -EOPNOTSUPP;
	}

	/* Fault address should be aligned to length of MMIO */
	if (fault_addr & (len - 1))
		return -EIO;

    printk("emulating load: pc=0x%02lx, addr=0x%02lx, len=%d, shift=%d\n",
            guest_regs(vcpu)->sepc, fault_addr, len, shift);

    if ( is_plic_access(fault_addr) )
    {
        switch ( len )
        {
        case 1:
            rc = vplic_emulate_load(current, fault_addr, &data8, len);
            if ( rc < 0 )
                return rc;
            SET_RD(insn, guest_regs(vcpu), ((unsigned long)data8 << shift) >> shift);
            break;
        case 2:
            rc = vplic_emulate_load(current, fault_addr, &data16, len);
            if ( rc < 0 )
                return rc;
            SET_RD(insn, guest_regs(vcpu), ((unsigned long)data16 << shift) >> shift);
            break;
        case 4:
            rc = vplic_emulate_load(current, fault_addr, &data32, len);
            if ( rc < 0 )
                return rc;
            SET_RD(insn, guest_regs(vcpu), ((unsigned long)data32 << shift) >> shift);
            break;
        case 8:
            rc = vplic_emulate_load(current, fault_addr, &data64, len);
            if ( rc < 0 )
                return rc;
            SET_RD(insn, guest_regs(vcpu), ((unsigned long)data64 << shift) >> shift);
            break;
        default:
            BUG();
        }
    }

    advance_pc(guest_regs(vcpu));

    return 0;
}

static void handle_guest_page_fault(unsigned long cause, struct cpu_user_regs *regs)
{
    unsigned long addr;

    BUG_ON(cause != CAUSE_LOAD_GUEST_PAGE_FAULT && cause != CAUSE_STORE_GUEST_PAGE_FAULT);

    addr = get_faulting_gpa();

    printk("%s: TODO: handle faulted guest IO %s @ addr 0x%02lx\n",
            __func__,
            (cause == CAUSE_LOAD_GUEST_PAGE_FAULT) ? "load" : "store",
            addr);

    if ( cause == CAUSE_LOAD_GUEST_PAGE_FAULT )
    {
        emulate_load(current, get_faulting_gpa(), csr_read(CSR_HTINST));
    }
    else if ( cause == CAUSE_STORE_GUEST_PAGE_FAULT )
    {
        printk("TODO: emulate_store()\n");
        advance_pc(regs);
    }
}

void do_trap(struct cpu_user_regs *cpu_regs)
{
    register_t pc = cpu_regs->sepc;
    unsigned long cause = csr_read(CSR_SCAUSE);

    if ( trap_from_guest )
        enter_hypervisor_from_guest();
    else
    {
        uint32_t instr = read_instr(pc);

        if ( is_valid_bugaddr(instr) )
        {
            if ( !do_bug_frame(cpu_regs, pc) )
            {
                cpu_regs->sepc += GET_INSN_LENGTH(instr);
                return;
            }
        }
    }

    if ( cause & CAUSE_IRQ_FLAG )
    {
        /* Handle interrupt */
        unsigned long icause = cause & ~CAUSE_IRQ_FLAG;
        switch ( icause )
        {
        case IRQ_S_TIMER:
            timer_interrupt(cause, cpu_regs);
            break;
        default:
            dump_csrs(cause);
            break;
        }
    } else {
        switch ( cause )
        {
        case CAUSE_VIRTUAL_SUPERVISOR_ECALL:
            handle_guest_sbi(cpu_regs);
            break;
        case CAUSE_LOAD_GUEST_PAGE_FAULT:
        case CAUSE_STORE_GUEST_PAGE_FAULT:
            handle_guest_page_fault(cause, cpu_regs);
            break;
        default:
            dump_csrs(cause);
            break;
        }
    }

    if ( trap_from_guest )
        leave_hypervisor_to_guest();
    else
        stay_in_hypervisor();
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
