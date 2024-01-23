/* SPDX-License-Identifier: MIT */
/*
 * xen/arch/riscv/vsbi.c
 *
 * Handle sbi calls from guest
 *
 * Copyright (c) 2024 Microchip.
 *
 */
#include <xen/sched.h>

#include <asm/event.h>
#include <asm/processor.h>
#include <asm/sbi.h>
#include <asm/vsbi.h>
#include <asm/vtimer.h>

static int vsbi_timer_set(struct vcpu *v, struct cpu_user_regs *regs)
{
    vtimer_set_timer(&v->arch.vtimer, regs->a0);
    return SBI_SUCCESS;
}

static int vsbi_ext_base(struct cpu_user_regs *regs)
{
    unsigned long fid = regs->a6;
    int ret = SBI_SUCCESS;

    switch (fid)
    {
    case SBI_EXT_BASE_GET_SPEC_VERSION:
        regs->a1 = sbi_spec_version;
        break;
    case SBI_EXT_BASE_GET_IMP_ID:
        regs->a1 = sbi_fw_id;
        break;
    case SBI_EXT_BASE_GET_IMP_VERSION:
        regs->a1 = sbi_fw_version;
        break;
    case SBI_EXT_BASE_PROBE_EXT:
        regs->a1 = sbi_probe_extension(regs->a0);
        break;
    case SBI_EXT_BASE_GET_MVENDORID:
        regs->a1 = 0;
        break;
    case SBI_EXT_BASE_GET_MARCHID:
        regs->a1 = 0;
        break;
    case SBI_EXT_BASE_GET_MIMPID:
        regs->a1 = 7;
       break;

    default:
        printk("%s: Unsupport FID #%ld\n", __func__, fid);
        return SBI_ERR_NOT_SUPPORTED;
    }
    return ret;
}

static int vsbi_rfence(struct cpu_user_regs *regs)
{
    unsigned long fid = regs->a6;

    switch (fid)
    {
    case SBI_EXT_RFENCE_REMOTE_FENCE_I:
        sbi_remote_fence_i((const unsigned long *)&regs->a0);
        return SBI_SUCCESS;
    case SBI_EXT_RFENCE_REMOTE_SFENCE_VMA:
        sbi_remote_sfence_vma(&regs->a0, regs->a1, regs->a2);
        return SBI_SUCCESS;

    default:
        printk("%s: Unsupport FID #%ld\n", __func__, fid);
        return SBI_ERR_NOT_SUPPORTED;
    }
}

void vsbi_handle_ecall(struct vcpu *vcpu, struct cpu_user_regs *regs)
{
    unsigned long eid = regs->a7;

    switch ( eid )
    {
    case SBI_EXT_TIME:
    case SBI_EXT_0_1_SET_TIMER:
        regs->a0 = vsbi_timer_set(vcpu, regs);
        break;
    case SBI_EXT_0_1_CONSOLE_PUTCHAR:
        vsbi_uart_putchar(regs);
        break;
    case SBI_EXT_0_1_CONSOLE_GETCHAR:
        vsbi_uart_getchar(regs);
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
        regs->a0 = vsbi_ext_base(regs);
        break;
    case SBI_EXT_RFENCE:
        regs->a0 = vsbi_rfence(regs);
        break;
    default:
        printk("UNKNOWN Guest SBI extension id 0x%lx, FID #%lu\n", eid, regs->a1);
        regs->a0 = SBI_ERR_NOT_SUPPORTED;
        break;
    };

    /* advance sepc */
    regs->sepc += 4;
}
