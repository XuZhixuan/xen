/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/asm-RISCV/monitor.h
 *
 * Arch-specific monitor_op domctl handler.
 *
 * Copyright (c) 2015 Tamas K Lengyel (tamas@tklengyel.com)
 * Copyright (c) 2016, Bitdefender S.R.L.
 *
 */

#ifndef __ASM_RISCV_MONITOR_H__
#define __ASM_RISCV_MONITOR_H__

#include <xen/sched.h>
#include <public/domctl.h>

static inline
void arch_monitor_allow_userspace(struct domain *d, bool allow_userspace)
{
}

static inline
int arch_monitor_domctl_op(struct domain *d, struct xen_domctl_monitor_op *mop)
{
    /* No arch-specific monitor ops on RISCV. */
    return -EOPNOTSUPP;
}

int arch_monitor_domctl_event(struct domain *d,
                              struct xen_domctl_monitor_op *mop);

static inline
int arch_monitor_init_domain(struct domain *d)
{
    /* No arch-specific domain initialization on RISCV. */
    return 0;
}

static inline
void arch_monitor_cleanup_domain(struct domain *d)
{
    /* No arch-specific domain cleanup on RISCV. */
}

static inline uint32_t arch_monitor_get_capabilities(struct domain *d)
{
    uint32_t capabilities = 0;

    return capabilities;
}

#endif /* __ASM_RISCV_MONITOR_H__ */
