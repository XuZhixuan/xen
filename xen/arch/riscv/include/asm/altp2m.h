/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Alternate p2m
 *
 * Copyright (c) 2014, Intel Corporation.
 */

#ifndef __ASM_RISCV_ALTP2M_H
#define __ASM_RISCV_ALTP2M_H

#include <xen/sched.h>

/* Alternate p2m on/off per domain */
static inline bool altp2m_active(const struct domain *d)
{
    /* Not implemented on RISCV. */
    return false;
}

/* Alternate p2m VCPU */
static inline uint16_t altp2m_vcpu_idx(const struct vcpu *v)
{
    /* Not implemented on RISCV, should not be reached. */
    BUG();
    return 0;
}

#endif /* __ASM_RISCV_ALTP2M_H */
