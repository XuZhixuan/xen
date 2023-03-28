/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2012 Regents of the University of California */

#ifndef _ASM_RISCV_TIMEX_H
#define _ASM_RISCV_TIMEX_H

#include <asm/processor.h>
#include <xen/lib.h>

typedef unsigned long cycles_t;

static inline s_time_t ticks_to_ns(uint64_t ticks)
{
    return muldiv64(ticks, SECONDS(1), 1000 * cpu_khz);
}

static inline cycles_t get_cycles_inline(void)
{
	cycles_t n;

	__asm__ __volatile__ (
		"rdtime %0"
		: "=r" (n));
	return n;
}
#define get_cycles get_cycles_inline

extern void force_update_vcpu_system_time(struct vcpu *v);

#endif /* _ASM_RISCV_TIMEX_H */
