/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2012 Regents of the University of California */

#ifndef _ASM_RISCV_TIMEX_H
#define _ASM_RISCV_TIMEX_H

#include <asm/processor.h>
#include <xen/lib.h>

#define DT_MATCH_TIMER                      \
    DT_MATCH_COMPATIBLE("sifive,clint0"), \
    DT_MATCH_COMPATIBLE("riscv,clint0")

typedef unsigned long cycles_t;

static inline s_time_t ticks_to_ns(uint64_t ticks)
{
    return muldiv64(ticks, SECONDS(1), 1000 * cpu_khz);
}

static inline uint64_t ns_to_ticks(s_time_t ns)
{
    return muldiv64(ns, 1000 * cpu_khz, SECONDS(1));
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

void preinit_xen_time(void);

/* Set up the timer interrupt on this CPU */
void init_timer_interrupt(void);

extern uint64_t boot_count;

#endif /* _ASM_RISCV_TIMEX_H */
