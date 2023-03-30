/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <xen/bug.h>
#include <xen/sched.h>

unsigned long __read_mostly cpu_khz;  /* CPU clock frequency in kHz. */

uint64_t __read_mostly boot_count;

s_time_t get_s_time(void)
{
    uint64_t ticks = get_cycles() - boot_count;
    return ticks_to_ns(ticks);
}

/* VCPU PV timers. */
void send_timer_event(struct vcpu *v)
{
    assert_failed("need to be implemented");
}

void force_update_vcpu_system_time(struct vcpu *v)
{
    assert_failed("need to be implemented");
}

void domain_set_time_offset(struct domain *d, int64_t time_offset_seconds)
{
    assert_failed("need to be implemented");
}

int reprogram_timer(s_time_t timeout)
{
    assert_failed("need to be implemented");

    return 0;
}

