/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <xen/bug.h>
#include <xen/device_tree.h>
#include <xen/sched.h>

unsigned long __read_mostly cpu_khz;  /* CPU clock frequency in kHz. */

uint32_t __read_mostly timer_dt_clock_frequency;

uint64_t __read_mostly boot_count;

static __initdata struct dt_device_node *timer;

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

/* Set up the timer on the boot CPU (early init function) */
static void __init preinit_dt_xen_time(void)
{
    static const struct dt_device_match timer_ids[] __initconst =
    {
        DT_MATCH_PATH("/cpus"),
        { /* sentinel */ },
    };
    int res;
    u32 rate;

    timer = dt_find_matching_node(NULL, timer_ids);
    if ( !timer )
        panic("Unable to find a compatible timer in the device tree\n");

    dt_device_set_used_by(timer, DOMID_XEN);

    res = dt_property_read_u32(timer, "timebase-frequency", &rate);
    if ( !res )
        panic("Unable to find clock frequency.\n");

    cpu_khz = rate / 1000;
    timer_dt_clock_frequency = rate;
}

void __init preinit_xen_time(void)
{
    preinit_dt_xen_time();

    boot_count = get_cycles();
}

/* Set up the timer on the boot CPU (late init function) */
int __init init_xen_time(void)
{
    printk("%s: need to be implemented\n", __func__);

    return 0;
}

