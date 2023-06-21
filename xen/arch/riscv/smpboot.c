/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Dummy smpboot support */

#include <xen/bug.h>
#include <xen/cpu.h>
#include <xen/cpumask.h>
#include <xen/init.h>
#include <xen/smp.h>
#include <xen/nodemask.h>

cpumask_t cpu_online_map;
cpumask_t cpu_present_map;
cpumask_t cpu_possible_map;

DEFINE_PER_CPU(unsigned int, cpu_id);
DEFINE_PER_CPU_READ_MOSTLY(cpumask_var_t, cpu_sibling_mask);
DEFINE_PER_CPU_READ_MOSTLY(cpumask_var_t, cpu_core_mask);

/* Fake one node for now. See also include/asm-arm/numa.h */
nodemask_t __read_mostly node_online_map = { { [0] = 1UL } };

unsigned long __cpuid_to_hartid_map[NR_CPUS] __ro_after_init = {
    [0 ... NR_CPUS-1] = INVALID_HARTID
};

int __cpu_up(unsigned int cpu)
{
    assert_failed("need to be implemented\n");
    return 0;
}

/* Shut down the current CPU */
void __cpu_disable(void)
{
    assert_failed("need to be implemented\n");
}

void __cpu_die(unsigned int cpu)
{
    assert_failed("need to be implemented\n");
}

int __init
smp_get_max_cpus(void)
{
    int i, max_cpus = 0;

    for ( i = 0; i < nr_cpu_ids; i++ )
        if ( cpu_possible(i) )
            max_cpus++;

    return max_cpus;
}

void __init
smp_clear_cpu_maps (void)
{
    cpumask_clear(&cpu_possible_map);
    cpumask_clear(&cpu_online_map);
    cpumask_set_cpu(0, &cpu_possible_map);
    cpumask_set_cpu(0, &cpu_online_map);
    cpumask_copy(&cpu_present_map, &cpu_possible_map);
}

void __init smp_setup_processor_id(unsigned long boot_cpu_hartid)
{
    cpuid_to_hartid_map(0) = boot_cpu_hartid;
}

