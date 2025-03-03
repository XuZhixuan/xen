/* SPDX-License-Identifier: MIT */

#ifndef _ASM_RISCV_SMP_H
#define _ASM_RISCV_SMP_H

#ifndef __ASSEMBLY__
#include <xen/cpumask.h>
#include <asm/current.h>
#endif

#define INVALID_HARTID UINT_MAX

DECLARE_PER_CPU(cpumask_var_t, cpu_sibling_mask);
DECLARE_PER_CPU(cpumask_var_t, cpu_core_mask);

/*
 * Do we, for platform reasons, need to actually keep CPUs online when we
 * would otherwise prefer them to be off?
 */
#define park_offline_cpus true

#define cpu_is_offline(cpu) unlikely(!cpu_online(cpu))

static inline unsigned int __raw_smp_processor_id(void)
{
    unsigned long id;

    id = get_processor_id();

    /*
     * Technically the hartid can be greater than what a uint can hold.
     * If such a system were to exist, we will need to change
     * the raw_smp_processor_id() API to be unsigned long instead of
     * unsigned int.
     */
    BUG_ON(id > UINT_MAX);

    return (unsigned int)id;
}

#define raw_smp_processor_id() (__raw_smp_processor_id())
#define smp_processor_id() (__raw_smp_processor_id())

extern void smp_clear_cpu_maps (void);
extern void smp_init_cpus(void);
extern unsigned int smp_get_max_cpus(void);
void smp_setup_processor_id(unsigned long boot_cpu_hartid);

/*
 * Mapping between linux logical cpu index and hartid.
 */
extern unsigned long __cpuid_to_hartid_map[NR_CPUS];
#define cpuid_to_hartid_map(cpu) __cpuid_to_hartid_map[cpu]

#define cpu_physical_id(cpu) cpuid_to_hartid_map(cpu)

#endif /* _ASM_RISCV_SMP_H */
