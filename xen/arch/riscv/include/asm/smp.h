/* SPDX-License-Identifier: MIT */

#ifndef _ASM_RISCV_SMP_H
#define _ASM_RISCV_SMP_H

#ifndef __ASSEMBLY__
#include <xen/cpumask.h>
#include <asm/current.h>
#endif

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

#endif /* _ASM_RISCV_SMP_H */
