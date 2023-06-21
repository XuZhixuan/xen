/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Dummy smpboot support */

#include <xen/bug.h>
#include <xen/cpu.h>
#include <xen/cpumask.h>
#include <xen/device_tree.h>
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

unsigned int __init
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

/**
 * of_get_cpu_hwid - Get the hardware ID from a CPU device node
 *
 * @cpun: CPU number(logical index) for which device node is required
 * @thread: The local thread number to get the hardware ID for.
 *
 * Return: The hardware ID for the CPU node or ~0ULL if not found.
 */
u64 of_get_cpu_hwid(struct dt_device_node *cpun, unsigned int thread)
{
    const __be32 *cell;
    int ac;
    u32 len;

    ac = dt_n_addr_cells(cpun);
    cell = dt_get_property(cpun, "reg", &len);
    if (!cell || !ac || ((sizeof(*cell) * ac * (thread + 1)) > len))
        return ~0ULL;

    cell += ac * thread;
    return dt_read_number(cell, ac);
}

/*
 * Returns the hart ID of the given device tree node, or -ENODEV if the node
 * isn't an enabled and valid RISC-V hart node.
 */
int riscv_of_processor_hartid(struct dt_device_node *node, unsigned long *hart)
{
    const char *isa;

    if ( !dt_device_is_compatible(node, "riscv") )
    {
        printk("Found incompatible CPU\n");
        return -ENODEV;
    }

    *hart = (unsigned long) of_get_cpu_hwid(node, 0);
    if ( *hart == ~0UL )
    {
        printk("Found CPU without hart ID\n");
        return -ENODEV;
    }

    if ( !dt_device_is_available(node))
    {
        printk("CPU with hartid=%lu is not available\n", *hart);
        return -ENODEV;
    }

    if ( dt_property_read_string(node, "riscv,isa", &isa) )
    {
        printk("CPU with hartid=%lu has no \"riscv,isa\" property\n", *hart);
        return -ENODEV;
    }

    if ( isa[0] != 'r' || isa[1] != 'v' )
    {
        printk("CPU with hartid=%lu has an invalid ISA of \"%s\"\n", *hart, isa);
        return -ENODEV;
    }

    return 0;
}

void __init smp_init_cpus(void)
{
    struct dt_device_node *cpus = dt_find_node_by_path("/cpus");
    struct dt_device_node *cpu;
    unsigned long hart;
    bool found_boot_cpu = false;
    int cpuid = 1;
    int rc;

    dt_for_each_child_node( cpus, cpu )
    {
        if ( !dt_device_type_is_equal(cpu, "cpu") )
            continue;

        rc = riscv_of_processor_hartid(cpu, &hart);
        if ( rc < 0 )
            continue;

        if ( hart == cpuid_to_hartid_map(0) )
        {
            BUG_ON(found_boot_cpu);
            found_boot_cpu = 1;
            continue;
        }

        if ( cpuid >= NR_CPUS )
        {
            printk("Invalid cpuid [%d] for hartid [%lu]\n",
                cpuid, hart);
            continue;
        }

        cpuid_to_hartid_map(cpuid) = hart;
        cpuid++;
    }

    BUG_ON(!found_boot_cpu);

    if ( cpuid > NR_CPUS )
        printk("Total number of cpus [%d] is greater than nr_cpus option value [%d]\n",
            cpuid, NR_CPUS);

    for ( cpuid = 1; cpuid < NR_CPUS; cpuid++ )
    {
        if ( cpuid_to_hartid_map(cpuid) != INVALID_HARTID )
            cpumask_set_cpu(cpuid, &cpu_possible_map);
    }
}

static int setup_cpu_sibling_map(int cpu)
{
    if ( !zalloc_cpumask_var(&per_cpu(cpu_sibling_mask, cpu)) ||
         !zalloc_cpumask_var(&per_cpu(cpu_core_mask, cpu)) )
        return -ENOMEM;

    /* A CPU is a sibling with itself and is always on its own core. */
    cpumask_set_cpu(cpu, per_cpu(cpu_sibling_mask, cpu));
    cpumask_set_cpu(cpu, per_cpu(cpu_core_mask, cpu));

    return 0;
}

void __init smp_prepare_cpus(void)
{
    int rc;

    cpumask_copy(&cpu_present_map, &cpu_possible_map);

    rc = setup_cpu_sibling_map(0);
    if ( rc )
        panic("Unable to allocate CPU sibling/core maps\n");
}

void __init smp_setup_processor_id(unsigned long boot_cpu_hartid)
{
    cpuid_to_hartid_map(0) = boot_cpu_hartid;
}

