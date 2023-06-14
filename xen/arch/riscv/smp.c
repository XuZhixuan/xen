#include <xen/bug.h>
#include <xen/cpumask.h>
#include <xen/lib.h>

#include <asm/processor.h>

/* tp points to one of these per cpu */
struct pcpu_info pcpu_info[NR_CPUS];

void arch_flush_tlb_mask(const cpumask_t *mask)
{
    assert_failed("need to be implemented");
}

/*
 * The utilization of the printk() function within this function has
 * the potential to result in a deadlock.
 */
void smp_send_event_check_mask(const cpumask_t *mask)
{
}

void smp_send_call_function_mask(const cpumask_t *mask)
{
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
