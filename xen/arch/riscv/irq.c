/* SPDX-License-Identifier: GPL-2.0-or-later */
/* RISC-V Interrupt support */

#include <xen/bug.h>
#include <xen/sched.h>

const unsigned int nr_irqs = NR_IRQS;

hw_irq_controller no_irq_type = {
};

int arch_init_one_irq_desc(struct irq_desc *desc)
{
    assert_failed("need to be implemented");
    return 0;
}

struct pirq *alloc_pirq_struct(struct domain *d)
{
    assert_failed("need to be implemented");
    return NULL;
}

int pirq_guest_bind(struct vcpu *v, struct pirq *pirq, int will_share)
{
    assert_failed("need to be implemented");
}

void pirq_guest_unbind(struct domain *d, struct pirq *pirq)
{
    assert_failed("need to be implemented");
}

void pirq_set_affinity(struct domain *d, int pirq, const cpumask_t *mask)
{
    assert_failed("need to be implemented");
}

void smp_send_state_dump(unsigned int cpu)
{
    assert_failed("need to be implemented");
}

void arch_move_irqs(struct vcpu *v)
{
    /*
     * TODO: there is no interrupt support in RISC-V for time being so
     *       we can only print a message instead of assert
     */
    printk("%s: need to be implemented", __func__);
}

int setup_irq(unsigned int irq, unsigned int irqflags, struct irqaction *new)
{
    assert_failed(__func__);

    return -ENOSYS;
}

int platform_get_irq(const struct dt_device_node *device, int index)
{
    struct dt_irq dt_irq;
    unsigned int irq;

    if ( dt_device_get_irq(device, index, &dt_irq) )
        return -1;

    irq = dt_irq.irq;

    return irq;
}

int platform_get_irq_byname(const struct dt_device_node *np, const char *name)
{
    int index;

    if ( unlikely(!name) )
        return -EINVAL;

    index = dt_property_match_string(np, "interrupt-names", name);
    if ( index < 0 )
        return index;

    return platform_get_irq(np, index);
}
