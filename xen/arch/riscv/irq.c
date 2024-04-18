/* SPDX-License-Identifier: GPL-2.0-or-later */
/* RISC-V Interrupt support */

#include <xen/bug.h>
#include <xen/sched.h>
#include <xen/cpu.h>

#include <asm/gic.h>

const unsigned int nr_irqs = NR_IRQS;

/* Describe an IRQ assigned to a guest */
struct irq_guest
{
    struct domain *d;
    unsigned int virq;
};

hw_irq_controller no_irq_type = {
};

static irq_desc_t irq_desc[NR_IRQS];

static int __setup_irq(struct irq_desc *desc, unsigned int irqflags,
                       struct irqaction *new)
{
    bool shared = irqflags & IRQF_SHARED;

    ASSERT(new != NULL);

    /* Sanity checks:
     *  - if the IRQ is marked as shared
     *  - dev_id is not NULL when IRQF_SHARED is set
     */
    if ( desc->action != NULL && (!test_bit(_IRQF_SHARED, &desc->status) || !shared) )
        return -EINVAL;
    if ( shared && new->dev_id == NULL )
        return -EINVAL;

    if ( shared )
        set_bit(_IRQF_SHARED, &desc->status);

    new->next = desc->action;
    desc->action = new;

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

int arch_init_one_irq_desc(struct irq_desc *desc)
{
    desc->arch.type = IRQ_TYPE_INVALID;
    return 0;
}

static int __init init_irq_data(void)
{
    int irq;

    for ( irq = 0; irq < NR_IRQS; irq++ )
    {
        struct irq_desc *desc = irq_to_desc(irq);
        int rc = init_one_irq_desc(desc);

        if ( rc )
            return rc;

        desc->irq = irq;
        desc->action  = NULL;
    }

    return 0;
}

void __init init_IRQ(void)
{
    BUG_ON(init_irq_data() < 0);
}

/* Dispatch an interrupt */
void do_IRQ(struct cpu_user_regs *regs, uint32_t irq)
{
    struct irq_desc *desc = irq_to_desc(irq);
    struct irqaction *action;

    irq_enter();

    spin_lock(&desc->lock);
    desc->handler->ack(desc);

    if ( test_bit(_IRQ_DISABLED, &desc->status) )
        goto out;

    set_bit(_IRQ_INPROGRESS, &desc->status);

    action = desc->action;

    spin_unlock_irq(&desc->lock);

    do
    {
        action->handler(irq, action->dev_id, regs);
        action = action->next;
    } while ( action );

    spin_lock_irq(&desc->lock);

    clear_bit(_IRQ_INPROGRESS, &desc->status);

out:
    desc->handler->end(desc);
    spin_unlock(&desc->lock);
    irq_exit();
}

void irq_set_affinity(struct irq_desc *desc, const cpumask_t *cpu_mask)
{
    if ( desc != NULL )
        desc->handler->set_affinity(desc, cpu_mask);
}

int setup_irq(unsigned int irq, unsigned int irqflags, struct irqaction *new)
{
      int rc;
    unsigned long flags;
    struct irq_desc *desc;
    bool disabled;

    desc = irq_to_desc(irq);

    spin_lock_irqsave(&desc->lock, flags);

    disabled = (desc->action == NULL);

    rc = __setup_irq(desc, irqflags, new);
    if ( rc )
        goto err;

    /* First time the IRQ is setup */
    if ( disabled )
    {
        /* disable irq by default */
        set_bit(_IRQ_DISABLED, &desc->status);

        /* route interrupt to xen */
        gic_route_irq_to_xen(desc, IRQ_NO_PRIORITY);

        /* TODO: Handle case where IRQ is setup on different CPU than
         * the targeted CPU and the priority.
         */
        irq_set_affinity(desc, cpumask_of(smp_processor_id()));
        desc->handler->startup(desc);
        /* enable irq */
        clear_bit(_IRQ_DISABLED, &desc->status);
    }

err:
    spin_unlock_irqrestore(&desc->lock, flags);

    return rc;
}

int request_irq(unsigned int irq, unsigned int irqflags,
                void (*handler)(int, void *, struct cpu_user_regs *),
                const char *devname, void *dev_id)
{
    struct irqaction *action;
    int retval;

    /*
     * Sanity-check: shared interrupts must pass in a real dev-ID,
     * otherwise we'll have trouble later trying to figure out
     * which interrupt is which (messes up the interrupt freeing
     * logic etc).
     */
    if ( irq >= nr_irqs )
        return -EINVAL;
    if ( !handler )
        return -EINVAL;

    action = xmalloc(struct irqaction);
    if ( !action )
        return -ENOMEM;

    action->handler = handler;
    action->name = devname;
    action->dev_id = dev_id;
    action->free_on_release = 1;
    action->next = NULL;

    retval = setup_irq(irq, irqflags, action);
    if ( retval )
        xfree(action);

    return retval;
}

void release_irq(unsigned int irq, const void *dev_id)
{
    struct irq_desc *desc;
    unsigned long flags;
    struct irqaction *action, **action_ptr;

    desc = irq_to_desc(irq);

    spin_lock_irqsave(&desc->lock,flags);

    action_ptr = &desc->action;
    for ( ;; )
    {
        action = *action_ptr;
        if ( !action )
        {
            printk(XENLOG_WARNING "Trying to free already-free IRQ %u\n", irq);
            spin_unlock_irqrestore(&desc->lock, flags);
            return;
        }

        if ( action->dev_id == dev_id )
            break;

        action_ptr = &action->next;
    }

    /* Found it - remove it from the action list */
    *action_ptr = action->next;

    /* If this was the last action, shut down the IRQ */
    if ( !desc->action )
    {
        desc->handler->shutdown(desc);
        clear_bit(_IRQ_GUEST, &desc->status);
    }

    spin_unlock_irqrestore(&desc->lock,flags);

    /* Wait to make sure it's not being used on another CPU */
    do { smp_mb(); } while ( test_bit(_IRQ_INPROGRESS, &desc->status) );

    if ( action->free_on_release )
        xfree(action);
}

static bool irq_validate_new_type(unsigned int curr, unsigned int new)
{
    return (curr == IRQ_TYPE_INVALID || curr == new );
}

static int irq_set_type(unsigned int irq, unsigned int type)
{
    unsigned long flags;
    int ret = -EINVAL;
    struct irq_desc *desc = irq_to_desc(irq);

    spin_lock_irqsave(&desc->lock, flags);
    if ( !irq_validate_new_type(desc->arch.type, type) )
        goto err;
    desc->arch.type = type;
    ret = 0;

err:
    spin_unlock_irqrestore(&desc->lock, flags);
    return ret;
}

int platform_get_nr_irqs(const struct dt_device_node *device)
{
    struct dt_raw_irq raw;
    int count = 0;
    unsigned int index = 0;

    while( dt_device_get_raw_irq(device, index++, &raw) == 0 ) {
        count++;
    }
    return count;
}

int platform_get_irq(const struct dt_device_node *device, int index)
{
    struct dt_irq dt_irq;
    
    if ( dt_device_get_irq(device, index, &dt_irq) )
        return -1;

    if ( irq_set_type(dt_irq.irq, dt_irq.type) )
        return -1;

    return dt_irq.irq;
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

static inline struct irq_guest *irq_get_guest_info(struct irq_desc *desc)
{
    ASSERT(spin_is_locked(&desc->lock));
    ASSERT(test_bit(_IRQ_GUEST, &desc->status));
    ASSERT(desc->action != NULL);

    return desc->action->dev_id;
}

static inline struct domain *irq_get_domain(struct irq_desc *desc)
{
    return irq_get_guest_info(desc)->d;
}

/*
 * Route an IRQ to a specific guest.
 * For now only SPIs are assignable to the guest.
 */
int route_irq_to_guest(struct domain *d, unsigned int virq,
                       unsigned int irq, const char * devname)
{
    struct irqaction *action;
    struct irq_guest *info;
    struct irq_desc *desc;
    unsigned long flags;
    int retval = 0;

    desc = irq_to_desc(irq);

    action = xmalloc(struct irqaction);
    if ( !action )
        return -ENOMEM;

    info = xmalloc(struct irq_guest);
    if ( !info )
    {
        xfree(action);
        return -ENOMEM;
    }

    info->d = d;
    info->virq = virq;

    action->dev_id = info;
    action->name = devname;
    action->free_on_release = 1;

    spin_lock_irqsave(&desc->lock, flags);

    if ( !is_hardware_domain(d) && desc->arch.type == IRQ_TYPE_INVALID )
    {
        printk(XENLOG_G_ERR "IRQ %u has not been configured\n", irq);
        retval = -EIO;
        goto out;
    }

    /*
     * If the IRQ is already used by someone
     *  - If it's the same domain -> Xen doesn't need to update the IRQ desc.
     *  For safety check if we are not trying to assign the IRQ to a
     *  different vIRQ.
     *  - Otherwise -> For now, don't allow the IRQ to be shared between
     *  Xen and domains.
     */
    if ( desc->action != NULL )
    {
        if ( test_bit(_IRQ_GUEST, &desc->status) )
        {
            struct domain *ad = irq_get_domain(desc);

            if ( d != ad )
            {
                printk(XENLOG_G_ERR "IRQ %u is already used by domain %u\n",
                       irq, ad->domain_id);
                retval = -EBUSY;
            }
            else if ( irq_get_guest_info(desc)->virq != virq )
            {
                printk(XENLOG_G_ERR
                       "d%u: IRQ %u is already assigned to vIRQ %u\n",
                       d->domain_id, irq, irq_get_guest_info(desc)->virq);
                retval = -EBUSY;
            }
        }
        else
        {
            printk(XENLOG_G_ERR "IRQ %u is already used by Xen\n", irq);
            retval = -EBUSY;
        }
        goto out;
    }

    retval = __setup_irq(desc, 0, action);
    if ( retval )
        goto out;

    retval = gic_route_irq_to_guest(d, virq, desc);

    spin_unlock_irqrestore(&desc->lock, flags);

    if ( retval )
    {
        release_irq(desc->irq, info);
        goto free_info;
    }

    return 0;

out:
    spin_unlock_irqrestore(&desc->lock, flags);
    xfree(action);
free_info:
    xfree(info);

    return retval;
}
