#ifndef _ASM_HW_IRQ_H
#define _ASM_HW_IRQ_H

#include <xen/device_tree.h>

#define NR_IRQS		1024

/*
 * These defines correspond to the Xen internal representation of the
 * IRQ types. We choose to make them the same as the existing device
 * tree definitions for convenience.
 */
#define IRQ_TYPE_NONE           DT_IRQ_TYPE_NONE
#define IRQ_TYPE_EDGE_RISING    DT_IRQ_TYPE_EDGE_RISING
#define IRQ_TYPE_EDGE_FALLING   DT_IRQ_TYPE_EDGE_FALLING
#define IRQ_TYPE_EDGE_BOTH      DT_IRQ_TYPE_EDGE_BOTH 
#define IRQ_TYPE_LEVEL_HIGH     DT_IRQ_TYPE_LEVEL_HIGH
#define IRQ_TYPE_LEVEL_LOW      DT_IRQ_TYPE_LEVEL_LOW
#define IRQ_TYPE_LEVEL_MASK     DT_IRQ_TYPE_LEVEL_MASK
#define IRQ_TYPE_SENSE_MASK     DT_IRQ_TYPE_SENSE_MASK
#define IRQ_TYPE_INVALID        DT_IRQ_TYPE_INVALID

struct arch_pirq
{
};

struct arch_irq_desc {
};

void arch_move_irqs(struct vcpu *v);

#define domain_pirq_to_irq(d, pirq) (pirq)

extern const unsigned int nr_irqs;
#define nr_static_irqs NR_IRQS
#define arch_hwdom_irqs(domid) NR_IRQS

#define arch_evtchn_bind_pirq(d, pirq) ((void)((d) + (pirq)))

int platform_get_irq(const struct dt_device_node *device, int index);
int platform_get_irq_byname(const struct dt_device_node *np, const char *name);

#endif /* _ASM_HW_IRQ_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
