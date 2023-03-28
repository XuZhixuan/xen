#ifndef _ASM_HW_IRQ_H
#define _ASM_HW_IRQ_H

#define NR_IRQS		1024

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

#endif /* _ASM_HW_IRQ_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
