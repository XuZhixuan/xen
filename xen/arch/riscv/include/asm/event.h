#ifndef __ASM_EVENT_H__
#define __ASM_EVENT_H__

void vcpu_mark_events_pending(struct vcpu *v);

static inline int vcpu_event_delivery_is_enabled(struct vcpu *v)
{
    return 0;
}

static inline int local_events_need_delivery(void)
{
    return 0;
}

static inline void local_event_delivery_enable(void)
{
}

/* No arch specific virq definition now. Default to global. */
static inline bool arch_virq_is_global(unsigned int virq)
{
    return true;
}

#endif
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
