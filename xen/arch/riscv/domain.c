#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/softirq.h>
#include <asm/traps.h>
#include <public/domctl.h>
#include <public/xen.h>

DEFINE_PER_CPU(struct vcpu *, curr_vcpu);

void context_switch(struct vcpu *prev, struct vcpu *next)
{
    assert_failed(__func__);
}

void continue_running(struct vcpu *same)
{
    assert_failed(__func__);
}

void sync_local_execstate(void)
{
    assert_failed(__func__);
}

void sync_vcpu_execstate(struct vcpu *v)
{
    assert_failed(__func__);
}

unsigned long hypercall_create_continuation(
    unsigned int op, const char *format, ...)
{
    assert_failed(__func__);
    return 0;
}

struct domain *alloc_domain_struct(void)
{
    struct domain *d;
    BUILD_BUG_ON(sizeof(*d) > PAGE_SIZE);
    d = alloc_xenheap_pages(0, 0);
    if ( d == NULL )
        return NULL;

    clear_page(d);
    return d;
}

void free_domain_struct(struct domain *d)
{
    assert_failed(__func__);
}

void dump_pageframe_info(struct domain *d)
{
    assert_failed(__func__);
}

int arch_sanitise_domain_config(struct xen_domctl_createdomain *config)
{
    return 0;
}


int arch_domain_create(struct domain *d,
                       struct xen_domctl_createdomain *config,
                        unsigned int flags)
{
    assert_failed(__func__);
    return 0;
}

void arch_domain_destroy(struct domain *d)
{
    assert_failed(__func__);
}

void arch_domain_shutdown(struct domain *d)
{
    assert_failed(__func__);
}

void arch_domain_pause(struct domain *d)
{
    assert_failed(__func__);
}

void arch_domain_unpause(struct domain *d)
{
    assert_failed(__func__);
}

int arch_domain_soft_reset(struct domain *d)
{
    /* TODO */
    return -ENOSYS;
}

void arch_domain_creation_finished(struct domain *d)
{
    /* TODO */
}

int domain_relinquish_resources(struct domain *d)
{
    /* TODO */
    return -ENOSYS;
}

void arch_dump_domain_info(struct domain *d)
{
    assert_failed(__func__);
}

void arch_dump_vcpu_info(struct vcpu *v)
{
    assert_failed(__func__);
}

int arch_set_info_guest(
    struct vcpu *v, vcpu_guest_context_u c)
{
    assert_failed(__func__);
    return -ENOSYS;
}

/* taken from arm/domain.c */
struct vcpu *alloc_vcpu_struct(const struct domain *d)
{
    assert_failed(__func__);
    return 0;
}

void free_vcpu_struct(struct vcpu *v)
{
    /* TODO */
}

int arch_initialise_vcpu(struct vcpu *v, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    /* TODO */
    return -ENOSYS;
}

int arch_vcpu_reset(struct vcpu *v)
{
    /* TODO */
    return -ENOSYS;
}

int arch_vcpu_create(struct vcpu *v)
{
    assert_failed(__func__);

    return 0;
}

void arch_vcpu_destroy(struct vcpu *v)
{
    /* TODO */
}

