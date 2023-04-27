#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/softirq.h>
#include <asm/current.h>
#include <asm/p2m.h>
#include <asm/riscv_encoding.h>
#include <asm/traps.h>
#include <asm/vplic.h>
#include <asm/vtimer.h>
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
    int rc = 0;

    if ( is_idle_domain(d) )
        return 0;

    if ( (rc = p2m_init(d)) != 0)
        goto fail;

    if ( (rc = domain_vtimer_init(d, &config->arch)) != 0 )
        goto fail;

    return rc;

fail:
    d->is_dying = DOMDYING_dead;
    arch_domain_destroy(d);
    return rc;
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

#define MAX_PAGES_PER_VCPU  1

struct vcpu *alloc_vcpu_struct(const struct domain *d)
{
    struct vcpu *v;

    BUILD_BUG_ON(sizeof(*v) > MAX_PAGES_PER_VCPU * PAGE_SIZE);
    v = alloc_xenheap_pages(get_order_from_bytes(sizeof(*v)), 0);
    if ( v != NULL )
    {
        unsigned int i;

        for ( i = 0; i < DIV_ROUND_UP(sizeof(*v), PAGE_SIZE); i++ )
            clear_page((void *)v + i * PAGE_SIZE);
    }

    return v;
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

extern void noreturn return_to_new_vcpu64(void);

static void continue_new_vcpu(void)
{
    reset_stack_and_jump(return_to_new_vcpu64);
}

static void vcpu_csr_init(struct vcpu *v)
{
    unsigned long hedeleg, hideleg, hstatus;

    hedeleg = 0;
    hedeleg |= (1U << CAUSE_MISALIGNED_FETCH);
    hedeleg |= (1U << CAUSE_FETCH_ACCESS);
    hedeleg |= (1U << CAUSE_ILLEGAL_INSTRUCTION);
    hedeleg |= (1U << CAUSE_MISALIGNED_LOAD);
    hedeleg |= (1U << CAUSE_LOAD_ACCESS);
    hedeleg |= (1U << CAUSE_MISALIGNED_STORE);
    hedeleg |= (1U << CAUSE_STORE_ACCESS);
    hedeleg |= (1U << CAUSE_BREAKPOINT);
    hedeleg |= (1U << CAUSE_USER_ECALL);
    hedeleg |= (1U << CAUSE_FETCH_PAGE_FAULT);
    hedeleg |= (1U << CAUSE_LOAD_PAGE_FAULT);
    hedeleg |= (1U << CAUSE_STORE_PAGE_FAULT);
    v->arch.hedeleg = hedeleg;

    hstatus = HSTATUS_SPV | HSTATUS_SPVP;
    v->arch.hstatus = hstatus;

    hideleg = MIP_VSTIP;
    v->arch.hideleg = hideleg;

    /* Enable all timers for guest */
    v->arch.hcounteren = -1UL;

    v->arch.henvcfg |= ENVCFG_STCE;

    /* Enable floating point and other extensions for guest. */
    /* TODO Disable them in Xen. */
    csr_clear(CSR_SSTATUS, SSTATUS_FS | SSTATUS_XS);
    csr_set(CSR_SSTATUS, SSTATUS_FS_INITIAL | SSTATUS_XS_INITIAL);
}

int arch_vcpu_create(struct vcpu *v)
{
    int rc = 0;

    BUILD_BUG_ON( sizeof(struct cpu_info) > STACK_SIZE );

    v->arch.stack = alloc_xenheap_pages(3, MEMF_node(vcpu_to_node(v)));
    if ( v->arch.stack == NULL )
        return -ENOMEM;

    v->arch.cpu_info = (struct cpu_info *)(v->arch.stack
                                           + STACK_SIZE
                                           - sizeof(struct cpu_info));

    /* Back reference to vcpu is used to access its processor field */
    memset(v->arch.cpu_info, 0, sizeof(*v->arch.cpu_info));

    v->arch.saved_context.sp = (register_t)v->arch.cpu_info;
    v->arch.saved_context.ra = (register_t)continue_new_vcpu;

    printk(XENLOG_INFO "Create vCPU with sp=0x%02lx, pc=0x%02lx\n",
            v->arch.saved_context.sp, v->arch.saved_context.ra);

    v->arch.vplic = vplic_alloc();

    if ( !v->arch.vplic )
    {
        free_xenheap_pages(v->arch.stack, 3);
        return -ENOMEM;
    }

    vcpu_csr_init(v);

    if ( (rc = vcpu_vtimer_init(v)) != 0 )
        goto fail;

    return rc;

 fail:
    arch_vcpu_destroy(v);
    return rc;
}

void arch_vcpu_destroy(struct vcpu *v)
{
    /* TODO */
}

