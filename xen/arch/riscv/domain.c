#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/softirq.h>
#include <asm/cpufeature.h>
#include <asm/current.h>
#include <asm/gic.h>
#include <asm/p2m.h>
#include <asm/riscv_encoding.h>
#include <asm/sbi.h>
#include <asm/traps.h>
#include <asm/vplic.h>
#include <asm/vtimer.h>
#include <public/domctl.h>
#include <public/xen.h>

DEFINE_PER_CPU(struct vcpu *, curr_vcpu);

static void ctxt_switch_from(struct vcpu *p)
{
    /* When the idle VCPU is running, Xen will always stay in hypervisor
     * mode. Therefore we don't need to save the context of an idle VCPU.
     */
    if ( is_idle_vcpu(p) )
    {
        printk("%s: is_idle_vcpu\n", __func__);
        return;
    }

    p2m_save_state(p);

    vtimer_save(p);

    context_save_csrs(p);
}

static void ctxt_switch_to(struct vcpu *n)
{
    /*
     * When the idle VCPU is running, Xen will always stay in hypervisor
     * mode. Therefore we don't need to restore the context of an idle VCPU.
     */
    if ( is_idle_vcpu(n) )
    {
        printk("%s: is_idle_vcpu\n", __func__);

        return;
    }

    p2m_restore_state(n);

    vtimer_restore(n);

    context_restore_csrs(n);
}

static void schedule_tail(struct vcpu *prev)
{
    ASSERT(prev != current);

    local_irq_enable();

    sched_context_switched(prev, current);

    // update_runstate_area(current);

    /* Ensure that the vcpu has an up-to-date time base. */
    // update_vcpu_system_time(current);
}

void context_switch(struct vcpu *prev, struct vcpu *next)
{
    ASSERT(local_irq_is_enabled());
    ASSERT(prev != next);
    ASSERT(!vcpu_cpu_dirty(next));

    // update_runstate_area(prev);

    local_irq_disable();

    set_current(next);

    ctxt_switch_from(prev);

    ctxt_switch_to(next); 

    tp->hsp = (unsigned long)next->arch.cpu_info;
    tp->guest_cpu_info = next->arch.cpu_info;

    prev = __context_switch(prev, next);

    schedule_tail(prev);
}

void continue_running(struct vcpu *same)
{
    /* Nothing to do */
}

void sync_local_execstate(void)
{
    /* Nothing to do -- no lazy switching */
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

    d->arch.phandle_gic = 0;

    if ( is_idle_domain(d) )
        return 0;

    if ( (rc = iommu_domain_init(d, config->iommu_opts)) != 0 )
        goto fail;

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

static void do_idle(void)
{
    unsigned int cpu = smp_processor_id();

    rcu_idle_enter(cpu);
    /* rcu_idle_enter() can raise TIMER_SOFTIRQ. Process it now. */
    process_pending_softirqs();

    local_irq_disable();
    if ( cpu_is_haltable(cpu) )
    {
        wfi();
    }
    local_irq_enable();

    rcu_idle_exit(cpu);
}

void idle_loop(void)
{
    unsigned int cpu = smp_processor_id();

    printk("%s\n", __func__);

    for ( ; ; )
    {
        if ( unlikely(tasklet_work_to_do(cpu)) )
            do_tasklet();
        else if ( !softirq_pending(cpu) && !scrub_free_pages() &&
                  !softirq_pending(cpu) )
            do_idle();

        do_softirq();
    }
}

void noreturn startup_cpu_idle_loop(void)
{
    struct vcpu *v = current;

    ASSERT(is_idle_vcpu(v));

    tp->hsp = v->arch.saved_context.sp;
    tp->guest_cpu_info = (struct cpu_info *)guest_regs(v);

    reset_stack_and_jump(idle_loop);

    /* This function is noreturn */
    BUG();
}

extern void noreturn return_to_new_vcpu64(void);

static void continue_new_vcpu(struct vcpu *prev)
{
    if ( is_idle_vcpu(current) )
        reset_stack_and_jump(idle_loop);
    else
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

    hideleg = MIP_VSTIP |  MIP_VSEIP | MIP_VSSIP;
    v->arch.hideleg = hideleg;

    v->arch.hie = hideleg;

    /* Enable all timers for guest */
    v->arch.hcounteren = -1UL;

    v->arch.henvcfg |= ENVCFG_STCE;

    if ( riscv_isa_extension_available(NULL, SMSTATEEN) )
        /*
         * If the hypervisor extension is implemented, the same three bitsare
         * defined also in hypervisor CSR hstateen0 but concern only the state
         * potentially accessible to a virtual machine executing in privilege
         * modes VS and VU:
         *      bit 60 CSRs siselect and sireg (really vsiselect and vsireg)
         *      bit 59 CSRs siph and sieh (RV32 only) and stopi (really vsiph,
         *             vsieh, and vstopi)
         *      bit 58 all state of IMSIC guest interrupt files, including CSR
         *             stopei (really vstopei)
         * If one of these bits is zero in hstateen0, and the same bit is one
         * in mstateen0, then an attempt to access the corresponding state from
         * VS or VU-mode raises a virtual instruction exception.
        */
        v->arch.hstateen0 = SMSTATEEN0_AIA | SMSTATEEN0_IMSIC | SMSTATEEN0_SVSLCT;

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

    vcpu_csr_init(v);

    /* no interruption controler for reserved domain */
    if ( v->domain->domain_id < DOMID_FIRST_RESERVED )
    {
        v->arch.vgic = gic_alloc_vgic(v);

        if ( !v->arch.vgic )
        {
            free_xenheap_pages(v->arch.stack, 3);
            return -ENOMEM;
        }
    }

    if ( (rc = vcpu_vtimer_init(v)) != 0 )
        goto fail;

    return rc;

 fail:
    arch_vcpu_destroy(v);
    return rc;
}

void arch_vcpu_destroy(struct vcpu *v)
{
    gic_free_vgic(v->arch.vgic);

    /* TODO */
}

struct vcpu *alloc_dom0_vcpu0(struct domain *dom0)
{
    return vcpu_create(dom0, 0);
}

void vcpu_kick(struct vcpu *vcpu)
{
    bool running = vcpu->is_running;

    vcpu_unblock(vcpu);
    if ( running && vcpu != current )
    {
        perfc_incr(vcpu_kick);
        smp_send_event_check_mask(cpumask_of(vcpu->processor));
    }
}
