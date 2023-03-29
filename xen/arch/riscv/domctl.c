#include <xen/bug.h>
#include <xen/errno.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/iocap.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/types.h>
#include <xsm/xsm.h>
#include <public/domctl.h>

void arch_get_domain_info(const struct domain *d,
                          struct xen_domctl_getdomaininfo *info)
{
    assert_failed("need to be implemented");
}

long arch_do_domctl(struct xen_domctl *domctl, struct domain *d,
                    XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl)
{
    assert_failed("need to be implemented");
}

void arch_get_info_guest(struct vcpu *v, vcpu_guest_context_u c)
{
    WARN();
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
