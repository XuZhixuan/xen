/******************************************************************************
 * Arch-specific sysctl.c
 *
 * System management operations. For use by node control stack.
 *
 * Copyright (c) 2012, Citrix Systems
 */

#include <xen/lib.h>
#include <xen/errno.h>
#include <public/sysctl.h>

void arch_do_physinfo(struct xen_sysctl_physinfo *pi) { }

long arch_do_sysctl(struct xen_sysctl *sysctl,
                XEN_GUEST_HANDLE_PARAM(xen_sysctl_t) u_sysctl)
{
    return -ENOSYS;
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
