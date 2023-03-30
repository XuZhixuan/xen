/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Architecture-specific vm_event handling routines */

#include <xen/bug.h>
#include <xen/sched.h>
#include <asm/vm_event.h>

void vm_event_fill_regs(vm_event_request_t *req)
{
    assert_failed("need to be implemented");
}

void vm_event_set_registers(struct vcpu *v, vm_event_response_t *rsp)
{
    assert_failed("need to be implemented");
}

void vm_event_monitor_next_interrupt(struct vcpu *v)
{
    assert_failed("need to be implemented");
}

void vm_event_reset_vmtrace(struct vcpu *v)
{
    assert_failed("need to be implemented");
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
