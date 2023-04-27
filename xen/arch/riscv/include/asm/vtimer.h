/*
 * xen/include/asm-riscv/vtimer.h
 *
 * RISC-V Virtual Timer emulation support
 * 
 * Copyright (c) 2022 Xie Xun <xiexun162534@gmail.com>
 *
 * Based on xen/include/asm-arm/vtimer.h
 * Ian Campbell <ian.campbell@citrix.com>
 * Copyright (c) 2011 Citrix Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __ARCH_RISCV_VTIMER_H__
#define __ARCH_RISCV_VTIMER_H__

#include <asm/domain.h>

extern int domain_vtimer_init(struct domain *d,
                              struct xen_arch_domainconfig *config);
extern int vcpu_vtimer_init(struct vcpu *v);
extern void vcpu_timer_destroy(struct vcpu *v);
extern void vtimer_save(struct vcpu *v);
extern void vtimer_restore(struct vcpu *v);
extern void vtimer_set_timer(struct vtimer *t, uint64_t ticks);

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
