/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <xen/errno.h>
#include <xen/device_tree.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <asm/device.h>
#include <asm/plic.h>
#include <asm/vplic.h>

static void __init plic_dt_preinit(void)
{
    int rc = -ENODEV;
    struct dt_device_node *node;

    dt_for_each_device_node( dt_host, node )
    {
        if ( !dt_get_property(node, "interrupt-controller", NULL) )
            continue;

        if ( !dt_get_parent(node) )
            continue;

        rc = device_init(node, DEVICE_GIC, NULL);
        if ( !rc )
            break;
    }

    if ( rc )
        panic("Unable to find PLIC node in the device tree\n");

    dt_interrupt_controller = node;
    dt_device_set_used_by(node, DOMID_XEN);
}

void __init plic_preinit(void)
{
    plic_dt_preinit();
}

int plic_irq_xlate(const u32 *intspec, unsigned int intsize,
                   unsigned int *out_hwirq,
                   unsigned int *out_type)
{
    if ( intsize != 1 )
        return -EINVAL;

    *out_hwirq = intspec[0];

    if ( out_type )
        *out_type = DT_IRQ_TYPE_NONE;

    return 0;
}

static const struct dt_device_match plic_dt_match[] __initconst =
{
    DT_MATCH_COMPATIBLE("riscv,plic0"),
    DT_MATCH_COMPATIBLE("sifive,plic-1.0.0"),
    { /* sentinel */ },
};

static int __init plic_dev_dt_preinit(struct dt_device_node *node,
                                      const void *data)
{
    dt_irq_xlate = plic_irq_xlate;

    return 0;
}

DT_DEVICE_START(plic, "PLIC", DEVICE_GIC)
        .dt_match = plic_dt_match,
        .init = plic_dev_dt_preinit,
DT_DEVICE_END
