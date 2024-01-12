/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <xen/errno.h>
#include <xen/device_tree.h>
#include <xen/init.h>
#include <xen/lib.h>

#include <asm/device.h>
#include <asm/gic.h>
#include <asm/plic.h>
#include <asm/vplic.h>

struct plic_priv {
    /* base physical address and size */
    paddr_t    paddr_start;
    paddr_t    paddr_end;
    uint64_t   size;
};

static struct plic_priv plic;

static struct gic_info plic_info = {
    .hw_version = GIC_PLIC,
    .node = NULL,
    .private = &plic
};

int __init plic_init_secondary_cpu(void)
{
    printk(XENLOG_WARNING "%s: need to be implemented\n", __func__);

    return -EOPNOTSUPP;
}

const static struct gic_hw_operations plic_ops = {
    .info               = &plic_info,
    .secondary_init     = plic_init_secondary_cpu,
};

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

    plic_info.node = node;

    gic_ops_register(&plic_ops);

    return 0;
}

DT_DEVICE_START(plic, "PLIC", DEVICE_GIC)
        .dt_match = plic_dt_match,
        .init = plic_dev_dt_preinit,
DT_DEVICE_END
