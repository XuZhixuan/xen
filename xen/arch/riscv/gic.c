/* SPDX-License-Identifier: MIT */
/*
 * xen/arch/riscv/gic.c
 *
 * Based on Arm xen/arch/arm/gic.c
 *
 * Generic Interrupt Controler
 *
 * (c) 2024 Microchip Technology Inc.
 */

#include <xen/sched.h>
#include <asm/setup.h>
#include <xen/types.h>

#include <asm/gic.h>
#include <asm/vplic.h>

static const struct gic_hw_operations *gic_ops = NULL;

void* gic_get_private(void)
{
    if ( gic_ops->get_private )
        return gic_ops->get_private();

    return NULL;
}

/* Set up the per-CPU parts of the GIC for a secondary CPU */
void gic_init_secondary_cpu(void)
{
    if ( gic_ops->secondary_init )
        gic_ops->secondary_init();
}

int gic_make_hwdom_dt_node(struct domain *d,
                           const struct dt_device_node *gic,
                           void *fdt)
{
    ASSERT(gic == dt_interrupt_controller);

    if ( gic_ops && gic_ops->make_dom_dt_node )
        return gic_ops->make_dom_dt_node(d, gic, fdt);

    return 0;
}

int gic_make_domu_dt_node(struct domain *d, void *fdt)
{
    if ( gic_ops && gic_ops->make_dom_dt_node )
        return gic_ops->make_dom_dt_node(d, gic_ops->info->node, fdt);

    return 0;
}

int gic_iomem_deny_access(struct domain *d)
{
    if ( gic_ops && gic_ops->iomem_deny_access )
        return gic_ops->iomem_deny_access(d);

    return 0;
}

int gic_register_domain(const struct domain *d)
{
    if ( gic_ops && gic_ops->register_domain )
        return gic_ops->register_domain(d);

    return 0;
}

int gic_unregister_domain(const struct domain *d)
{
    if ( gic_ops && gic_ops->unregister_domain )
        return gic_ops->unregister_domain(d);

    return 0;
}

void gic_ops_register(const struct gic_hw_operations *ops)
{
    gic_ops = ops;
}

static void __init gic_dt_preinit(void)
{
    int rc;
    struct dt_device_node *node;
    uint8_t num_gics = 0;

    dt_for_each_device_node( dt_host, node )
    {
        if ( !dt_get_property(node, "interrupt-controller", NULL) )
            continue;

        if ( !dt_get_parent(node) )
            continue;        

        rc = device_init(node, DEVICE_GIC, NULL);
        if ( !rc )
        {
            /* NOTE: Only one GIC is supported */
            num_gics = 1;
            break;
        }
    }
    if ( !num_gics )
        panic("Unable to find a compatible GIC in the device tree\n");

    /* Set the GIC as the primary interrupt controller */
    dt_interrupt_controller = node;
    dt_device_set_used_by(node, DOMID_XEN);
}

void __init gic_init(void)
{
    if ( gic_ops->init && gic_ops->init() )
        panic("Failed to initialize the GIC drivers\n");
}

void __init gic_preinit(void)
{
    gic_dt_preinit();
}

struct vgic* gic_alloc_vgic(struct vcpu *vcpu)
{
    struct vgic *v;

    switch ( gic_ops->info->hw_version )
    {
    case GIC_PLIC:
        v = &vplic_alloc(vcpu)->vgic;
        break;
    default:
        printk(XENLOG_WARNING "need to add allocation vgic?\n");
        return NULL;
    }

    if ( v )
        v->info = gic_ops->info;

    /* phandle will be updated during the dom0/domU creation */
    return v;
}

void gic_free_vgic(struct vgic *v)
{
    switch ( gic_ops->info->hw_version )
    {
    case GIC_PLIC:
        if ( v ) to_vaplic(v);
        break;
    default:
        panic("Unsupported free of gic\n"); 
    }
}
