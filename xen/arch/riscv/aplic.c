/* SPDX-License-Identifier: MIT */
/*
 * xen/arch/riscv/aplic.c
 *
 * RISC-V Advanced Platform-Level Interrupt Controller support
 *
 * Copyright (c) 2024 Microchip.
 */

#include <xen/errno.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/libfdt/libfdt.h>
#include <xen/sched.h>
#include <xen/vmap.h>

#include <asm/aplic.h>
#include <asm/device.h>
#include <asm/gic.h>

#define APLIC_DEFAULT_PRIORITY		1

static struct aplic_priv aplic;

static struct gic_info aplic_info = {
    .hw_version = GIC_APLIC,
    .node = NULL,
    .private = &aplic
};

static void aplic_init_hw_interrupts(void)
{
    int i;

    /* Disable all interrupts */
    for ( i = 0; i <= aplic_info.nr_irqs; i += 32 )
        aplic.regs->clrie[i] = -1U;

    /* Set interrupt type */
    for ( i = 1; i <= aplic_info.nr_irqs; i++ )
    {
        aplic.regs->sourcecfg[i - 1] = 0;
    }

    /* set imsic delivery for the this hart */
    imsic_ids_local_delivery(true);

    /* Clear APLIC domaincfg */
    aplic.regs->domaincfg = APLIC_DOMAINCFG_IE | APLIC_DOMAINCFG_DM;
}

static int aplic_irq_xlate(const uint32_t *intspec, unsigned int intsize,
                           unsigned int *out_hwirq,
                           unsigned int *out_type)
{
    if ( intsize < 2 )
        return -EINVAL;

    /* Mapping 1:1 */
    *out_hwirq = intspec[0];

    if ( out_type )
        *out_type = intspec[1] & IRQ_TYPE_SENSE_MASK;

    return 0;
}

static int __init aplic_init(void)
{
    int rc, err;
    u32 phandle, irq_range[2];
    const __be32 *prop;
    uint64_t size, paddr = 0;
    const struct dt_device_node *node = aplic_info.node;
    struct dt_device_node *imsic_node = NULL;

    /* check for associated imsic node */
    rc = dt_property_read_u32(node, "msi-parent", &phandle);
    if ( !rc )
    {
        printk(XENLOG_ERR "%s: APLIC wired mode not supported\n", node->full_name);
        return -EOPNOTSUPP;
    }

    imsic_node = dt_find_node_by_phandle(phandle);
    if ( !imsic_node )
    {
        printk(XENLOG_ERR "%s: unable to find IMSIC node\n", node->full_name);
        return -EINVAL;
    }

    /* check imsic mode */
    rc = dt_property_read_u32_array(imsic_node, "interrupts-extended", irq_range,
                                    ARRAY_SIZE(irq_range));
    if ( rc && (rc != -EOVERFLOW) )
    {
        printk(XENLOG_ERR "%s: unable to find interrupt-extended in %s node\n",
            node->full_name, imsic_node->full_name);
        return -EINVAL;
    }

    if ( irq_range[1] == IRQ_M_EXT )
    {
        /* machine mode imsic node, ignore this aplic node */
        return 0;
    }

    rc = imsic_init(imsic_node);
    if ( rc )
    {
        printk(XENLOG_ERR "%s: Failded to initialize IMSIC\n", node->full_name);
        return -EINVAL;
    }

    /* Find out number of interrupt sources */
    rc = dt_property_read_u32(node, "riscv,num-sources", &aplic_info.nr_irqs);
    if ( !rc )
    {
        printk(XENLOG_ERR "%s: failed to get number of interrupt sources\n",
            node->full_name);
        err = -EINVAL;
        goto aplic_dev_dt_preinit_err1;
    }

    prop = dt_get_property(node, "reg", NULL);
    dt_get_range(&prop, node, &paddr, &size);
    if ( !paddr )
    {
        printk(XENLOG_ERR "%s: first MMIO resource not found\n", node->full_name);
        err = -EINVAL;
        goto aplic_dev_dt_preinit_err1;
    }

    aplic.paddr_start = paddr;
    aplic.paddr_end = paddr + size;
    aplic.size = size;

    aplic.regs = ioremap(paddr, size);
    if ( !aplic.regs )
        panic("%s: unable to map\n", node->full_name);

    /* Setup initial state APLIC interrupts */
    aplic_init_hw_interrupts();

    /* Setup IDCs or MSIs */
    rc = dt_property_read_bool(node, "msi-parent");
    if (!rc)
    {
        /* only MSI support */
        /* TODO: implement IDC */
        panic("%s: IDC mode not supported\n", node->full_name);
    }
    return 0;

aplic_dev_dt_preinit_err1:
    return err;
}

static unsigned int aplic_get_cpu_from_mask(const cpumask_t *cpumask)
{
    unsigned int cpu;
    cpumask_t possible_mask;

    cpumask_and(&possible_mask, cpumask, &cpu_possible_map);
    cpu = cpumask_any(&possible_mask);

    return cpu;
}

static void aplic_irq_enable(struct irq_desc *desc)
{
    unsigned long flags;

    ASSERT(spin_is_locked(&desc->lock));

    spin_lock_irqsave(&aplic.lock, flags);
    clear_bit(_IRQ_DISABLED, &desc->status);
    /* enable interrupt in IMSIC */
    imsic_irq_enable(desc->irq);
    /* enable interrupt in APLIC */
    aplic.regs->setienum = desc->irq;
    spin_unlock_irqrestore(&aplic.lock, flags);
}

static void aplic_irq_disable(struct irq_desc *desc)
{
    unsigned long flags;

    ASSERT(spin_is_locked(&desc->lock));

    spin_lock_irqsave(&aplic.lock, flags);
    set_bit(_IRQ_DISABLED, &desc->status);
    /* disable interrupt in APLIC */
    aplic.regs->clrienum = desc->irq;
    /* disable interrupt in IMSIC */
    imsic_irq_disable(desc->irq);
    spin_unlock_irqrestore(&aplic.lock, flags);
}

static int __init aplic_secondary_cpu_init(void)
{
    /* set imsic delivery for the secondary harts */
    imsic_ids_local_delivery(true);
    return 0;
}

static void aplic_save_state(struct vcpu *v)
{
    BUG_ON("unimplemented");
}

static void aplic_restore_state(const struct vcpu *v)
{
    BUG_ON("unimplemented");
}

static void aplic_dump_state(const struct vcpu *v)
{
    BUG_ON("unimplemented");
}

static unsigned int aplic_read_irq(void)
{
    BUG_ON("unimplemented");

    return 0;
}

static void aplic_set_active_state(struct irq_desc *irqd, bool active)
{
    BUG_ON("unimplemented");
}

static void aplic_set_pending_state(struct irq_desc *irqd, bool pending)
{
    BUG_ON("unimplemented");
}

static void aplic_set_irq_type(struct irq_desc *desc, unsigned int type)
{
    unsigned int irq = desc->irq - 1;
    
    spin_lock(&aplic.lock);
    switch(type) {
        case IRQ_TYPE_EDGE_RISING:
            aplic.regs->sourcecfg[irq] = APLIC_SOURCECFG_SM_EDGE_RISE;
            break;
        case IRQ_TYPE_EDGE_FALLING:
            aplic.regs->sourcecfg[irq] = APLIC_SOURCECFG_SM_EDGE_FALL;
            break;
        case IRQ_TYPE_LEVEL_HIGH:
            aplic.regs->sourcecfg[irq] = APLIC_SOURCECFG_SM_LEVEL_HIGH;
            break;
        case IRQ_TYPE_LEVEL_LOW:
            aplic.regs->sourcecfg[irq] = APLIC_SOURCECFG_SM_LEVEL_LOW;
            break;
        default:
            aplic.regs->sourcecfg[irq] = APLIC_SOURCECFG_SM_INACTIVE;
            break;
    }
    spin_unlock(&aplic.lock);
}

static void aplic_set_irq_priority(struct irq_desc *desc,
                                   unsigned int priority)
{
    /* No priority, do nothing */
}

static unsigned int aplic_irq_startup(struct irq_desc *desc)
{
    aplic_irq_enable(desc);

    return 0;
}

static void aplic_irq_shutdown(struct irq_desc *desc)
{
    aplic_irq_disable(desc);
}

static void aplic_irq_ack(struct irq_desc *desc)
{
    /* nothing to do */
}

static void aplic_host_irq_end(struct irq_desc *desc)
{
    /* do nothing */
}

// static void aplic_guest_irq_end(struct irq_desc *desc)
// {
//     /* Lower the priority of the IRQ */
//     aplic_eoi_irq(desc);
//     /* Deactivation happens in maintenance interrupt / via GICV */
// }

static void aplic_set_irq_affinity(struct irq_desc *desc, const cpumask_t *mask)
{
    unsigned int cpu;
    uint64_t group_index, base_ppn;
    uint32_t hhxw, lhxw ,hhxs, value;
    const struct imsic_config *imsic = aplic.imsic_cfg;

    ASSERT(!cpumask_empty(mask));

    spin_lock(&aplic.lock);
    
    cpu = cpu_physical_id(aplic_get_cpu_from_mask(mask));
    hhxw = imsic->group_index_bits;
    lhxw = imsic->hart_index_bits;
    hhxs = imsic->group_index_shift - IMSIC_MMIO_PAGE_SHIFT * 2;
    base_ppn = imsic->msi[cpu].base_addr >> IMSIC_MMIO_PAGE_SHIFT;

    /* update hart and EEID in the target register */
    group_index = (base_ppn >> (hhxs + 12)) & (BIT(hhxw, UL) - 1);
    value = desc->irq;
    value |= cpu << APLIC_TARGET_HART_IDX_SHIFT;
    value |= group_index << (lhxw + APLIC_TARGET_HART_IDX_SHIFT) ;
    aplic.regs->target[desc->irq - 1] = value;
    spin_unlock(&aplic.lock);
}

static void aplic_disable_interface(void)
{
    imsic_ids_local_delivery(false);
}

static bool aplic_read_pending_state(struct irq_desc *irqd)
{
    BUG_ON("unimplemented");

    return false;
}

static int aplic_make_dom_dt_node(struct domain *d,
                                  const struct dt_device_node *aplic_node,
                                  void *fdt)
{
    uint32_t len, phandle;
    const __be32 *regs;
    const void *data = NULL;
    struct dt_device_node *imsic_node = NULL;
    int res = 0;

    /* TODO: re-use imsic_node from aplic_init()? */

    /* create IMSIC node first */
    res = dt_property_read_u32(aplic_node, "msi-parent", &phandle);
    if ( !res )
    {
        printk(XENLOG_ERR "%s: APLIC wired mode not supported\n", aplic_node->full_name);
        return -EOPNOTSUPP;
    }

    imsic_node = dt_find_node_by_phandle(phandle);
    if ( !imsic_node )
    {
        printk(XENLOG_ERR "%s: unable to find IMSIC node\n", aplic_node->full_name);
        return -EINVAL;
    }

    res = imsic_make_dt_node(d, fdt, imsic_node);
    if ( res )
        return res;

    /* create aplic node */
    res = fdt_begin_node(fdt, strrchr(aplic_node->full_name, '/') + 1);
    if (res)
        return res;

    /* TODO: DO WE REALLY NEED TO GENERATE IT?? */
    /* generate a phandle */
    res = fdt_generate_phandle(fdt, &d->arch.phandle_gic);
    if ( res )
        return res;

    data = dt_get_property(aplic_node, "#interrupt-cells", &len);
    if ( !data )
    {
        printk("%s: Can't find '#interrupt-cells' property\n", aplic_node->full_name);
        return -FDT_ERR_XEN(ENOENT);
    }

    res = fdt_property(fdt, "#interrupt-cells", data, len);
    if (res)
        return res;

    regs = dt_get_property(aplic_node, "reg", &len);
    if ( !regs )
    {
        printk("%s: Can't find 'reg' property\n", aplic_node->full_name);
        return -FDT_ERR_XEN(ENOENT);
    }

    res = fdt_property(fdt, "reg", regs, len);
    if ( res )
        return res;

    data = dt_get_property(aplic_node, "riscv,num-sources", &len);
    if ( !data )
    {
        printk("%s: Can't find 'riscv,num-sources' property\n", aplic_node->full_name);
        return -FDT_ERR_XEN(ENOENT);
    }

    res = fdt_property(fdt, "riscv,num-sources", data, len);
    if ( res )
        return res;

    res = fdt_property(fdt, "interrupt-controller", NULL, 0);
    if ( res )
        return res;

    data = dt_get_property(aplic_node, "compatible", &len);
    if ( !data )
    {
        printk("%s: Can't find 'compatible' property\n", aplic_node->full_name);
        return -FDT_ERR_XEN(ENOENT);
    }

    res = fdt_property(fdt, "compatible", data, len);
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "msi-parent", aplic.imsic_cfg->phandle);
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "phandle", d->arch.phandle_gic);
    if ( res )
        return res;

    return fdt_end_node(fdt);
}

static int aplic_map_hwdom_extra_mappings(struct domain *d)
{
    BUG_ON("unimplemented");

    return 0;
}

static void * aplic_get_private(void)
{
    return aplic_info.private;
}

void aplic_handle_interrupt(unsigned long cause, struct cpu_user_regs *regs)
{
    /* disable to avoid more external interrupts */
    csr_clear(CSR_SIE, 1UL << IRQ_S_EXT);

    /* clear the pending bit */
    csr_clear(CSR_SIP, 1UL << IRQ_S_EXT);
    
    /* dispatch the interrupt */
    do_IRQ(regs, csr_swap(CSR_STOPEI, 0) >> TOPI_IID_SHIFT);

    /* enable external interrupts */
    csr_set(CSR_SIE, 1UL << IRQ_S_EXT);
}

static hw_irq_controller aplic_host_irq_type = {
    .typename     = "aplic",
    .startup      = aplic_irq_startup,
    .shutdown     = aplic_irq_shutdown,
    .enable       = aplic_irq_enable,
    .disable      = aplic_irq_disable,
    .ack          = aplic_irq_ack,
    .end          = aplic_host_irq_end,
    .set_affinity = aplic_set_irq_affinity,
};

// static hw_irq_controller aplic_guest_irq_type = {
//     .typename     = "aplic",
//     .startup      = aplic_irq_startup,
//     .shutdown     = aplic_irq_shutdown,
//     .enable       = aplic_irq_enable,
//     .disable      = aplic_irq_disable,
//     .ack          = aplic_irq_ack,
//     .end          = aplic_guest_irq_end,
//     .set_affinity = aplic_set_irq_affinity,
// };

const static struct gic_hw_operations aplic_ops = {
    .info                = &aplic_info,
    .register_domain     = imsic_register_domain,
    .unregister_domain   = imsic_unregister_domain,
    .init                = aplic_init,
    .secondary_init      = aplic_secondary_cpu_init,
    .save_state          = aplic_save_state,
    .restore_state       = aplic_restore_state,
    .dump_state          = aplic_dump_state,
    .host_irq_type       = &aplic_host_irq_type,
    // .guest_irq_type      = &aplic_guest_irq_type,
    .read_irq            = aplic_read_irq,
    .set_active_state    = aplic_set_active_state,
    .set_pending_state   = aplic_set_pending_state,
    .set_irq_type        = aplic_set_irq_type,
    .set_irq_priority    = aplic_set_irq_priority,
    .disable_interface   = aplic_disable_interface,
    .read_pending_state  = aplic_read_pending_state,
    .make_dom_dt_node    = aplic_make_dom_dt_node,
    .map_hwdom_extra_mappings = aplic_map_hwdom_extra_mappings,
    .iomem_deny_access   = imsic_iomem_deny_access,
    .get_private         = aplic_get_private,
    .handle_interrupt    = aplic_handle_interrupt,
};

static int __init aplic_preinit(struct dt_device_node *node,
                                const void *dat)
{
    static bool already_set = false;

    /* Enable supervisor external interrupt */
    csr_set(CSR_SIE, 1UL << IRQ_S_EXT);

    /* support only one supervisor aplic */
    if ( already_set )
    {
        printk(XENLOG_ERR "XEN doesn't support more than one supervisor APLIC\n");
        return -ENODEV;
    }

    /* don't process if aplic node is not for S mode */
    if ( dt_get_property(node, "riscv,children", NULL) )
        return -ENODEV;
    
    aplic_info.node = node;
    aplic.imsic_cfg = imsic_get_config();
    spin_lock_init(&aplic.lock);
    gic_ops_register(&aplic_ops);
    dt_irq_xlate = aplic_irq_xlate;

    return 0;
}

static const struct dt_device_match aplic_dt_match[] __initconst =
{
    DT_MATCH_COMPATIBLE("riscv,aplic"),
    { /* sentinel */ },
};

DT_DEVICE_START(aplic, "APLIC", DEVICE_GIC)
        .dt_match = aplic_dt_match,
        .init = aplic_preinit,
DT_DEVICE_END
