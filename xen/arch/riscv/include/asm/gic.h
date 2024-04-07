/* SPDX-License-Identifier: MIT */
/*
 * xen/arch/riscv/gic.h
 *
 * Based on xen/arch/arm/gic.h
 *
 * Generic Interrupt Controler
 *
 * (c) 2024 Microchip Technology Inc.
 *
 */

#ifndef __ASM_RISCV_GIC_H__
#define __ASM_RISCV_GIC_H__

#include <xen/irq.h>
#include <xen/init.h>

enum gic_version {
    GIC_INVALID = 0,    /* the default until explicitly set up */
    GIC_PLIC,
    GIC_APLIC,
};

struct gic_info {
    /* GIC version */
    enum gic_version hw_version;
    /* Pointer to the device tree node representing the interrupt controller */
    const struct dt_device_node *node;
    /* interrupt cell size of GIC */
    int interrupt_cell_size;
    /* private data pointer of the interrupt controller */
    void *private;
    /* GIC number of interrupt */
    unsigned int nr_irqs;
};

struct gic_hw_operations {
    /* Hold GIC HW information */
    const struct gic_info *info;
    /* Initialize the GIC and the boot CPU */
    int (*init)(void);
    /* Save GIC registers */
    void (*save_state)(struct vcpu *);
    /* Restore GIC registers */
    void (*restore_state)(const struct vcpu *);
    /* Dump GIC LR register information */
    void (*dump_state)(const struct vcpu *);
    /* register a domain */
    int (*register_domain)(const struct domain *d);
    /* unregister domain */
    int (*unregister_domain)(const struct domain *d);
    /* hw_irq_controller to enable/disable/eoi host irq */
    hw_irq_controller *host_irq_type;
    /* hw_irq_controller to enable/disable/eoi guest irq */
    // hw_irq_controller *guest_irq_type;
    /* Read IRQ id and Ack */
    unsigned int (*read_irq)(void);
    /* Force the active state of an IRQ by accessing the distributor */
    void (*set_active_state)(struct irq_desc *irqd, bool state);
    /* Force the pending state of an IRQ by accessing the distributor */
    void (*set_pending_state)(struct irq_desc *irqd, bool state);
    /* Set IRQ type */
    void (*set_irq_type)(struct irq_desc *desc, unsigned int type);
    /* Set IRQ priority */
    void (*set_irq_priority)(struct irq_desc *desc, unsigned int priority);
    /* Disable CPU physical and virtual interfaces */
    void (*disable_interface)(void);
    /* Query the pending state of an interrupt at the distributor level. */
    bool (*read_pending_state)(struct irq_desc *irqd);
    /* Secondary CPU init */
    int (*secondary_init)(void);
    /* Create GIC node for domain */
    int (*make_dom_dt_node)(struct domain *d,
                              const struct dt_device_node *gic, void *fdt);
    /* Map extra GIC MMIO, irqs and other hw stuffs to the hardware domain. */
    int (*map_hwdom_extra_mappings)(struct domain *d);
    /* Deny access to GIC regions */
    int (*iomem_deny_access)(struct domain *d);
    /* get private section */
    void * (*get_private)(void);
    /* handle external interrupt */
    void (*handle_interrupt)(unsigned long cause, struct cpu_user_regs *regs);
};

struct vgic {
    const struct gic_info *info;
    int (*emulate_load)(struct vcpu *vcpu, unsigned long addr, uint32_t *out);
    int (*emulate_store)(struct vcpu *vcpu, unsigned long addr, uint32_t in);
    int (*is_access)(struct vcpu *vcpu, unsigned long address);
};

void gic_preinit(void);
void gic_init(void);

void gic_ops_register(const struct gic_hw_operations *ops);
int gic_register_domain(const struct domain *d);
int gic_unregister_domain(const struct domain *d);
int gic_make_hwdom_dt_node(struct domain *d,
                           const struct dt_device_node *gic,
                           void *fdt);
int gic_make_domu_dt_node(struct domain *d, void *fdt);

struct vgic* gic_alloc_vgic(struct vcpu *vcpu);
void gic_free_vgic(struct vgic *v);

void* gic_get_private(void);

int gic_iomem_deny_access(struct domain *d);

void gic_init_secondary_cpu(void);

void gic_route_irq_to_xen(struct irq_desc *desc, unsigned int priority);

void gic_disable_cpu(void);

void gic_handle_external_interrupts(unsigned long cause, struct cpu_user_regs *regs);

#endif /* __ASM_RISCV_GIC_H__ */
