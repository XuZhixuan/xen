/* SPDX-License-Identifier: MIT */
/*
 * xen/arch/riscv/vaplic.c
 *
 * Virtual RISC-V Advanced Platform-Level Interrupt Controller support
 *
 * Copyright (c) 2024 Microchip.
 *
 */

#include <xen/sched.h>
#include <xen/types.h>

#include <asm/aplic.h>
#include <asm/imsic.h>
#include <asm/setup.h>
#include <asm/vaplic.h>

#define IMSIC_REG_GET(addr) (*(uint32_t *)((uint64_t)addr))
#define IMSIC_REG_SET(addr, value) ((*(uint32_t *)((uint64_t)addr) = value))
#define IS_SETIPNUM_LE_ACCESS(addr) ((addr % IMSIC_MMIO_PAGE_SZ) == IMSIC_MMIO_SETIPNUM_LE)

static void vaplic_update_target(const struct imsic_config *imsic,
                                 int guest_id, unsigned long hart_id,
                                 uint32_t *value)
{
    unsigned long group_index;
    uint32_t hhxw = imsic->group_index_bits;
    uint32_t lhxw = imsic->hart_index_bits;
    uint32_t hhxs = imsic->group_index_shift - IMSIC_MMIO_PAGE_SHIFT * 2;
    unsigned long base_ppn = imsic->msi[hart_id].base_addr >> IMSIC_MMIO_PAGE_SHIFT;

    group_index = (base_ppn >> (hhxs + 12)) & (BIT(hhxw, UL) - 1);

    *value &= APLIC_TARGET_EIID_MASK;
    *value |= guest_id << APLIC_TARGET_GUEST_IDX_SHIFT;
    *value |= hart_id << APLIC_TARGET_HART_IDX_SHIFT;
    *value |= group_index << (lhxw + APLIC_TARGET_HART_IDX_SHIFT) ;
}

int vaplic_is_access(struct vcpu *vcpu, unsigned long addr)
{
    struct vaplic *vaplic = to_vaplic(vcpu->arch.vgic);
    struct aplic_priv *priv = vaplic->base.info->private;

    /* check if it is an APLIC access */
    if ( priv->paddr_start <= addr && addr < priv->paddr_end )
        return 1;

    return 0;
}

int vaplic_emulate_load(struct vcpu *vcpu, unsigned long addr, uint32_t *out)
{
    struct vaplic *vaplic = to_vaplic(vcpu->arch.vgic);
    struct aplic_priv *priv = vaplic->base.info->private;
    unsigned long offset = addr & APLIC_REG_OFFSET_MASK;

    switch ( offset )
    {
    case APLIC_DOMAINCFG:
        *out = vaplic->regs.domaincfg;
        return 0;

    case APLIC_SMSICFGADDR:
        *out = vaplic->regs.smsiaddrcfg;
        return 0;

    case APLIC_SMSICFGADDRH:
        *out = vaplic->regs.smsiaddrcfgh;
        return 0;

    case APLIC_SETIPNUM:
    case APLIC_CLRIPNUM:
    case APLIC_SETIENUM:
        *out = 0;
        return 0;

    case APLIC_SETIP_BASE ... APLIC_SETIP_LAST:
        *out = APLIC_REG_GET(priv->regs, addr - priv->paddr_start)
                & vaplic->auth_irq_bmp[offset - APLIC_SETIP_BASE];
        break;

    case APLIC_CLRIP_BASE ... APLIC_CLRIP_LAST:
        *out = APLIC_REG_GET(priv->regs, addr - priv->paddr_start)
                & vaplic->auth_irq_bmp[offset - APLIC_CLRIP_BASE];
        break;

    case APLIC_SETIE_BASE ... APLIC_SETIE_LAST:
        *out = APLIC_REG_GET(priv->regs, addr - priv->paddr_start)
                & vaplic->auth_irq_bmp[offset - APLIC_SETIE_BASE];
        break;

    case APLIC_CLRIE_BASE ... APLIC_CLRIE_LAST:
        *out = APLIC_REG_GET(priv->regs, addr - priv->paddr_start)
                & vaplic->auth_irq_bmp[offset - APLIC_CLRIE_BASE];
        break;

    case APLIC_TARGET_BASE ... APLIC_TARGET_LAST:
        *out = APLIC_REG_GET(priv->regs, addr - priv->paddr_start)
                & vaplic->auth_irq_bmp[offset - APLIC_CLRIE_BASE];
        break;
    }

    *out = APLIC_REG_GET(priv->regs, addr - priv->paddr_start);

    return 0;
}

int vaplic_emulate_store(struct vcpu *vcpu, unsigned long addr, uint32_t value)
{
    uint32_t tmp_val;
    uint32_t index, shift;
    struct vcpu *target_vcpu = vcpu;
    struct vaplic *vaplic = to_vaplic(vcpu->arch.vgic);
    struct aplic_priv *priv = vaplic->base.info->private;
    uint32_t offset = addr & APLIC_REG_OFFSET_MASK;
    unsigned long aplic_addr = addr - priv->paddr_start;

    switch ( offset )
    {
    case APLIC_SETIP_BASE ... APLIC_SETIP_LAST:
        index = (offset - APLIC_SETIP_LAST) / 4;
        tmp_val = APLIC_REG_GET(priv->regs, aplic_addr) & ~vaplic->auth_irq_bmp[index];
        value &= vaplic->auth_irq_bmp[index];
        value |= tmp_val;
        break;

    case APLIC_CLRIP_BASE ... APLIC_CLRIP_LAST:
        index = (offset - APLIC_CLRIP_BASE) / 4;
        tmp_val = APLIC_REG_GET(priv->regs, aplic_addr) & ~vaplic->auth_irq_bmp[index];
        value &= vaplic->auth_irq_bmp[index];
        value |= tmp_val;
        break;

    case APLIC_SETIE_BASE ... APLIC_SETIE_LAST:
        index = (offset - APLIC_SETIE_BASE) / 4;
        tmp_val = APLIC_REG_GET(priv->regs, aplic_addr) & ~vaplic->auth_irq_bmp[index];
        value &= vaplic->auth_irq_bmp[index];
        value |= tmp_val;
        break;

    case APLIC_CLRIE_BASE ... APLIC_CLRIE_LAST:
        index = (offset - APLIC_CLRIE_BASE) / 4;
        tmp_val = APLIC_REG_GET(priv->regs, aplic_addr) & ~vaplic->auth_irq_bmp[index];
        value &= vaplic->auth_irq_bmp[index];
        value |= tmp_val;
        break;

    case APLIC_SOURCECFG_BASE ... APLIC_SOURCECFG_LAST:
        index = (offset - APLIC_DOMAINCFG) / 128;
        shift = (((offset - APLIC_DOMAINCFG) / 4) % 32);

        /* TODO: why do we need such if/else???? Can't we just invert statement and drop break? */
        if ( vaplic->auth_irq_bmp[index] & (1 << shift) )
            break;
        else
            /* interrupt not enabled, ignore it */
            return 0;

        break;

    case APLIC_TARGET_BASE ... APLIC_TARGET_LAST:
        index = (offset - APLIC_GENMSI) / 4;

        if ( !(vaplic->auth_irq_bmp[index / 32] & (1 << index)) )
            /* interrupt not enabled, ignore it */
            return 0;

        for ( int idx = 0; idx < vcpu->domain->max_vcpus; idx++ )
        {
            if ( vcpu->domain->vcpu[idx]->vcpu_id == (value) >> APLIC_TARGET_HART_IDX_SHIFT )
            {
                target_vcpu = vcpu->domain->vcpu[idx];
                break;
            }
        }

        vaplic_update_target(
            priv->imsic_cfg, 
            vaplic->guest_file_id,
            cpu_physical_id(target_vcpu->processor),
            &value);

        break;

    case APLIC_SETIPNUM:
    case APLIC_CLRIPNUM:
    case APLIC_SETIENUM:
        if ( vaplic->auth_irq_bmp[value / 32] & (1 << (value % 32)) )
            break;

        return 0;

    case APLIC_DOMAINCFG:
        /* nothing to do, domaincfg is set by aplic during initialization */
        vaplic->regs.domaincfg = value;
        return 0;

    case APLIC_SMSICFGADDR:
        vaplic->regs.smsiaddrcfg = value;
        return 0;

    case APLIC_SMSICFGADDRH:
        vaplic->regs.smsiaddrcfgh = value;
        return 0;
    }

    APLIC_REG_SET(priv->regs, aplic_addr, value);

    return 0;
}

struct vaplic* vaplic_alloc(struct vcpu *vcpu)
{
    struct vaplic *v;

    v = xzalloc(struct vaplic);
    if ( !v )
        return NULL;
        
    v->base.emulate_load = vaplic_emulate_load;
    v->base.emulate_store = vaplic_emulate_store;
    v->base.is_access = vaplic_is_access;
    v->auth_irq_bmp = vcpu->domain->arch.auth_irq_bmp;

    if ( vcpu->domain->domain_id != DOMID_IDLE )
    {
        v->guest_file_id = imsic_get_guest_interrupt_file(vcpu->domain);
        if ( v->guest_file_id > 0 )
        {
            vcpu->arch.hgeie = 1 << v->guest_file_id;
            vcpu->arch.hstatus |= v->guest_file_id << HSTATUS_VGEIN_SHIFT;
            printk(XENLOG_INFO "assigns guest interrupts file %d for domain %u and vcpu %u\n", 
                v->guest_file_id, vcpu->domain->domain_id, vcpu->vcpu_id);
        }
        else
            printk(XENLOG_ERR "unable to get guest interrupts file for domain %u and vpcu %u\n", 
                vcpu->domain->domain_id, vcpu->vcpu_id);
    }

    return v;
}

void vaplic_free(struct vaplic *v)
{
    xfree(v);
}
