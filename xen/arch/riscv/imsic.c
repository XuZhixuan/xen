/* SPDX-License-Identifier: MIT */
/*
 * xen/arch/riscv/imsic.c
 *
 * RISC-V Incoming MSI Controller support
 *
 * (c) 2024 Microchip Technology Inc.
 *
 */

#include <xen/bitmap.h>
#include <xen/bitops.h>
#include <xen/cpumask.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/iocap.h>
#include <xen/lib.h>
#include <xen/libfdt/libfdt.h>
#include <xen/percpu.h>
#include <xen/sched.h>
#include <xen/spinlock.h>
#include <xen/vmap.h>

#include <asm/imsic.h>

#define IMSIC_DISABLE_EIDELIVERY    0
#define IMSIC_ENABLE_EIDELIVERY     1
#define IMSIC_DISABLE_EITHRESHOLD   1
#define IMSIC_ENABLE_EITHRESHOLD    0

#define imsic_csr_write(c, v)   \
do {                            \
    csr_write(CSR_SISELECT, c); \
    csr_write(CSR_SIREG, v);    \
} while (0)

#define imsic_csr_read(c)       \
({                              \
    unsigned long v;            \
    csr_write(CSR_SISELECT, c); \
    v = csr_read(CSR_SIREG);    \
    v;                          \
})

#define imsic_csr_set(c, v)     \
do {                            \
    csr_write(CSR_SISELECT, c); \
    csr_set(CSR_SIREG, v);      \
} while (0)

#define imsic_csr_clear(c, v)   \
do {                            \
    csr_write(CSR_SISELECT, c); \
    csr_clear(CSR_SIREG, v);    \
} while (0)

extern int riscv_of_processor_hartid(struct dt_device_node *node, unsigned long *hart);

struct imsic_config imsic_cfg;
static spinlock_t pool_lock;
static int domain_id_pool[IMSIC_GEILEN] = {[0 ... IMSIC_GEILEN-1] = -1};

static int __init imsic_get_parent_hartid(struct dt_device_node *node,
                      uint32_t index, unsigned long *hartid)
{
    int res;
    unsigned long hart;
    struct dt_phandle_args args;

    /* Try the new-style interrupts-extended first */
    res = dt_parse_phandle_with_args(node, "interrupts-extended",
                                     "#interrupt-cells", index, &args);
    if ( !res )
    {
        res = riscv_of_processor_hartid(args.np->parent, &hart);
        if ( res < 0 ) {
            return -EINVAL;
        }
        *hartid = hart;
    }
    return res;
}

int imsic_register_domain(const struct domain *d)
{
    spin_lock(&pool_lock);

    for( int i = 0; i < IMSIC_GEILEN; i++)
    {
        if ( domain_id_pool[i] == -1 )
        {
            domain_id_pool[i] = d->domain_id;
            spin_unlock(&pool_lock);
            return 0;
        } 
    }

    spin_unlock(&pool_lock);

    return -ENODEV;
}

int imsic_get_guest_interrupt_file(const struct domain *d)
{
    spin_lock(&pool_lock);

    for( int i = 0; i < IMSIC_GEILEN; i++ )
    {
        if ( domain_id_pool[i] == d->domain_id )
        {
            spin_unlock(&pool_lock);
            return i + 1;
        }
    }

    spin_unlock(&pool_lock);

    return -ENODEV;
}

int imsic_unregister_domain(const struct domain *d)
{
    spin_lock(&pool_lock);

    for ( int i = 0; i < IMSIC_GEILEN; i++ )
    {
        if ( domain_id_pool[i] == d->domain_id )
        {
            domain_id_pool[i] = -1;
            spin_unlock(&pool_lock);
            return 0;
        } 
    }

    spin_unlock(&pool_lock);

    return -ENODEV;
}

const struct imsic_config *imsic_get_config(void)
{
    return (const struct imsic_config*) &imsic_cfg;
}

int imsic_iomem_deny_access(struct domain *d)
{
    int res;
    uint32_t cpu;
    uint64_t guest_offset = imsic_get_guest_interrupt_file(d) * IMSIC_MMIO_PAGE_SZ;          

    for ( cpu = 0; cpu < d->max_vcpus; cpu++ )
    {
        uint64_t hart_id = cpu_physical_id(d->vcpu[cpu]->processor);
        paddr_t paddr = imsic_cfg.msi[hart_id].base_addr + 
            imsic_cfg.msi[hart_id].offset + guest_offset;
        vaddr_t vaddr = imsic_cfg.base_addr + (IMSIC_MMIO_PAGE_SZ * cpu) ;

        res = iomem_permit_access(d, paddr_to_pfn(paddr),
                                  paddr_to_pfn(PAGE_ALIGN(paddr + IMSIC_MMIO_PAGE_SZ - 1)));
        if ( res )
        {
            printk(XENLOG_ERR "Unable to permit to dom%d access to"
                " 0x%"PRIpaddr" - 0x%"PRIpaddr"\n",
                d->domain_id, paddr & PAGE_MASK, PAGE_ALIGN(paddr + IMSIC_MMIO_PAGE_SZ - 1));
            return res;
        }
        
        res = guest_physmap_add_entry(d,
            gaddr_to_gfn(vaddr),
            maddr_to_mfn(paddr),
            get_order_from_bytes(IMSIC_MMIO_PAGE_SZ),
            p2m_mmio_direct_c);
        if ( res < 0 )
        {
            printk(XENLOG_ERR
                   "Failed to map %"PRIpaddr" to the guest at%"PRIpaddr"\n",
                   paddr, vaddr);
            return -EFAULT;
        }
    }

    return 0;
}

static int imsic_make_reg_property(
                    struct domain *d, 
                    void *fdt, 
                    const struct dt_device_node *imsic_node)
{
    __be32 regs[4];

    regs[0] = __cpu_to_be32(imsic_cfg.base_addr >> 32);
    regs[1] = __cpu_to_be32(imsic_cfg.base_addr);
    regs[2] = __cpu_to_be32((IMSIC_MMIO_PAGE_SZ * d->max_vcpus) >> 32);
    regs[3] = __cpu_to_be32(IMSIC_MMIO_PAGE_SZ * d->max_vcpus);

    return fdt_property(fdt, "reg", regs, sizeof(regs));
}

static int imsic_set_interrupt_extended_prop(struct domain *d, void *fdt)
{
    uint32_t len = 0, pos = 0, cpu, phandle, irq_ext[NR_CPUS*2];
    char buf[64];

    for ( cpu = 0; cpu < d->max_vcpus; cpu++ )
    {
        snprintf(buf, sizeof(buf), "/cpus/cpu@%u/interrupt-controller", cpu);
        phandle = fdt_get_phandle(fdt, fdt_path_offset(fdt, buf));
        if (phandle  <= 0)
            return phandle;

        irq_ext[pos++] = cpu_to_be32(phandle);
        len += sizeof(uint32_t);
        irq_ext[pos++] = cpu_to_be32(IRQ_S_EXT);
        len += sizeof(uint32_t);
    }

    return fdt_property(fdt, "interrupts-extended", (void*)irq_ext, len);  
}

int imsic_make_dt_node(struct domain *d, void *fdt, const struct dt_device_node *imsic_node)
{
    uint32_t len;
    const void *data = NULL;
    int res = 0;

    res = fdt_begin_node(fdt, imsic_node->full_name);
    if ( res )
        return res;

    data = dt_get_property(imsic_node, "compatible", &len);
    if ( !data )
    {
        printk(XENLOG_ERR "%s: Can't find 'compatible' property\n", imsic_node->full_name);
        return -ENOENT;
    }

    res = fdt_property(fdt, "compatible", data, len);
    if ( res )
        return res;

    res = imsic_make_reg_property(d, fdt, imsic_node);
    if ( res )
        return res;

    res = imsic_set_interrupt_extended_prop(d, fdt);
    if ( res )
        return res;

    data = dt_get_property(imsic_node, "riscv,num-ids", &len);
    if ( !data )
    {
        printk(XENLOG_ERR "%s: Can't find 'riscv,num-ids' property\n", imsic_node->full_name);
        return -ENOENT;
    }

    res = fdt_property(fdt, "riscv,num-ids", data, len);
    if ( res )
        return res;

    data = dt_get_property(imsic_node, "riscv,hart-index-bits", &len);
    if ( data )
    {
        res = fdt_property(fdt, "riscv,hart-index-bits", data, len);
        if ( res )
            return res;
    }

    res = fdt_property(fdt, "msi-controller", NULL, 0);
    if ( res )
        return res;

    res = fdt_property_u32(fdt, "#msi-cells", 0);
    if ( res )
        return res;

    res = fdt_property(fdt, "interrupt-controller", NULL, 0);
    if ( res )
        return res;

    data = dt_get_property(imsic_node, "#interrupt-cells", &len);
    if ( !data )
    {
        printk(XENLOG_ERR "%s: Can't find '#interrupt-cells' property\n", imsic_node->full_name);
        return -ENOENT;
    }

    res = fdt_property(fdt, "#interrupt-cells", data, len);
    if ( res )
        return res;

    res = fdt_generate_phandle(fdt, &imsic_cfg.phandle);
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "phandle", imsic_cfg.phandle);
    if ( res )
            return res;

    return fdt_end_node(fdt);
}

int imsic_parse_node(struct dt_device_node *node,
                     uint32_t *nr_parent_irqs)
{
    int rc; 
    uint32_t tmp;
    paddr_t base_addr;

    /* Find number of parent interrupts */
    *nr_parent_irqs = dt_number_of_irq(node);
    if ( !*nr_parent_irqs )
    {
        printk(XENLOG_ERR "%s: no parent irqs available\n", node->name);
        return -ENOENT;
    }

    /* Find number of guest index bits in MSI address */
    rc = dt_property_read_u32(node, "riscv,guest-index-bits",
                  &imsic_cfg.guest_index_bits);
    if ( !rc )
        imsic_cfg.guest_index_bits = 0;
    tmp = BITS_PER_LONG - IMSIC_MMIO_PAGE_SHIFT;
    if ( tmp < imsic_cfg.guest_index_bits )
    {
        printk(XENLOG_ERR "%s: guest index bits too big\n", node->name);
        return -ENOENT;
    }

    /* Find number of HART index bits */
    rc = dt_property_read_u32(node, "riscv,hart-index-bits",
                  &imsic_cfg.hart_index_bits);
    if ( !rc )
    {
        /* Assume default value */
        imsic_cfg.hart_index_bits = fls(*nr_parent_irqs);
        if ( BIT(imsic_cfg.hart_index_bits, UL) < *nr_parent_irqs )
            imsic_cfg.hart_index_bits++;
    }
    tmp = BITS_PER_LONG - IMSIC_MMIO_PAGE_SHIFT -
          imsic_cfg.guest_index_bits;
    if ( tmp < imsic_cfg.hart_index_bits )
    {
        printk(XENLOG_ERR "%s: HART index bits too big\n", node->name);
        return -ENOENT;
    }

    /* Find number of group index bits */
    rc = dt_property_read_u32(node, "riscv,group-index-bits",
                  &imsic_cfg.group_index_bits);
    if ( !rc )
        imsic_cfg.group_index_bits = 0;
    tmp = BITS_PER_LONG - IMSIC_MMIO_PAGE_SHIFT -
          imsic_cfg.guest_index_bits - imsic_cfg.hart_index_bits;
    if ( tmp < imsic_cfg.group_index_bits )
    {
        printk(XENLOG_ERR "%s: group index bits too big\n", node->name);
        return -ENOENT;
    }

    /* Find first bit position of group index */
    tmp = IMSIC_MMIO_PAGE_SHIFT * 2;
    rc = dt_property_read_u32(node, "riscv,group-index-shift",
                  &imsic_cfg.group_index_shift);
    if ( !rc )
        imsic_cfg.group_index_shift = tmp;

    if ( imsic_cfg.group_index_shift < tmp )
    {
        printk(XENLOG_ERR "%s: group index shift too small\n", node->name);
        return -ENOENT;
    }

    tmp = imsic_cfg.group_index_bits + imsic_cfg.group_index_shift - 1;
    if ( tmp >= BITS_PER_LONG )
    {
        printk(XENLOG_ERR "%s: group index shift too big\n", node->name);
        return -EINVAL;
    }

    /* Find number of interrupt identities */
    rc = dt_property_read_u32(node, "riscv,num-ids", &imsic_cfg.nr_ids);
    if ( !rc )
    {
        printk(XENLOG_ERR "%s: number of interrupt identities not found\n",
            node->name);
        return -ENOENT;
    }

    if ( (imsic_cfg.nr_ids < IMSIC_MIN_ID) ||
         (imsic_cfg.nr_ids >= IMSIC_MAX_ID) ||
         ((imsic_cfg.nr_ids & IMSIC_MIN_ID) != IMSIC_MIN_ID) )
    {
        printk(XENLOG_ERR "%s: invalid number of interrupt identities\n",
            node->name);
        return -EINVAL;
    }

    /* Compute base address */
    imsic_cfg.nr_mmios = 0;
    rc = dt_device_get_address(node, imsic_cfg.nr_mmios, &base_addr, NULL);
    if (rc)
    {
        printk(XENLOG_ERR "%s: first MMIO resource not found\n", node->name);
        return -EINVAL;
    }

    imsic_cfg.base_addr = base_addr;
    imsic_cfg.base_addr &= ~(BIT(imsic_cfg.guest_index_bits +
                   imsic_cfg.hart_index_bits +
                   IMSIC_MMIO_PAGE_SHIFT, UL) - 1);
    imsic_cfg.base_addr &= ~((BIT(imsic_cfg.group_index_bits, UL) - 1) <<
                   imsic_cfg.group_index_shift);

    /* Find number of MMIO register sets */
    imsic_cfg.nr_mmios++;
    while ( !dt_device_get_address(node, imsic_cfg.nr_mmios, &base_addr, NULL) )
        imsic_cfg.nr_mmios++;
    return 0;
}

int __init imsic_init(struct dt_device_node *node)
{
    int rc;
    unsigned long reloff, hartid;
    uint32_t nr_parent_irqs, index, nr_handlers = 0;
    paddr_t base_addr;

    spin_lock_init(&pool_lock);
   
    /* Parse IMSIC node */
    rc = imsic_parse_node(node, &nr_parent_irqs);
    if ( rc )
        return rc;

    /* Allocate MMIO resource array */
    imsic_cfg.mmios = xzalloc_array(struct imsic_mmios, imsic_cfg.nr_mmios);
    if ( !imsic_cfg.mmios )
        return -ENOMEM;

    /* check MMIO register sets */
    for ( int i = 0; i < imsic_cfg.nr_mmios; i++ )
    {
        rc = dt_device_get_address(node, i, &imsic_cfg.mmios[i].base_addr, &imsic_cfg.mmios[i].size);
        if ( rc )
        {
            printk(XENLOG_ERR "%s:  unable to parse MMIO regset %d\n", 
                node->name, i);
            goto imsic_init_err;
        }

        base_addr = imsic_cfg.mmios[i].base_addr;
        base_addr &= ~(BIT(imsic_cfg.guest_index_bits +
                   imsic_cfg.hart_index_bits +
                   IMSIC_MMIO_PAGE_SHIFT, UL) - 1);
        base_addr &= ~((BIT(imsic_cfg.group_index_bits, UL) - 1) <<
                   imsic_cfg.group_index_shift);
        if (base_addr != imsic_cfg.base_addr)
        {
            rc = -EINVAL;
            printk(XENLOG_ERR "%s: address mismatch for regset %d\n", 
                node->name, i);
            goto imsic_init_err;
        }
    }

    /* Configure handlers for target CPUs */
    for ( int i = 0; i < nr_parent_irqs; i++)
    {
        rc = imsic_get_parent_hartid(node, i, &hartid);
        if ( rc )
        {
            printk(XENLOG_WARNING "%s: hart ID for parent irq%d not found\n",
                node->name, i);
            continue;
        }

        if ( hartid > NR_CPUS )
        {
            printk(XENLOG_WARNING "%s: unsupported hart ID=%lu for parent irq%d\n",
                node->name, hartid, i);
            continue;
        }

        /* Find MMIO location of MSI page */
        index = imsic_cfg.nr_mmios;
        reloff = i * BIT(imsic_cfg.guest_index_bits, UL) * IMSIC_MMIO_PAGE_SZ;
        for (int j = 0; imsic_cfg.nr_mmios; j++)
        {
            if ( reloff < imsic_cfg.mmios[j].size )
            {
                index = j;
                break;
            }

            /*
             * MMIO region size may not be aligned to
             * BIT(global->guest_index_bits) * IMSIC_MMIO_PAGE_SZ
             * if holes are present.
             */
            reloff -= ROUNDUP(imsic_cfg.mmios[j].size,
                BIT(imsic_cfg.guest_index_bits, UL) * IMSIC_MMIO_PAGE_SZ);
        }

        if ( index >= imsic_cfg.nr_mmios )
        {
            printk(XENLOG_WARNING "%s: MMIO not found for parent irq%d\n",
                node->name, i);
            continue;
        }

        if ( !IS_ALIGNED(imsic_cfg.msi[hartid].base_addr + reloff, PAGE_SIZE) )
        {
            printk(XENLOG_WARNING "%s: MMIO address 0x%lx is not aligned on a page\n",
                node->name, imsic_cfg.msi[hartid].base_addr + reloff);
            imsic_cfg.msi[hartid].offset = 0;
            imsic_cfg.msi[hartid].base_addr = 0;
            continue;
        }

        imsic_cfg.mmios[index].harts[hartid] = true;
        imsic_cfg.msi[hartid].base_addr = imsic_cfg.mmios[index].base_addr;
        imsic_cfg.msi[hartid].offset = reloff;
        nr_handlers++;
    }

    if ( !nr_handlers )
    {
        printk(XENLOG_ERR "%s: No CPU handlers found\n", node->name);
		rc = -ENODEV;
        goto imsic_init_err;
	}

    return 0;

imsic_init_err:
    xfree(imsic_cfg.mmios);

    return rc;
}
