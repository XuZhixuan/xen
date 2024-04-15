/* SPDX-License-Identifier: MIT
 * Copyright (C) 2024 Microchip
 *
 * This driver currently supports:
 *	- Single stage translation (Only G-STAGE no VS-STAGE)
 *    with multiple device ids per master
 *
 * This drivers does not support
 *  - MSI_FLAT, MSI_MRIF
 *  - AMO
 *  - END (big endian)
 *  - PDT (Process Directory Table)
 *  - Master protected by more than one IOMMU
 *
 * NOT YET IMPLEMENTED:
 *  - Two-stage address translation
 *  - PCIe support
 *  - Performance monitoring counters
 */

#include <xen/device_tree.h>
#include <xen/err.h>
#include <xen/iommu.h>
#include <xen/lib.h>
#include <xen/list.h>
#include <xen/param.h>
#include <xen/sched.h>
#include <xen/vmap.h>

#include <asm/delay.h>
#include <asm/iommu.h>
#include <asm/iommu_fwspec.h>
#include <asm/irq.h>

#define GET_DC_ID(i) ((uint32_t) (master->dids[i] >> 32))
#define GET_TC_OPTS(i) ((uint32_t) master->dids[i])

/* Order of the queue size (default 0 -> 4kiB) */
#define CQ_ORDER CONFIG_IOMMU_CQ_ORDER
#define FQ_ORDER CONFIG_IOMMU_FQ_ORDER
#define PQ_ORDER CONFIG_IOMMU_FQ_ORDER

/* RISC-V IOMMU PPN <> PHYS address conversions, PPN[53:10] */
#define RISCV_IOMMU_PPN_FIELD GENMASK_ULL(53, 10)
#define iommu_ddt_phys_to_ppn(phys)                                            \
    (((phys >> PAGE_SHIFT) << 10) & RISCV_IOMMU_PPN_FIELD)
#define iommu_ddt_ppn_to_phys(ppn)                                             \
    (((ppn & RISCV_IOMMU_PPN_FIELD) >> 10) << PAGE_SHIFT)

/*
 * 'ddt mode' parameter
 * By default, device ID is up to 24 bits (three level table)
 */
static unsigned int __initdata ddt_mode = RISCV_IOMMU_DDTP_MODE_3LVL;
integer_param("ddt_mode", ddt_mode);

/* Keep a list of devices associated with this driver */
static DEFINE_SPINLOCK(riscv_iommu_devices_lock);
static LIST_HEAD(riscv_iommu_devices);

/* device directory table definition table */
struct riscv_iommu_ddt_level
{
    unsigned int bshift;
    unsigned int bwidth;
};

/* Three, two and single-level device directory with base format DC */
static const struct riscv_iommu_ddt_level level_base[] = {
    /* DDI[0] */
    {.bshift = 0, .bwidth = 7},
    /* DDI[1] */
    {.bshift = 7, .bwidth = 9},
    /* DDI[2] */
    {.bshift = 16, .bwidth = 8},
};
/* Three, two and single-level device directory with extended format DC */
static const struct riscv_iommu_ddt_level level_ext[] = {
    /* DDI[0] */
    {.bshift = 0, .bwidth = 6},
    /* DDI[1] */
    {.bshift = 6, .bwidth = 9},
    /* DDI[2] */
    {.bshift = 15, .bwidth = 9},
};

/* d: device, l: level, ls: levels, dc: device context size */
#define DDT_MAX_DEVID(l, ls) BIT(ls[l].bshift + ls[l].bwidth, U)
#define DDT_DEVID(d, l, ls)                                                    \
    ((((d) >> (ls)[(l)].bshift) & ((1U << (ls)[(l)].bwidth) - 1U)))
#define DDT_NL_OFFSET(d, l, ls) (DDT_DEVID(d, l, ls) * 8)
#define DDT_DC_OFFSET(d, l, ls, dc) (DDT_DEVID(d, l, ls) * ((dc) ? 64 : 32))

#ifdef CONFIG_IOMMU_DEBUG
static void riscv_iommu_print_dc(void *ddtp, unsigned int level, bool dc,
                                 unsigned int devid, unsigned int tab)
{
    char *tabulation[3] = {"", "  ", "    "};
    const struct riscv_iommu_ddt_level *levels = dc ? level_ext : level_base;
    unsigned int idx = 0;
    unsigned int tmp_devid;

    for ( unsigned int i = 0; i < BIT(levels[level].bwidth, U); i++ )
    {
        if ( level == 0 )
        {
            unsigned long *ptr = ddtp;
            if ( *ptr & RISCV_IOMMU_DDTE_VALID )
            {
                tmp_devid = devid + (idx << levels[level].bshift);
                printk("%sLEAF devid=[%u - 0x%x] va=%p pa=%p\n",
                       tabulation[tab], tmp_devid, tmp_devid, ptr,
                       (void *) _virt_to_maddr(ptr));
                printk("%s%sDevice Context[%lx][%lx][%lx][%lx]\n",
                       tabulation[tab], tabulation[tab], ptr[0], ptr[1], ptr[2],
                       ptr[3]);
            }
            ddtp = ptr + (dc ? 8 : 4);
            idx++;
        }
        else
        {
            unsigned long *ptr = ddtp;
            if ( *ptr & RISCV_IOMMU_DDTE_VALID )
            {
                void *addr =
                    (void *) _maddr_to_virt(iommu_ddt_ppn_to_phys(*ptr));
                tmp_devid = devid + (idx << levels[level].bshift);
                printk("%sLEVEL=%u ENTRY=%d pte=%p pa=%llx va=%p\n",
                       tabulation[tab], level, idx, (void *) *ptr,
                       iommu_ddt_ppn_to_phys(*ptr), addr);
                riscv_iommu_print_dc(addr, level - 1, dc, tmp_devid, tab + 1);
            }
            ddtp += 8;
            idx++;
        }
    }
}

static void riscv_iommu_dump_dc(struct riscv_iommu_device *iommu_dev)
{
    printk("\n-------- IOMMU DDT (%s) DUMP START --------\n",
           dev_name(iommu_dev->dev));
    riscv_iommu_print_dc(iommu_dev->ddtp, iommu_dev->level,
                         iommu_dev->extended_dc, 0, 0);
    printk("-------- IOMMU DDT (%s) DUMP END --------\n\n",
           dev_name(iommu_dev->dev));
}
#endif /* CONFIG_IOMMU_DEBUG */

static struct riscv_iommu_domain *to_iommu_domain(struct iommu_domain *dom)
{
    return container_of(dom, struct riscv_iommu_domain, domain);
}

static void riscv_iommu_priv_set(struct device *dev, void *priv)
{
    struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);
    fwspec->iommu_priv = priv;
}

static void *riscv_iommu_priv_get(struct device *dev)
{
    struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);
    return fwspec && fwspec->iommu_priv ? fwspec->iommu_priv : NULL;
}

static struct riscv_iommu_device *
riscv_iommu_get_by_dev(const struct device *dev)
{
    struct riscv_iommu_device *iommu_dev = NULL;

    spin_lock(&riscv_iommu_devices_lock);
    list_for_each_entry(iommu_dev, &riscv_iommu_devices, devices)
    {
        if ( iommu_dev->dev == dev )
        {
            spin_unlock(&riscv_iommu_devices_lock);
            return iommu_dev;
        }
    }
    spin_unlock(&riscv_iommu_devices_lock);
    return NULL;
}

static int riscv_iommu_wait_ddtp_ready(struct riscv_iommu_device *iommu_dev)
{
    s_time_t deadline = NOW() + MILLISECS(1000);

    while ( iommu_read64(iommu_dev, RISCV_IOMMU_REG_DDTP) &
            RISCV_IOMMU_DDTP_BUSY )
    {
        if ( NOW() > deadline )
        {
            dev_err(iommu_dev->dev, "DDTP not ready\n");
            return -EBUSY;
        }
        cpu_relax();
        udelay(1);
    }
    return 0;
}

static int riscv_iommu_xen_domain_init(struct domain *d)
{
    struct riscv_iommu_xen_domain *xen_domain;

    xen_domain = xzalloc(struct riscv_iommu_xen_domain);
    if ( !xen_domain )
    {
        return -ENOMEM;
    }

    spin_lock_init(&xen_domain->lock);
    INIT_LIST_HEAD(&xen_domain->contexts);

    dom_iommu(d)->arch.priv = xen_domain;

    return 0;
}

static struct iommu_domain *riscv_iommu_domain_alloc(void)
{
    struct riscv_iommu_domain *iommu_domain;

    /*
     * Allocate the domain and initialise some of its data structures.
     * We can't really do anything meaningful until we've added a
     * master.
     */
    iommu_domain = xzalloc(struct riscv_iommu_domain);
    if ( !iommu_domain )
        return NULL;

    INIT_LIST_HEAD(&iommu_domain->devices);
    spin_lock_init(&iommu_domain->iommu_lock);
    spin_lock_init(&iommu_domain->devices_lock);

    return &iommu_domain->domain;
}

static struct iommu_domain *riscv_iommu_get_domain(struct domain *d,
                                                   struct device *dev)
{
    struct iommu_domain *io_domain;
    struct riscv_iommu_domain *iommu_domain;
    struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);
    struct riscv_iommu_xen_domain *xen_domain = dom_iommu(d)->arch.priv;
    struct riscv_iommu_device *iommu_dev =
        riscv_iommu_get_by_dev(fwspec->iommu_dev);

    if ( !iommu_dev )
        return NULL;

    /*
     * Loop through the &xen_domain->contexts to locate a context
     * assigned to this IOMMU
     */
    list_for_each_entry(io_domain, &xen_domain->contexts, list)
    {
        iommu_domain = to_iommu_domain(io_domain);
        if ( iommu_domain->iommu_dev == iommu_dev )
            return io_domain;
    }

    return NULL;
}

static struct riscv_iommu_dc *
riscv_iommu_get_dc(struct riscv_iommu_device *iommu_dev, unsigned int device_id)
{
    const struct riscv_iommu_ddt_level *levels =
        iommu_dev->extended_dc ? level_ext : level_base;
    unsigned int level = iommu_dev->level;
    void *ddtp = iommu_dev->ddtp;

    /* check device ID */
    if ( device_id >= DDT_MAX_DEVID(level, levels) )
    {
        dev_err(iommu_dev->dev, "device ID %u too big for %u level%s DDT\n",
                device_id, level + 1, level ? "s" : "");
        return NULL;
    }

    /* walk through non leaf levels */
    while ( level )
    {
        unsigned long *ddte = ddtp + DDT_NL_OFFSET(device_id, level, levels);
        if ( *ddte & RISCV_IOMMU_DDTE_VALID )
        {
            ddtp =
                (unsigned long *) _maddr_to_virt(iommu_ddt_ppn_to_phys(*ddte));
        }
        else
        {
            /* Allocate next device directory level. */
            ddtp = alloc_xenheap_page();
            if ( !ddtp )
            {
                dev_err(iommu_dev->dev,
                        "unable to allocate table for device ID %u\n",
                        device_id);
                return NULL;
            }
            clear_page(ddtp);
            *ddte = iommu_ddt_phys_to_ppn(_virt_to_maddr(ddtp)) |
                    RISCV_IOMMU_DDTE_VALID;
        }
        level--;
    }

    /* walk through the leaf page table */
    ddtp += DDT_DC_OFFSET(device_id, level, levels, iommu_dev->extended_dc);
    return (struct riscv_iommu_dc *) ddtp;
}

static int riscv_iommu_post(struct riscv_iommu_device *iommu_dev,
                            struct riscv_iommu_command *cmd)
{
    uint32_t head, tail, next;
    unsigned long flags;

    spin_lock_irqsave(&iommu_dev->hw.cmd_queue.lock, flags);
    head = iommu_read32(iommu_dev, RISCV_IOMMU_REG_CQH) &
           iommu_dev->hw.cmd_queue.mask;
    tail = iommu_read32(iommu_dev, RISCV_IOMMU_REG_CQT) &
           iommu_dev->hw.cmd_queue.mask;

    if ( tail == head - 1 )
    {
        /* command queue is full */
        return -ENOBUFS;
    }
    next = (tail + 1) & iommu_dev->hw.cmd_queue.mask;
    if ( next != head )
    {
        memcpy(iommu_dev->hw.cmd_queue.cmd + tail, cmd, sizeof(*cmd));
        iommu_write32(iommu_dev, RISCV_IOMMU_REG_CQT, next);
    }
    spin_unlock_irqrestore(&iommu_dev->hw.cmd_queue.lock, flags);

    return 0;
}

static int riscv_iommu_iodir_inv_devid(struct riscv_iommu_device *iommu_dev,
                                       uint32_t devid)
{
    struct riscv_iommu_command cmd;

    cmd.request =
        FIELD_PREP(RISCV_IOMMU_CMD_MASK_FCT_OP, RISCV_IOMMU_CMD_IODIR) |
        FIELD_PREP(RISCV_IOMMU_IODIR_MASK_DID, devid) |
        RISCV_IOMMU_IODIR_DID_VALID;
    cmd.address = 0;
    return riscv_iommu_post(iommu_dev, &cmd);
}

static int riscv_iommu_iofence_sync(struct riscv_iommu_device *iommu_dev)
{
    struct riscv_iommu_command cmd;

    cmd.request =
        FIELD_PREP(RISCV_IOMMU_CMD_MASK_FCT_OP, RISCV_IOMMU_CMD_IOFENCE_C);
    cmd.address = 0;
    return riscv_iommu_post(iommu_dev, &cmd);
}

static void riscv_iommu_cmd_inval_gvma(struct riscv_iommu_command *cmd)
{
    cmd->request |=
        FIELD_PREP(RISCV_IOMMU_CMD_MASK_FCT_OP, RISCV_IOMMU_CMD_IOTINVAL_GVMA);
    cmd->address = 0;
}

static void riscv_iommu_cmd_inval_set_gscid(struct riscv_iommu_command *cmd,
                                            unsigned int gscid)
{
    if ( gscid != 0 )
        cmd->request |= FIELD_PREP(RISCV_IOMMU_IOTINVAL_MASK_GSCID, gscid) |
                        RISCV_IOMMU_IOTINVAL_GSCID_VALID;
}

static void riscv_iommu_cmd_inval_set_pscid(struct riscv_iommu_command *cmd,
                                            unsigned int pscid)
{
    cmd->request |= FIELD_PREP(RISCV_IOMMU_IOTINVAL_MASK_PSCID, pscid) |
                    RISCV_IOMMU_IOTINVAL_PSCID_VALID;
}

static int riscv_iommu_iotlb_flush_all(struct domain *d)
{
    int ret;
    struct riscv_iommu_command cmd;
    struct iommu_domain *io_domain;
    struct riscv_iommu_xen_domain *xen_domain = dom_iommu(d)->arch.priv;

    /* TODO: implement invalid VMA for VS stage */

    spin_lock(&xen_domain->lock);
    /* invalid GVMA for G-stage */
    riscv_iommu_cmd_inval_gvma(&cmd);
    list_for_each_entry(io_domain, &xen_domain->contexts, list)
    {
        struct riscv_iommu_command cmd;
        struct riscv_iommu_domain *domain = to_iommu_domain(io_domain);
        struct riscv_iommu_device *iommu_dev = domain->iommu_dev;
        /*
         * Only invalidate the context when IOMMU is present.
         * This is because the context initialization is delayed
         * until a master has been added.
         */
        if ( unlikely(!ACCESS_ONCE(iommu_dev)) )
            continue;

        /* prepare the command */
        riscv_iommu_cmd_inval_set_gscid(&cmd, domain->gscid);
        riscv_iommu_cmd_inval_set_pscid(&cmd, 0);

        /* post the command */
        ret = riscv_iommu_post(iommu_dev, &cmd);
        if ( ret )
        {
            spin_unlock(&xen_domain->lock);
            return ret;
        }

        /* be sure the command is executed */
        ret = riscv_iommu_iofence_sync(iommu_dev);
        if ( ret )
        {
            spin_unlock(&xen_domain->lock);
            return ret;
        }
    }
    spin_unlock(&xen_domain->lock);
    return 0;
}

static int riscv_iommu_install_dc_for_dev(struct riscv_iommu_master *master)
{
    int ret;
    struct riscv_iommu_device *iommu_dev = master->iommu_dev;
    struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(master->dev);

    unsigned long hgatp = p2m_get_hostp2m(master->domain->d)->hgatp;

    if ( !master->dc )
    {
        master->dc = xzalloc_array(struct riscv_iommu_dc *, master->num_dids);
        if ( !master->dc )
        {
            return -ENOMEM;
        }
    }

    for ( int i = 0; i < master->num_dids; i++ )
    {
        struct riscv_iommu_dc *dc = riscv_iommu_get_dc(iommu_dev, GET_DC_ID(i));
        if ( !dc )
        {
            dev_err(master->dev, "failed to add device ID=%u-0x%x IOMMU=%s\n",
                    GET_DC_ID(i), GET_DC_ID(i), dev_name(fwspec->iommu_dev));
            return -EINVAL;
        }
        if ( dc->tc & RISCV_IOMMU_DCTC_VALID )
        {
            dev_err(master->dev,
                    "device ID=%u-0x%x already existe for IOMMU=%s\n",
                    GET_DC_ID(i), GET_DC_ID(i), dev_name(fwspec->iommu_dev));
            return -EINVAL;
        }

        dc->tc = RISCV_IOMMU_DCTC_VALID;
        dc->tc = 0;
        if ( iommu_dev->tc_opts )
        {
            if ( GET_TC_OPTS(i) & RISCV_IOMMU_OPTS_TC_DTF )
                dc->tc |= RISCV_IOMMU_DCTC_DTF;
        }

        dc->iohgatp = (hgatp & ~(HGATP64_VMID_MASK)) |
                      ((uint64_t) master->domain->gscid << HGATP64_VMID_SHIFT);
        dc->ta = 0ULL;
        dc->fsc = 0ULL;
        master->dc[i] = dc;

        /* Mark device context as valid */
        wmb();

        /* invalid iommu DDT cache */
        ret = riscv_iommu_iodir_inv_devid(iommu_dev, GET_DC_ID(i));
        if ( ret )
        {
            dev_err(master->dev,
                    "unable to execute IODIR.INVAL_DDT for device ID=%u-0x%x"
                    "IOMMU=%s\n",
                    GET_DC_ID(i), GET_DC_ID(i), dev_name(fwspec->iommu_dev));
            return ret;
        }
        dev_info(master->dev, "add device ID=%u-0x%x IOMMU=%s\n", GET_DC_ID(i),
                 GET_DC_ID(i), dev_name(fwspec->iommu_dev));
    }

#ifdef CONFIG_IOMMU_DEBUG
    riscv_iommu_dump_dc(iommu_dev);
#endif /* CONFIG_IOMMU_DEBUG */

    return 0;
}

static void riscv_iommu_uninstall_dc_for_dev(struct riscv_iommu_master *master)
{
    struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(master->dev);
    struct riscv_iommu_device *iommu_dev = master->iommu_dev;

    for ( int i = 0; i < master->num_dids; i++ )
    {
        if ( master->dc[i] )
        {
            master->dc[i]->tc = 0ULL;
            master->dc[i]->iohgatp = 0ULL;
            master->dc[i]->ta = 0ULL;
            master->dc[i]->fsc = 0ULL;
            if ( iommu_dev->extended_dc )
            {
                master->dc[i]->msiptp = 0ULL;
                master->dc[i]->msi_addr_mask = 0ULL;
                master->dc[i]->msi_addr_pattern = 0ULL;
            }
            master->dc[i] = NULL;

            wmb();

            if ( riscv_iommu_iodir_inv_devid(iommu_dev, GET_DC_ID(i)) )
            {
                /* no error raised, just warns */
                dev_warn(
                    master->dev,
                    "unable to execute IODIR.INVAL_DDT for device ID=%u (%x) "
                    "IOMMU=%s\n",
                    GET_DC_ID(i), GET_DC_ID(i), dev_name(fwspec->iommu_dev));
            }

            dev_info(master->dev, "remove device ID=%u (0x%x) IOMMU=%s\n",
                     GET_DC_ID(i), GET_DC_ID(i), dev_name(fwspec->iommu_dev));
        }
    }

    xfree(master->dc);
    master->dc = NULL;
}

static void riscv_iommu_domain_free(struct iommu_domain *domain)
{
    struct riscv_iommu_domain *iommu_domain = to_iommu_domain(domain);
    xfree(iommu_domain);
}

static int riscv_iommu_domain_finalise(struct iommu_domain *domain,
                                       struct riscv_iommu_master *master)
{
    /* currently nothing to do, maybe remove it if it is never used */
    return 0;
}

static void riscv_iommu_destroy_domain(struct iommu_domain *io_domain)
{
    list_del(&io_domain->list);
    riscv_iommu_domain_free(io_domain);
}

static int riscv_iommu_detach_dev(struct riscv_iommu_master *master)
{
    unsigned long flags;
    struct riscv_iommu_domain *iommu_domain = master->domain;

    if ( !iommu_domain )
        return -EINVAL;

    /* TODO: disable PCI ATS when it will be supported */

    spin_lock_irqsave(&iommu_domain->devices_lock, flags);
    list_del(&master->domain_head);
    spin_unlock_irqrestore(&iommu_domain->devices_lock, flags);

    riscv_iommu_uninstall_dc_for_dev(master);
    return 0;
}

static int riscv_iommu_attach_dev(struct iommu_domain *domain,
                                  struct device *dev)
{
    int ret = 0;
    unsigned long flags;
    struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);
    struct riscv_iommu_device *iommu_dev;
    struct riscv_iommu_domain *iommu_domain = to_iommu_domain(domain);
    struct riscv_iommu_master *master;

    if ( !fwspec )
        return -ENOENT;

    master = riscv_iommu_priv_get(dev);
    if ( master->attached )
    {
        dev_err(dev, "Already attached\n");
        return -EEXIST;
    }

    iommu_dev = master->iommu_dev;

    spin_lock(&iommu_domain->iommu_lock);

    if ( !iommu_domain->iommu_dev )
    {
        iommu_domain->iommu_dev = iommu_dev;

        ret = riscv_iommu_domain_finalise(domain, master);
        if ( ret )
        {
            iommu_domain->iommu_dev = NULL;
            goto out_unlock;
        }
    }
    else if ( iommu_domain->iommu_dev != iommu_dev )
    {
        dev_err(dev, "cannot attach to IOMMU %s (upstream of %s)\n",
                dev_name(iommu_domain->iommu_dev->dev),
                dev_name(iommu_dev->dev));
        ret = -ENXIO;
        goto out_unlock;
    }

    master->domain = iommu_domain;

    /* install device Context */
    ret = riscv_iommu_install_dc_for_dev(master);
    if ( ret )
    {
        riscv_iommu_uninstall_dc_for_dev(master);
        return ret;
    }

    spin_lock_irqsave(&iommu_domain->devices_lock, flags);
    list_add_tail(&master->domain_head, &iommu_domain->devices);
    spin_unlock_irqrestore(&iommu_domain->devices_lock, flags);

    /* TODO: enable PCI ATS when it will be supported */
    master->attached = true;

out_unlock:
    spin_unlock(&iommu_domain->iommu_lock);
    return ret;
}

static int riscv_iommu_assign_dev(struct domain *d, uint8_t devfn,
                                  struct device *dev, uint32_t flag)
{
    int ret = 0;
    struct iommu_domain *io_domain;
    struct riscv_iommu_domain *iommu_domain;
    struct riscv_iommu_xen_domain *xen_domain = dom_iommu(d)->arch.priv;

    spin_lock(&xen_domain->lock);

    /*
     * Check to see if an iommu_domain already exists for this xen domain
     * under the same IOMMU
     */
    io_domain = riscv_iommu_get_domain(d, dev);
    if ( !io_domain )
    {
        io_domain = riscv_iommu_domain_alloc();
        if ( !io_domain )
        {
            ret = -ENOMEM;
            goto out;
        }
        iommu_domain = to_iommu_domain(io_domain);
        iommu_domain->d = d;
        iommu_domain->gscid = d->domain_id + 1;

        /* Chain the new context to the domain */
        list_add(&io_domain->list, &xen_domain->contexts);
    }

    ret = riscv_iommu_attach_dev(io_domain, dev);
    if ( ret )
    {
        if ( io_domain->ref.counter == 0 )
            riscv_iommu_destroy_domain(io_domain);
    }
    else
    {
        atomic_inc(&io_domain->ref);
    }

out:
    spin_unlock(&xen_domain->lock);
    return ret;
}

static int riscv_iommu_add_device(uint8_t devfn, struct device *dev)
{
    struct riscv_iommu_device *iommu_dev;
    struct riscv_iommu_master *master;
    struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);

    if ( !fwspec )
        return -ENODEV;

    iommu_dev = riscv_iommu_get_by_dev(fwspec->iommu_dev);
    if ( !iommu_dev )
        return -ENODEV;

    master = xzalloc(struct riscv_iommu_master);
    if ( !master )
        return -ENOMEM;

    master->dev = dev;
    master->iommu_dev = iommu_dev;
    master->num_dids = fwspec->num_ids;
    master->dids = fwspec->ids;
    if ( dt_device_is_protected(dev_to_dt(dev)) )
    {
        xfree(master);
        dev_err(dev, "Already added to IOMMU\n");
        return -EEXIST;
    }

    riscv_iommu_priv_set(dev, master);

    /* Let Xen know that the master device is protected by an IOMMU. */
    dt_device_set_protected(dev_to_dt(dev));

    return 0;
}

static int riscv_iommu_dt_xlate(struct device *dev,
                                const struct dt_phandle_args *args)
{
    uint64_t ids;
    struct riscv_iommu_device *iommu_dev;
    struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);

    if ( !fwspec )
        return -ENODEV;

    iommu_dev = riscv_iommu_get_by_dev(fwspec->iommu_dev);
    if ( !iommu_dev )
        return -ENODEV;

    if ( iommu_dev->tc_opts )
    {
        /* set the upper 32 bits with the device id and
         * set the lower 32 bits with device translation control options
         */
        ids = ((uint64_t) args->args[0] << 32) + args->args[1];
    }
    else
    {
        /* no device translation control options */
        ids = (uint64_t) args->args[0] << 32;
    }

    return iommu_fwspec_add_ids(dev, &ids, 1);
}

static void riscv_iommu_xen_domain_teardown(struct domain *d)
{
    struct riscv_iommu_xen_domain *xen_domain = dom_iommu(d)->arch.priv;

    ASSERT(list_empty(&xen_domain->contexts));
    xfree(xen_domain);
}

static int __must_check riscv_iommu_iotlb_flush(struct domain *d, dfn_t dfn,
                                                unsigned long page_count,
                                                unsigned int flush_flags)
{
    return riscv_iommu_iotlb_flush_all(d);
}

static int riscv_iommu_deassign_dev(struct domain *d, struct device *dev)
{
    int ret;
    struct iommu_domain *io_domain = riscv_iommu_get_domain(d, dev);
    struct riscv_iommu_xen_domain *xen_domain = dom_iommu(d)->arch.priv;
    struct riscv_iommu_domain *iommu_domain = to_iommu_domain(io_domain);
    struct riscv_iommu_master *master = riscv_iommu_priv_get(dev);

    if ( !iommu_domain || iommu_domain->d != d )
    {
        dev_err(dev, " not attached to domain %d\n", iommu_domain->gscid);
        return -ESRCH;
    }

    spin_lock(&xen_domain->lock);

    ret = riscv_iommu_detach_dev(master);
    atomic_dec(&io_domain->ref);

    if ( io_domain->ref.counter == 0 )
        riscv_iommu_destroy_domain(io_domain);

    xfree(master);

    spin_unlock(&xen_domain->lock);
    return ret;
}

static int riscv_iommu_reassign_dev(struct domain *s, struct domain *t,
                                    uint8_t devfn, struct device *dev)
{
    int ret = 0;

    /* Don't allow remapping on other domain than hwdom */
    if ( t && !is_hardware_domain(t) )
        return -EPERM;

    if ( t == s )
        return 0;

    ret = riscv_iommu_deassign_dev(s, dev);
    if ( ret )
        return ret;

    if ( t )
    {
        /* No flags are defined for RISCV. */
        ret = riscv_iommu_assign_dev(t, devfn, dev, 0);
        if ( ret )
            return ret;
    }

    return 0;
}

static int riscv_iommu_map_page(struct domain *d, dfn_t dfn, mfn_t mfn,
                                unsigned int flags, unsigned int *flush_flags)
{
    panic("%s NOT IMPLEMENTED !!!\n", __func__);
    return 0;
}

static int riscv_iommu_unmap_page(struct domain *d, dfn_t dfn,
                                  unsigned int order, unsigned int *flush_flags)
{
    panic("%s NOT IMPLEMENTED\n", __func__);
    return 0;
}

static const struct iommu_ops riscv_iommu_ops = {
    .page_sizes = PAGE_SIZE_4K,
    .init = riscv_iommu_xen_domain_init,
    .hwdom_init = arch_iommu_hwdom_init,
    .teardown = riscv_iommu_xen_domain_teardown,
    .iotlb_flush = riscv_iommu_iotlb_flush,
    .assign_device = riscv_iommu_assign_dev,
    .reassign_device = riscv_iommu_reassign_dev,
    .map_page = riscv_iommu_map_page,
    .unmap_page = riscv_iommu_unmap_page,
    .dt_xlate = riscv_iommu_dt_xlate,
    .add_device = riscv_iommu_add_device,
};

static int riscv_iommu_custom_init(struct riscv_iommu_device *iommu_dev)
{
    if ( is_sifive_iommu_22(iommu_dev) )
    {
        uint32_t val;

        val = iommu_read32(iommu_dev, RISCV_IOMMU_REG_CUSTOM_VID);
        if ( val != RISCV_IOMMU_CUSTOM_VID_DEFAULT )
        {
            dev_err(iommu_dev->dev, "Wrong IOMMU SiFive Version ID\n");
            return -EINVAL;
        }

        val = FIELD_PREP(RISCV_IOMMU_CUSTOM_TIMEOUT, 4) |
              FIELD_PREP(RISCV_IOMMU_CUSTOM_MPAGE, 0) |
              FIELD_PREP(RISCV_IOMMU_CUSTOM_GPAGE, 0) |
              FIELD_PREP(RISCV_IOMMU_CUSTOM_TPAGE, 0) |
              FIELD_PREP(RISCV_IOMMU_CUSTOM_PPAGE, 0) |
              FIELD_PREP(RISCV_IOMMU_CUSTOM_PTE_DISABLE, 0) |
              FIELD_PREP(RISCV_IOMMU_CUSTOM_CTE_DISABLE, 0) |
              FIELD_PREP(RISCV_IOMMU_CUSTOM_CG_DIS, 1);

        iommu_write32(iommu_dev, RISCV_IOMMU_REG_CUSTOM, val);

        /* Tiled to 0 for IOMMU-22 */
        val = iommu_read32(iommu_dev, RISCV_IOMMU_REG_FCTL);
        if ( FIELD_GET(RISCV_IOMMU_FCTL_GXL, val) )
            return -EINVAL;
    }
    return 0;
}

static void riscv_iommu_custom_uninit(struct riscv_iommu_device *iommu_dev)
{
    if ( is_sifive_iommu_22(iommu_dev) )
        iommu_write32(iommu_dev, RISCV_IOMMU_REG_CUSTOM_VID, 0UL);
}

static int riscv_iommu_wait_xqcsr_at_one(struct riscv_iommu_device *iommu_dev,
                                         uint32_t queue_csr, uint32_t busy_pos)
{
    s_time_t deadline = NOW() + MILLISECS(1000);

    while ( !(iommu_read32(iommu_dev, queue_csr) & busy_pos) )
    {
        if ( NOW() > deadline )
            return -EBUSY;
        cpu_relax();
        udelay(1);
    }
    return 0;
}

static int riscv_iommu_wait_xqcsr_at_zero(struct riscv_iommu_device *iommu_dev,
                                          uint32_t queue_csr, uint32_t busy_pos)
{
    s_time_t deadline = NOW() + MILLISECS(1000);

    while ( iommu_read32(iommu_dev, queue_csr) & busy_pos )
    {
        if ( NOW() > deadline )
            return -EBUSY;
        cpu_relax();
        udelay(1);
    }
    return 0;
}

static int riscv_iommu_enable_cmd_queue(struct riscv_iommu_device *iommu_dev)
{
    void *ptr;
    paddr_t addr;
    size_t logsz_bits, logsz;
    struct riscv_iommu_cmd_queue *queue = &iommu_dev->hw.cmd_queue;

    logsz = PAGE_SHIFT + CQ_ORDER - ilog2(sizeof(struct riscv_iommu_command));

    ptr = alloc_xenheap_pages(CQ_ORDER, 0);
    if ( !ptr )
        return -ENOMEM;

    for ( int i = 0; i < (1 << CQ_ORDER); i++ )
        clear_page(ptr + i * PAGE_SIZE);

    /* LOG2SZ-1 is WARL, discover the valid value */
    iommu_write32(iommu_dev, RISCV_IOMMU_REG_CQB, RISCV_IOMMU_CQ_MASK_LOG2SZ);
    logsz_bits = FIELD_GET(RISCV_IOMMU_CQ_MASK_LOG2SZ,
                           iommu_read64(iommu_dev, RISCV_IOMMU_REG_CQB));
    if ( logsz > logsz_bits )
        logsz = logsz_bits + 1;

    queue->mask = (1ULL << logsz) - 1;
    queue->cmd = (struct riscv_iommu_command *) ptr;

    addr = iommu_ddt_phys_to_ppn(_virt_to_maddr(ptr));
    if ( !addr )
    {
        dev_err(iommu_dev->dev,
                "Unable to get physical address of command queue\n");
        return -EINVAL;
    }

    /* set queue base address */
    iommu_write64(iommu_dev, RISCV_IOMMU_REG_CQB, (logsz - 1) | addr);

    /* enable queue and interrupt */
    iommu_write32(iommu_dev, RISCV_IOMMU_REG_CQCSR,
                  RISCV_IOMMU_CQ_EN | RISCV_IOMMU_CQ_IE);

    /* waiting for command queue ready */
    if ( riscv_iommu_wait_xqcsr_at_one(iommu_dev, RISCV_IOMMU_REG_CQCSR,
                                       RISCV_IOMMU_CQ_ACTIVE) )
    {
        dev_err(iommu_dev->dev, "command queue is not active\n");
        return -EINVAL;
    }

    return 0;
}

static void riscv_iommu_disable_cmd_queue(struct riscv_iommu_device *iommu_dev)
{
    struct riscv_iommu_cmd_queue *queue = &iommu_dev->hw.cmd_queue;
    iommu_write32(iommu_dev, RISCV_IOMMU_REG_CQCSR, 0);
    iommu_write64(iommu_dev, RISCV_IOMMU_REG_CQB, 0);
    if ( queue->cmd )
    {
        free_xenheap_pages(iommu_dev->hw.cmd_queue.cmd, CQ_ORDER);
    }
    queue->cmd = NULL;
    queue->mask = 0;
}

static void riscv_iommu_cmd_queue_handler(int irq, void *dev,
                                          struct cpu_user_regs *regs)
{
    struct riscv_iommu_device *iommu_dev = dev;
    uint32_t cqcsr = iommu_read32(iommu_dev, RISCV_IOMMU_REG_CQCSR);

    if ( FIELD_GET(RISCV_IOMMU_CQ_FAULT, cqcsr) )
    {
        clear_bit(RISCV_IOMMU_CQ_FAULT, &cqcsr);
        dev_warn(iommu_dev->dev, "command queue memory fault\n");
    }

    if ( FIELD_GET(RISCV_IOMMU_CQ_TIMEOUT, cqcsr) )
    {
        dev_warn(iommu_dev->dev, "command queue timeout\n");
        iommu_write32(iommu_dev, RISCV_IOMMU_REG_CQT,
                      iommu_read32(iommu_dev, RISCV_IOMMU_REG_CQH));
        clear_bit(RISCV_IOMMU_CQ_TIMEOUT, &cqcsr);
    }

    if ( FIELD_GET(RISCV_IOMMU_CQ_ERROR, cqcsr) )
    {
        dev_warn(iommu_dev->dev, "illegal or unsupported command queue\n");
        iommu_write32(iommu_dev, RISCV_IOMMU_REG_CQT,
                      iommu_read32(iommu_dev, RISCV_IOMMU_REG_CQH));
        clear_bit(RISCV_IOMMU_CQ_ERROR, &cqcsr);
    }

    if ( FIELD_GET(RISCV_IOMMU_CQ_FENCE_W_IP, cqcsr) )
    {
        dev_warn(iommu_dev->dev, "command queue fence_w_ip\n");
        clear_bit(RISCV_IOMMU_CQ_FENCE_W_IP, &cqcsr);
    }

    /* update CQCSR */
    if ( riscv_iommu_wait_xqcsr_at_zero(iommu_dev, RISCV_IOMMU_REG_CQCSR,
                                        RISCV_IOMMU_CQ_BUSY) )
        dev_err(iommu_dev->dev, "unable to write into CQCSR register\n");
    else
    {
        iommu_write32(iommu_dev, RISCV_IOMMU_REG_CQCSR, cqcsr);
    }

    iommu_write32(iommu_dev, RISCV_IOMMU_REG_IPSR, RISCV_IOMMU_IPSR_CQIP);
}

static int riscv_iommu_enable_fault_queue(struct riscv_iommu_device *iommu_dev)
{
    void *ptr;
    size_t logsz_bits, logsz;
    struct riscv_iommu_fault_queue *queue = &iommu_dev->hw.fault_queue;

    logsz = PAGE_SHIFT + FQ_ORDER - ilog2(sizeof(struct riscv_iommu_event));

    ptr = alloc_xenheap_pages(FQ_ORDER, 0);
    if ( !ptr )
        return -ENOMEM;

    for ( int i = 0; i < (1 << FQ_ORDER); i++ )
        clear_page(ptr + i * PAGE_SIZE);

    /* LOG2SZ-1 is WARL, discover the valid value */
    iommu_write32(iommu_dev, RISCV_IOMMU_REG_FQB, RISCV_IOMMU_FQ_MASK_LOG2SZ);
    logsz_bits = FIELD_GET(RISCV_IOMMU_FQ_MASK_LOG2SZ,
                           iommu_read64(iommu_dev, RISCV_IOMMU_REG_FQB));
    if ( logsz > logsz_bits )
        logsz = logsz_bits + 1;

    queue->mask = (1ULL << logsz) - 1;
    queue->event = (struct riscv_iommu_event *) ptr;

    iommu_write64(iommu_dev, RISCV_IOMMU_REG_FQB,
                  (logsz - 1) | iommu_ddt_phys_to_ppn(_virt_to_maddr(ptr)));

    /* enable queue and interrupt */
    iommu_write32(iommu_dev, RISCV_IOMMU_REG_FQCSR,
                  RISCV_IOMMU_FQ_EN | RISCV_IOMMU_FQ_IE);
    return 0;
}

static void
riscv_iommu_disable_fault_queue(struct riscv_iommu_device *iommu_dev)
{
    struct riscv_iommu_fault_queue *queue = &iommu_dev->hw.fault_queue;

    iommu_write32(iommu_dev, RISCV_IOMMU_REG_FQCSR, 0);
    iommu_write64(iommu_dev, RISCV_IOMMU_REG_FQB, 0ULL);
    if ( queue->event )
    {
        free_xenheap_pages(iommu_dev->hw.fault_queue.event, FQ_ORDER);
    }
    queue->event = NULL;
    queue->mask = 0;
}

static int riscv_iommu_enable_preq_queue(struct riscv_iommu_device *iommu_dev)
{
    void *ptr;
    size_t logsz;
    struct riscv_iommu_page_req_queue *queue = &iommu_dev->hw.preq_queue;

    logsz = PAGE_SHIFT + PQ_ORDER - ilog2(sizeof(struct riscv_iommu_event));

    ptr = alloc_xenheap_pages(PQ_ORDER, 0);
    if ( !ptr )
        return -ENOMEM;

    for ( int i = 0; i < PQ_ORDER; i++ )
        clear_page(ptr + i * PAGE_SIZE);

    queue->mask = (1ULL << logsz) - 1;
    queue->req = (struct riscv_iommu_page_request *) ptr;

    /* TODO: implement page request queue enable
     * when PCI will be implemented
     */
    return 0;
}

static void riscv_iommu_disable_preq_queue(struct riscv_iommu_device *iommu_dev)
{
    struct riscv_iommu_page_req_queue *queue = &iommu_dev->hw.preq_queue;

    iommu_write32(iommu_dev, RISCV_IOMMU_REG_PQCSR, 0);
    iommu_write64(iommu_dev, RISCV_IOMMU_REG_PQB, 0ULL);

    /* TODO: implement page request queue disable
     * when PCI will be implemented
     */
    if ( iommu_dev->hw.preq_queue.req )
    {
        free_xenheap_pages(iommu_dev->hw.preq_queue.req, PQ_ORDER);
    }
    queue->req = NULL;
    queue->mask = 0;
}

static void riscv_iommu_report_event(struct riscv_iommu_device *iommu_dev,
                                     int idx)
{
    struct riscv_iommu_fault_queue *fltq = &iommu_dev->hw.fault_queue;
    struct riscv_iommu_event *event = fltq->event + idx;
    uint32_t did, err;

    if ( printk_ratelimit() )
    {
        did = FIELD_GET(RISCV_IOMMU_EVENT_MASK_DID, event->reason);
        err = FIELD_GET(RISCV_IOMMU_EVENT_MASK_CAUSE, event->reason);

        dev_warn(iommu_dev->dev,
                 "fault queue event => cause: %u did: %u iova: %lx gpa: %lx\n",
                 err, did, event->iova, event->phys);
    }
}

static void riscv_iommu_flt_queue_handler(int irq, void *dev,
                                          struct cpu_user_regs *regs)
{
    uint32_t head, tail, ctrl;
    struct riscv_iommu_device *iommu_dev = dev;
    struct riscv_iommu_fault_queue *fltq = &iommu_dev->hw.fault_queue;

    head = iommu_read32(iommu_dev, RISCV_IOMMU_REG_FQH) & fltq->mask;
    tail = iommu_read32(iommu_dev, RISCV_IOMMU_REG_FQT) & fltq->mask;
    while ( head != tail )
    {
        riscv_iommu_report_event(iommu_dev, head);
        head = (head + 1) & fltq->mask;
    }
    iommu_write32(iommu_dev, RISCV_IOMMU_REG_FQH, head);

    /* Error reporting, clear error reports if any. */
    ctrl = iommu_read32(iommu_dev, RISCV_IOMMU_REG_FQCSR);
    if ( ctrl & (RISCV_IOMMU_FQ_FULL | RISCV_IOMMU_FQ_FAULT) )
    {
        iommu_write32(iommu_dev, RISCV_IOMMU_REG_FQCSR, ctrl);
        dev_warn(iommu_dev->dev, "event: fault: %d full: %d\n",
                 !!(ctrl & RISCV_IOMMU_FQ_FAULT),
                 !!(ctrl & RISCV_IOMMU_FQ_FULL));
    }
    /* reset the fault queue pending bit */
    iommu_write32(iommu_dev, RISCV_IOMMU_REG_IPSR, RISCV_IOMMU_IPSR_FQIP);
}

static void riscv_iommu_preq_queue_handler(int irq, void *dev,
                                           struct cpu_user_regs *regs)
{
    struct riscv_iommu_device *iommu_dev = dev;
    dev_err(iommu_dev->dev, " !!!\n");

    /* reset the page request queue pending bit */
    iommu_write32(iommu_dev, RISCV_IOMMU_REG_IPSR, RISCV_IOMMU_IPSR_PQIP);
}

static void riscv_iommu_queue_handler(int irq, void *dev,
                                      struct cpu_user_regs *regs)
{
    struct riscv_iommu_device *iommu_dev = dev;
    uint32_t reg = iommu_read32(iommu_dev, RISCV_IOMMU_REG_IPSR);

    while ( reg )
    {
        if ( reg & RISCV_IOMMU_IPSR_CQIP )
        {
            riscv_iommu_cmd_queue_handler(irq, dev, regs);
        }
        if ( reg & RISCV_IOMMU_IPSR_FQIP )
        {
            riscv_iommu_flt_queue_handler(irq, dev, regs);
        }
        if ( reg & RISCV_IOMMU_IPSR_PQIP )
        {
            riscv_iommu_preq_queue_handler(irq, dev, regs);
        }
        reg = iommu_read32(iommu_dev, RISCV_IOMMU_REG_IPSR);
    }
}

static void riscv_iommu_free_irq(struct riscv_iommu_device *iommu_dev)
{
    struct riscv_iommu_cmd_queue *cmd_queue;
    struct riscv_iommu_fault_queue *fault_queue;
    struct riscv_iommu_page_req_queue *preq_queue;

    if ( iommu_dev->hw.nr_irqs == 1 )
    {
        cmd_queue = &iommu_dev->hw.cmd_queue;
        if ( cmd_queue->irq >= 0 )
            release_irq(cmd_queue->irq, iommu_dev);
    }
    else if ( iommu_dev->hw.nr_irqs == 4 )
    {
        /* TODO: add perf-monitoring interrupt */
        cmd_queue = &iommu_dev->hw.cmd_queue;
        fault_queue = &iommu_dev->hw.fault_queue;
        preq_queue = &iommu_dev->hw.preq_queue;
        if ( cmd_queue->irq >= 0 )
            release_irq(cmd_queue->irq, iommu_dev);
        if ( fault_queue->irq >= 0 )
            release_irq(fault_queue->irq, iommu_dev);
        if ( preq_queue->irq >= 0 )
            release_irq(preq_queue->irq, iommu_dev);
    }
}

static int riscv_iommu_device_hw_probe(struct riscv_iommu_device *iommu_dev,
                                       struct dt_device_node *np)
{
    int ret, iommu_version;
    uint32_t cells;
    struct riscv_iommu_hw *hw = &iommu_dev->hw;

    if ( !dt_property_read_u32(np, "#iommu-cells", &cells) )
    {
        dev_err(iommu_dev->dev, "missing #iommu-cells property\n");
        return -EINVAL;
    }
    switch ( cells )
    {
    case 1: iommu_dev->tc_opts = false; break;
    case 2: iommu_dev->tc_opts = true; break;
    default:
        dev_err(iommu_dev->dev, "invalid #iommu-cells value (%d),\n", cells);
        return -EINVAL;
    }

    /* get the IOMMU capabilities */
    hw->capabilities = iommu_read64(iommu_dev, RISCV_IOMMU_REG_CAP);

    /* check version */
    iommu_version = RISCV_IOMUU_CAP_REV_MASK & hw->capabilities;
    if ( (RISCV_IOMUU_CAP_REV_MASK & hw->capabilities) !=
         RISCV_IOMMU_CUR_VERSION )
    {
        dev_err(iommu_dev->dev, "Version '%02x' is not supported\n",
                iommu_version);
        return -EINVAL;
    }

    /* read fctl register and check endianness */
    hw->fctl = iommu_read32(iommu_dev, RISCV_IOMMU_REG_FCTL);
#ifdef __BIG_ENDIAN
    if ( !(RISCV_IOMU_FCTL_BE & hw->ctl) &&
         !(hw->capabilities & RISCV_IOMMU_CAP_END) )
    {
        dev_err(iommu_dev->dev,
                "big endian mode is not supported by the IOMMU\n");
        return -EINVAL;
    }
    else
    {
        hw->fctl |= RISCV_IOMU_FCTL_BE;
        iommu_write32(iommu_dev, RISCV_IOMMU_REG_FCTL, hw->fctl);
    }
#else  /* LITTLE ENDIAN */
    if ( RISCV_IOMMU_FCTL_BE & hw->fctl )
    {
        dev_err(iommu_dev->dev,
                "little endian mode is not supported by the IOMMU\n");
        return -EINVAL;
    }
#endif /* __BIG_ENDIAN */

    /* get number of interrupts */
    hw->nr_irqs = platform_get_nr_irqs(np);

    /* TODO: CHECK MSI message, for the moment use only APLIC interrupt
     * 'BOTH' is set to wire by default, change after for MSI
     */
    if ( !(hw->capabilities & RISCV_IOMMU_CAP_IGS_BOTH) &&
         !(hw->capabilities & RISCV_IOMMU_CAP_IGS_WIS) )
    {
        /* MSI interrupts */
        iommu_write32(iommu_dev, RISCV_IOMMU_REG_FCTL,
                      hw->fctl & ~RISCV_IOMMU_CAP_IGS_WIS);

        /* TODO: MSI implementation */
        assert_failed("MSI interrupt need to be implemented");
    }
    else if ( hw->capabilities & RISCV_IOMMU_CAP_IGS_BOTH ||
              hw->capabilities & RISCV_IOMMU_CAP_IGS_WIS )
    {
        /* Wire interrupts is used first if BOTH */
        iommu_write32(iommu_dev, RISCV_IOMMU_REG_FCTL, RISCV_IOMMU_FCTL_WIS);

        if ( hw->nr_irqs == 0 )
        {
            /* no interrupts used */
            riscv_iommu_disable_cmd_queue(iommu_dev);
            riscv_iommu_disable_fault_queue(iommu_dev);
            riscv_iommu_disable_preq_queue(iommu_dev);
        }
        else if ( hw->nr_irqs == 1 )
        {
            /* all in one interrupt */
            ret = platform_get_irq(np, 0);
            if ( ret < 0 )
            {
                dev_err(iommu_dev->dev, "Unable to retrieve the IRQ\n");
                return ret;
            }
            hw->cmd_queue.irq = ret;
            hw->fault_queue.irq = ret;
            hw->preq_queue.irq = ret;
            iommu_write64(iommu_dev, RISCV_IOMMU_REG_IVEC, 0);

            ret = request_irq(hw->cmd_queue.irq, 0, riscv_iommu_queue_handler,
                              dev_name(iommu_dev->dev), iommu_dev);
            if ( ret < 0 )
            {
                dev_err(iommu_dev->dev, "Unable to request the irq number %u\n",
                        hw->cmd_queue.irq);
                return ret;
            }
        }
        else
        {
            /* get command queue interrupt */
            hw->cmd_queue.irq = platform_get_irq_byname(np, "cmdq");
            if ( hw->cmd_queue.irq < 0 )
            {
                dev_err(iommu_dev->dev, "Unable to get 'cmdq' interrupt\n");
                return -EINVAL;
            }

            ret =
                request_irq(hw->cmd_queue.irq, 0, riscv_iommu_cmd_queue_handler,
                            dev_name(iommu_dev->dev), iommu_dev);
            if ( ret < 0 )
            {
                dev_err(iommu_dev->dev, "Unable to request the irq number %u\n",
                        hw->cmd_queue.irq);
                return ret;
            }

            /* get fault queue interrupt */
            hw->fault_queue.irq = platform_get_irq_byname(np, "fltq");
            if ( hw->fault_queue.irq < 0 )
            {
                dev_err(iommu_dev->dev, "Unable to get 'fltq' interrupt\n");
                return -EINVAL;
            }

            ret = request_irq(hw->fault_queue.irq, 0,
                              riscv_iommu_flt_queue_handler,
                              dev_name(iommu_dev->dev), iommu_dev);
            if ( ret < 0 )
            {
                dev_err(iommu_dev->dev, "Unable to request the irq number %u\n",
                        hw->fault_queue.irq);
                return ret;
            }

            /* get page request queue interrupt */
            hw->preq_queue.irq = platform_get_irq_byname(np, "priq");
            if ( hw->preq_queue.irq < 0 )
            {
                dev_err(iommu_dev->dev, "No interrupts named 'priq'\n");
                return -EINVAL;
            }

            ret = request_irq(hw->preq_queue.irq, 0,
                              riscv_iommu_preq_queue_handler,
                              dev_name(iommu_dev->dev), iommu_dev);
            if ( ret < 0 )
            {
                dev_err(iommu_dev->dev, "Unable to request the irq number %u\n",
                        hw->preq_queue.irq);
                return ret;
            }

            /* TODO: clarify how to set interrupt cause vector in
             * case of multiple interrupts
             * iommu_write64(iommu_dev, RISCV_IOMMU_REG_IVEC, 0);
             */
        }
    }
    else
    {
        dev_err(iommu_dev->dev, "cannot allocate interrupts\n");
        return -EINVAL;
    }

    /* custom init */
    ret = riscv_iommu_custom_init(iommu_dev);
    if ( ret < 0 )
    {
        dev_err(iommu_dev->dev, "cannot init custom (%d)\n", ret);
        return ret;
    }

    return 0;
}

static void riscv_iommu_device_hw_unprobe(struct riscv_iommu_device *iommu_dev)
{
    riscv_iommu_custom_uninit(iommu_dev);
    riscv_iommu_free_irq(iommu_dev);
}

static int riscv_iommu_enable_queues(struct riscv_iommu_device *iommu_dev)
{
    int ret;

    spin_lock_init(&iommu_dev->hw.cmd_queue.lock);

    ret = riscv_iommu_enable_cmd_queue(iommu_dev);
    if ( ret )
    {
        dev_err(iommu_dev->dev, "cannot enable command queue (%d)\n", ret);
        goto riscv_iommu_enable_queues_err1;
    }

    ret = riscv_iommu_enable_fault_queue(iommu_dev);
    if ( ret < 0 )
    {
        dev_err(iommu_dev->dev, "cannot enable fault queue (%d)\n", ret);
        goto riscv_iommu_enable_queues_err2;
    }

    ret = riscv_iommu_enable_preq_queue(iommu_dev);
    if ( ret < 0 )
    {
        dev_err(iommu_dev->dev, "cannot enable page request queue (%d)\n", ret);
        goto riscv_iommu_enable_queues_err3;
    }

    return 0;

riscv_iommu_enable_queues_err3:
    riscv_iommu_disable_fault_queue(iommu_dev);

riscv_iommu_enable_queues_err2:
    riscv_iommu_disable_cmd_queue(iommu_dev);

riscv_iommu_enable_queues_err1:
    return ret;
}

static void riscv_iommu_disable_queues(struct riscv_iommu_device *iommu_dev)
{
    riscv_iommu_disable_cmd_queue(iommu_dev);
    riscv_iommu_disable_fault_queue(iommu_dev);
    riscv_iommu_disable_preq_queue(iommu_dev);
}

static int riscv_iommu_enable_ddt(struct riscv_iommu_device *iommu_dev)
{
    int ret;
    uint64_t ddtp;

    iommu_dev->extended_dc =
        iommu_dev->hw.capabilities & RISCV_IOMMU_CAP_MSI_FLAT;
    iommu_dev->level = iommu_dev->ddt_mode - RISCV_IOMMU_DDTP_MODE_1LVL;

    /* IOMMU must be either disabled or in pass-through mode. */
    ddtp = iommu_read64(iommu_dev, RISCV_IOMMU_REG_DDTP);
    switch ( FIELD_GET(RISCV_IOMMU_DDTP_MASK_MODE, ddtp) )
    {
    case RISCV_IOMMU_DDTP_MODE_OFF:
    case RISCV_IOMMU_DDTP_MODE_BARE: break;
    default:
        dev_err(iommu_dev->dev, "DDTP mode is not bare or off \n");
        return -EINVAL;
    }

    switch ( iommu_dev->ddt_mode )
    {
    case RISCV_IOMMU_DDTP_MODE_1LVL:
    case RISCV_IOMMU_DDTP_MODE_2LVL:
    case RISCV_IOMMU_DDTP_MODE_3LVL:
        /* allocate the first DDT page, one page is ok for all level modes */
        iommu_dev->ddtp = alloc_xenheap_page();
        if ( !iommu_dev->ddtp )
        {
            return -ENOMEM;
        }
        clear_page(iommu_dev->ddtp);
        ddtp = iommu_ddt_phys_to_ppn(_virt_to_maddr(iommu_dev->ddtp)) |
               (uint64_t) iommu_dev->ddt_mode;
        break;

    default:
        /* RISCV_IOMMU_DDTP_MODE_OFF and RISCV_IOMMU_DDTP_MODE_BARE
         * are not supported
         * TODO: check whether these modes should be supported
         */
        dev_err(iommu_dev->dev, "IOMMU is off or in bare mode\n");
        return -EINVAL;
    }

    ret = riscv_iommu_wait_ddtp_ready(iommu_dev);
    if ( ret )
    {
        goto riscv_iommu_enable_ddt_err;
    }

    iommu_write64(iommu_dev, RISCV_IOMMU_REG_DDTP, ddtp);
    return 0;

riscv_iommu_enable_ddt_err:
    if ( iommu_dev->ddtp )
    {
        free_xenheap_page((void *) iommu_dev->ddtp);
        iommu_dev->ddtp = NULL;
    }
    return ret;
}

static void riscv_iommu_disable_ddt(struct riscv_iommu_device *iommu_dev)
{
    riscv_iommu_wait_ddtp_ready(iommu_dev);
    iommu_write64(iommu_dev, RISCV_IOMMU_REG_DDTP, 0ULL);

    if ( iommu_dev->ddtp )
    {
        free_xenheap_page((void *) iommu_dev->ddtp);
        iommu_dev->ddtp = NULL;
    }
}

static int riscv_iommu_init_structures(struct riscv_iommu_device *iommu_dev)
{
    int ret;

    ret = riscv_iommu_enable_queues(iommu_dev);
    if ( ret )
        return ret;

    ret = riscv_iommu_enable_ddt(iommu_dev);
    if ( ret )
    {
        return ret;
    }

    iommu_dev->sync = alloc_xenheap_page();
    if ( !iommu_dev->sync )
    {
        return -ENOMEM;
    }
    clear_page(iommu_dev->sync);

    return 0;
}

static void riscv_iommu_uninit_structures(struct riscv_iommu_device *iommu_dev)
{
    riscv_iommu_disable_queues(iommu_dev);
    riscv_iommu_disable_ddt(iommu_dev);

    /* free notification page */
    if ( iommu_dev->sync )
    {
        free_xenheap_page(iommu_dev->sync);
        iommu_dev->sync = NULL;
    }
}

static int riscv_iommu_device_reset(struct riscv_iommu_device *iommu_dev)
{
    /* currently nothing to do */
    return 0;
}

static int riscv_iommu_device_probe(struct device *pdev)
{
    int ret;
    paddr_t ioaddr, iosize;
    struct riscv_iommu_device *iommu_dev;
    struct dt_device_node *np = dev_to_dt(pdev);

    /* create the device */
    iommu_dev = xzalloc(struct riscv_iommu_device);
    if ( !iommu_dev )
    {
        dev_err(pdev, "unable to allocate IOMMU device\n");
        return -ENOMEM;
    }
    iommu_dev->dev = pdev;

    if ( dt_device_is_compatible(np, "sifive,iommu-22") )
    {
        iommu_dev->sifive_iommu_22 = true;
        /* force ddt mode to 2 levels for sifive iommu-22 */
        iommu_dev->ddt_mode = RISCV_IOMMU_DDTP_MODE_2LVL;
    }
    else
    {
        iommu_dev->ddt_mode = ddt_mode;
    }

    /* get IOMMU base address */
    ret = dt_device_get_paddr(np, 0, &ioaddr, &iosize);
    if ( ret )
    {
        dev_err(pdev, "invalid address\n");
        goto riscv_iommu_device_probe_err;
    }

    /* map the registery */
    iommu_dev->hw.regs = ioremap_nocache(ioaddr, iosize);
    if ( IS_ERR(iommu_dev->hw.regs) )
    {
        dev_err(pdev, "unable to remap\n");
        ret = PTR_ERR(iommu_dev->hw.regs);
        goto riscv_iommu_device_probe_err;
    }

    /* Probe the h/w */
    ret = riscv_iommu_device_hw_probe(iommu_dev, np);
    if ( ret )
    {
        goto riscv_iommu_device_probe_err1;
    }

    /* Initialise in-memory data structures */
    ret = riscv_iommu_init_structures(iommu_dev);
    if ( ret )
        goto riscv_iommu_device_probe_err2;

    /* Reset the device */
    ret = riscv_iommu_device_reset(iommu_dev);
    if ( ret )
        goto riscv_iommu_device_probe_err3;

    /*
     * Keep a list of all probed devices. This will be used to query
     * the iommu devices based on the fwnode.
     */
    INIT_LIST_HEAD(&iommu_dev->devices);

    spin_lock(&riscv_iommu_devices_lock);
    list_add(&iommu_dev->devices, &riscv_iommu_devices);
    spin_unlock(&riscv_iommu_devices_lock);

    /* success */
    dev_info(pdev, "initialized\n");
    return 0;

riscv_iommu_device_probe_err3:
    riscv_iommu_uninit_structures(iommu_dev);

riscv_iommu_device_probe_err2:
    riscv_iommu_device_hw_unprobe(iommu_dev);

riscv_iommu_device_probe_err1:
    iounmap(iommu_dev->hw.regs);
    iommu_dev->hw.regs = NULL;

riscv_iommu_device_probe_err:
    xfree(iommu_dev);
    return ret;
}

static const struct dt_device_match riscv_iommu_of_match[] = {
    DT_MATCH_COMPATIBLE("riscv,iommu"),
    DT_MATCH_COMPATIBLE("sifive,iommu-22"),
    {/* sentinel */},
};

static __init int riscv_iommu_init(struct dt_device_node *dev, const void *data)
{
    int rc;

    dt_device_set_used_by(dev, DOMID_XEN);

    rc = riscv_iommu_device_probe(dt_to_dev(dev));
    if ( rc )
        return rc;

    iommu_set_ops(&riscv_iommu_ops);
    return 0;
}

DT_DEVICE_START(riscv_iommu_device, "RISC-V IOMMU", DEVICE_IOMMU)
    .dt_match = riscv_iommu_of_match,
   .init = riscv_iommu_init, DT_DEVICE_END
