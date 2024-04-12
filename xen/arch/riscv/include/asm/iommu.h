/* SPDX-License-Identifier: MIT
 * Copyright (C) 2024 Microchip
 */

#ifndef __ARCH_RISCV_IOMMU_H__
#define __ARCH_RISCV_IOMMU_H__

#include <asm/atomic.h>
#include <asm/io.h>
#include <xen/const.h>

#define FIELD_GET(_mask, _reg)                                                 \
    ((typeof(_mask)) (((_reg) & (_mask)) >> (ffs64(_mask) - 1)))

#define FIELD_PREP(_mask, _val)                                                \
    (((typeof(_mask)) (_val) << (ffs64(_mask) - 1)) & (_mask))

/* Device logger functions */
#ifdef CONFIG_SIFIVE_IOMMU22
#define IOMMU_LOG_PREFIX "sifive iommu-22"
#else
#define IOMMU_LOG_PREFIX "riscv iommu"
#endif

#define dev_name(dev) dt_node_full_name(dev->of_node)
#define dev_dbg(dev, fmt, ...)                                                 \
    printk(XENLOG_DEBUG IOMMU_LOG_PREFIX "[%s]: " fmt, dev_name(dev),          \
           ##__VA_ARGS__)
#define dev_notice(dev, fmt, ...)                                              \
    printk(XENLOG_INFO IOMMU_LOG_PREFIX "[%s]: " fmt, dev_name(dev),           \
           ##__VA_ARGS__)
#define dev_warn(dev, fmt, ...)                                                \
    printk(XENLOG_WARNING IOMMU_LOG_PREFIX "[%s]: " fmt, dev_name(dev),        \
           ##__VA_ARGS__)
#define dev_err(dev, fmt, ...)                                                 \
    printk(XENLOG_ERR IOMMU_LOG_PREFIX "[%s]: " fmt, dev_name(dev),            \
           ##__VA_ARGS__)
#define dev_info(dev, fmt, ...)                                                \
    printk(XENLOG_INFO IOMMU_LOG_PREFIX "[%s]: " fmt, dev_name(dev),           \
           ##__VA_ARGS__)
#define dev_err_ratelimited(dev, fmt, ...)                                     \
    printk(XENLOG_ERR IOMMU_LOG_PREFIX "[%s]: " fmt, dev_name(dev),            \
           ##__VA_ARGS__)

/* Current supported version v1.0 */
#define RISCV_IOMMU_CUR_VERSION 0x10

/* Memory-mapped registers */
#define RISCV_IOMMU_REG_CAP 0x0000
#define RISCV_IOMMU_REG_FCTL 0x0008
#define RISCV_IOMMU_REG_DDTP 0x0010
#define RISCV_IOMMU_REG_CQB 0x0018
#define RISCV_IOMMU_REG_CQH 0x0020
#define RISCV_IOMMU_REG_CQT 0x0024
#define RISCV_IOMMU_REG_FQB 0x0028
#define RISCV_IOMMU_REG_FQH 0x0030
#define RISCV_IOMMU_REG_FQT 0x0034
#define RISCV_IOMMU_REG_PQB 0x0038
#define RISCV_IOMMU_REG_PQH 0x0040
#define RISCV_IOMMU_REG_PQT 0x0044
#define RISCV_IOMMU_REG_CQCSR 0x0048
#define RISCV_IOMMU_REG_FQCSR 0x004C
#define RISCV_IOMMU_REG_PQCSR 0x0050
#define RISCV_IOMMU_REG_IPSR 0x0054
#define RISCV_IOMMU_REG_IOCNTOVF 0x0058
#define RISCV_IOMMU_REG_IOCNTINH 0x005C
#define RISCV_IOMMU_REG_IOHPMCYCLES 0x0060
#define RISCV_IOMMU_REG_IOHPMCTR_BASE 0x0068
#define RISCV_IOMMU_REG_IOHPMEVT_BASE 0x0160
#define RISCV_IOMMU_REG_TR_REQ_IOVA 0x0258
#define RISCV_IOMMU_REG_TR_REQ_CTRL 0x0260
#define RISCV_IOMMU_REG_TR_RESPONSE 0x0268
#define RISCV_IOMMU_REG_IVEC 0x02F8
#define RISCV_IOMMU_REG_MSI_CONFIG 0x0300
#define RISCV_IOMMU_REG_SIZE 0x1000

/* Capabilities supported by the IOMMU */
#define RISCV_IOMMU_CAPS_VERSION (0)
#define RISCV_IOMMU_CAP_SV32 BIT(8, ULL)
#define RISCV_IOMMU_CAP_SV39 BIT(9, ULL)
#define RISCV_IOMMU_CAP_SV48 BIT(10, ULL)
#define RISCV_IOMMU_CAP_SV57 BIT(11, ULL)
#define RISCV_IOMMU_CAP_SVNAPOT BIT(14, ULL)
#define RISCV_IOMMU_CAP_SVPBMT BIT(15, ULL)
#define RISCV_IOMMU_CAP_SV32X4 BIT(16, ULL)
#define RISCV_IOMMU_CAP_SV39X4 BIT(17, ULL)
#define RISCV_IOMMU_CAP_SV48X4 BIT(18, ULL)
#define RISCV_IOMMU_CAP_SV57X4 BIT(19, ULL)
#define RISCV_IOMMU_CAP_MSI_FLAT BIT(22, ULL)
#define RISCV_IOMMU_CAP_MSI_MRIF BIT(23, ULL)
#define RISCV_IOMMU_CAP_AMO BIT(24, ULL)
#define RISCV_IOMMU_CAP_ATS BIT(25, ULL)
#define RISCV_IOMMU_CAP_T2GPA BIT(26, ULL)
#define RISCV_IOMMU_CAP_END BIT(27, ULL)
#define RISCV_IOMMU_CAP_IGS_WIS BIT(28, ULL)
#define RISCV_IOMMU_CAP_IGS_BOTH BIT(29, ULL)
#define RISCV_IOMMU_CAP_HPM BIT(30, ULL)
#define RISCV_IOMMU_CAP_DBG BIT(31, ULL)
#define RISCV_IOMMU_CAP_PD8 BIT(38, ULL)
#define RISCV_IOMMU_CAP_PD17 BIT(39, ULL)
#define RISCV_IOMMU_CAP_PD20 BIT(40, ULL)
#define RISCV_IOMUU_CAP_REV_MASK 0x00000000000000FFULL
#define RISCV_IOMUU_CAP_PAS_MASK 0x0000003F00000000ULL
#define RISCV_IOMUU_CAP_IGS_MASK GENMASK_ULL(29, 28)

/* Features control register */
#define RISCV_IOMMU_FCTL_BE BIT(0, ULL)
#define RISCV_IOMMU_FCTL_WIS BIT(1, ULL)
#define RISCV_IOMMU_FCTL_GXL BIT(2, ULL)

/* Command queue base register */
#define RISCV_IOMMU_CQ_MASK_LOG2SZ 0x000000000000001FULL
#define RISCV_IOMMU_CQ_MASK_PPN 0x003FFFFFFFFFFC00ULL

/* Command queue control and status register */
#define RISCV_IOMMU_CQ_EN BIT(0, UL)
#define RISCV_IOMMU_CQ_IE BIT(1, UL)
#define RISCV_IOMMU_CQ_FAULT BIT(8, UL)
#define RISCV_IOMMU_CQ_TIMEOUT BIT(9, UL)
#define RISCV_IOMMU_CQ_ERROR BIT(10, UL)
#define RISCV_IOMMU_CQ_FENCE_W_IP BIT(11, UL)
#define RISCV_IOMMU_CQ_ACTIVE BIT(16, UL)
#define RISCV_IOMMU_CQ_BUSY BIT(17, UL)

/* Fault queue base register */
#define RISCV_IOMMU_FQ_MASK_LOG2SZ 0x000000000000001FULL
#define RISCV_IOMMU_FQ_MASK_PPN 0x003FFFFFFFFFFC00ULL

/* Fault queue control and status register */
#define RISCV_IOMMU_FQ_EN BIT(0, UL)
#define RISCV_IOMMU_FQ_IE BIT(1, UL)
#define RISCV_IOMMU_FQ_FAULT BIT(8, UL)
#define RISCV_IOMMU_FQ_FULL BIT(9, UL)
#define RISCV_IOMMU_FQ_ACTIVE BIT(16, UL)
#define RISCV_IOMMU_FQ_BUSY BIT(17, UL)

/* Page request queue base register */
#define RISCV_IOMMU_PQ_MASK_LOG2SZ 0x000000000000001FULL
#define RISCV_IOMMU_PQ_MASK_PPN 0x003FFFFFFFFFFC00ULL

/* Page request queue control and status register */
#define RISCV_IOMMU_PQ_EN BIT(0, UL)
#define RISCV_IOMMU_PQ_IE BIT(1, UL)
#define RISCV_IOMMU_PQ_FAULT BIT(8, UL)
#define RISCV_IOMMU_PQ_FULL BIT(9, UL)
#define RISCV_IOMMU_PQ_ACTIVE BIT(16, UL)
#define RISCV_IOMMU_PQ_BUSY BIT(17, UL)

/* Device directory table pointer */
#define RISCV_IOMMU_DDTP_MASK_PPN 0x003FFFFFFFFFFC00ULL
#define RISCV_IOMMU_DDTP_MASK_MODE 0x000000000000000FULL
#define RISCV_IOMMU_DDTP_BUSY 0x0000000000000010ULL

/* Device directory mode values, within RISCV_IOMMU_DDTP_MODE_MAX */
#define RISCV_IOMMU_DDTP_MODE_OFF 0
#define RISCV_IOMMU_DDTP_MODE_BARE 1
#define RISCV_IOMMU_DDTP_MODE_1LVL 2
#define RISCV_IOMMU_DDTP_MODE_2LVL 3
#define RISCV_IOMMU_DDTP_MODE_3LVL 4
#define RISCV_IOMMU_DDTP_MODE_MAX RISCV_IOMMU_DDTP_MODE_3LVL

/* Device directory table pointer */
#define RISCV_IOMMU_DDTP_MASK_PPN 0x003FFFFFFFFFFC00ULL
#define RISCV_IOMMU_DDTP_MASK_MODE 0x000000000000000FULL
#define RISCV_IOMMU_DDTP_BUSY 0x0000000000000010ULL
#define RISCV_IOMMU_DDTE_VALID BIT(0, ULL)
#define RISCV_IOMMU_DDTE_MASK_PPN 0x003FFFFFFFFFFC00ULL

/* SiFive IOMMU-22 Custom */
#define RISCV_IOMMU_REG_CUSTOM 0x000C /* Custom IOMMU control */
#define RISCV_IOMMU_CUSTOM_TIMEOUT GENMASK(7, 0)
#define RISCV_IOMMU_CUSTOM_MPAGE BIT(8, UL)
#define RISCV_IOMMU_CUSTOM_GPAGE BIT(9, UL)
#define RISCV_IOMMU_CUSTOM_TPAGE BIT(10, UL)
#define RISCV_IOMMU_CUSTOM_PPAGE BIT(11, UL)
#define RISCV_IOMMU_CUSTOM_PTE_DISABLE BIT(12, UL)
#define RISCV_IOMMU_CUSTOM_CTE_DISABLE BIT(13, UL)
#define RISCV_IOMMU_CUSTOM_CG_DIS BIT(14, UL)

#define RISCV_IOMMU_REG_CUSTOM_VID 0x02B0 /* SiFive Version ID */
#define RISCV_IOMMU_CUSTOM_VID_MAJOR GENMASK(15, 8)
#define RISCV_IOMMU_CUSTOM_VID_MINOR GENMASK(7, 0)
#define RISCV_IOMMU_CUSTOM_VID_DEFAULT 0x00000100

/* device context translation control */
#define RISCV_IOMMU_DCTC_VALID BIT(0, ULL)
#define RISCV_IOMMU_DCTC_EN_ATS BIT(1, ULL)
#define RISCV_IOMMU_DCTC_EN_PRI BIT(2, ULL)
#define RISCV_IOMMU_DCTC_T2GPA BIT(3, ULL)
#define RISCV_IOMMU_DCTC_DTF BIT(4, ULL)
#define RISCV_IOMMU_DCTC_PDTV BIT(5, ULL)
#define RISCV_IOMMU_DCTC_PRPR BIT(6, ULL)
#define RISCV_IOMMU_DCTC_GADE BIT(7, ULL)
#define RISCV_IOMMU_DCTC_SADE BIT(8, ULL)
#define RISCV_IOMMU_DCTC_DPE BIT(9, ULL)
#define RISCV_IOMMU_DCTC_SBE BIT(10, ULL)
#define RISCV_IOMMU_DCTC_SXL BIT(11, ULL)

/* Shared MODE:ASID:PPN masks for GATP, SATP */
#define RISCV_IOMMU_ATP_MODE_BARE 0
#define RISCV_IOMMU_ATP_MODE_SV32 8
#define RISCV_IOMMU_ATP_MODE_SV39 8
#define RISCV_IOMMU_ATP_MODE_SV48 9
#define RISCV_IOMMU_ATP_MODE_SV57 10

/* riscv_iommu_command.request opcode and function mask */
#define RISCV_IOMMU_CMD_MASK_FCT_OP 0x00000000000003FFULL

/* opcode == IOTINVAL.* */
#define RISCV_IOMMU_CMD_IOTINVAL_VMA 0x001
#define RISCV_IOMMU_CMD_IOTINVAL_GVMA 0x081
#define RISCV_IOMMU_CMD_IOTINVAL_MSI 0x101
#define RISCV_IOMMU_IOTINVAL_ADDR_VALID 0x0000000000000400ULL
#define RISCV_IOMMU_IOTINVAL_PSCID_VALID 0x0000000100000000ULL
#define RISCV_IOMMU_IOTINVAL_GSCID_VALID 0x0000000200000000ULL
#define RISCV_IOMMU_IOTINVAL_ADDR_NAPOT 0x0000000000002000ULL
#define RISCV_IOMMU_IOTINVAL_MASK_PSCID 0x00000000FFFFF000ULL
#define RISCV_IOMMU_IOTINVAL_MASK_GSCID 0x0FFFF00000000000ULL

/* opcode == IOFENCE.* */
#define RISCV_IOMMU_CMD_IOFENCE_C 0x002
#define RISCV_IOMMU_IOFENCE_AV 0x0000000000000400ULL
#define RISCV_IOMMU_IOFENCE_WIS 0x0000000000000800ULL
#define RISCV_IOMMU_IOFENCE_PR 0x0000000000001000ULL
#define RISCV_IOMMU_IOFENCE_PW 0x0000000000002000ULL
#define RISCV_IOMMU_IOFENCE_MASK_DATA 0xFFFFFFFF00000000ULL
#define RISCV_IOMMU_IOFENCE_MASK_ADDR 0x3FFFFFFFFFFFFFFFULL

/* opcode == IODIR.* */
#define RISCV_IOMMU_CMD_IODIR 0x003
#define RISCV_IOMMU_IODIR_DID_VALID 0x0000000200000000ULL
#define RISCV_IOMMU_IODIR_MASK_PID 0x00000000FFFFF000ULL
#define RISCV_IOMMU_IODIR_MASK_DID 0xFFFFFF0000000000ULL

/* Interrupt Sources */
#define RISCV_IOMMU_INT_CQ     0
#define RISCV_IOMMU_INT_FQ     1
#define RISCV_IOMMU_INT_PM     2
#define RISCV_IOMMU_INT_PQ     3
#define RISCV_IOMMU_INT_COUNT  4

#define RISCV_IOMMU_IPSR_CQIP   BIT(RISCV_IOMMU_INT_CQ, UL)
#define RISCV_IOMMU_IPSR_FQIP   BIT(RISCV_IOMMU_INT_FQ, UL)
#define RISCV_IOMMU_IPSR_PMIP   BIT(RISCV_IOMMU_INT_PM, UL)
#define RISCV_IOMMU_IPSR_PQIP   BIT(RISCV_IOMMU_INT_PQ, UL)

/* Interrupt vector mapping */
#define RIISC_IOMMU_IVEC_CQIV   (0x0F << 0)
#define RIISC_IOMMU_IVEC_FQIV   (0x0F << 4)
#define RIISC_IOMMU_IVEC_PMIV   (0x0F << 8)
#define RIISC_IOMMU_IVEC_PQIV   (0x0F << 12)

/* riscv_iommu_event.reason */
#define RISCV_IOMMU_EVENT_MASK_CAUSE    0x0000000000000FFFULL
#define RISCV_IOMMU_EVENT_MASK_PID      0x00000000FFFFF000ULL
#define RISCV_IOMMU_EVENT_MASK_DID      0xFFFFFF0000000000ULL
#define RISCV_IOMMU_EVENT_PV            0x0000000100000000ULL
#define RISCV_IOMMU_EVENT_PRIV          0x0000000200000000ULL
#define RISCV_IOMMU_EVENT_MASK_TTYPE    0x000000FC00000000ULL

struct riscv_iommu_dc
{
    uint64_t tc;
    uint64_t iohgatp;
    uint64_t ta;
    uint64_t fsc;
    uint64_t msiptp;
    uint64_t msi_addr_mask;
    uint64_t msi_addr_pattern;
    uint64_t __rsv;
} __attribute__((__packed__));

/* Command format */
struct riscv_iommu_command
{
    uint64_t request;
    uint64_t address;
};

/* Fault Queue element */
struct riscv_iommu_event
{
    uint64_t reason;
    uint64_t _reserved;
    uint64_t iova;
    uint64_t phys;
};

/* Page Request Queue element */
struct riscv_iommu_page_request
{
    uint64_t request;
    uint64_t payload;
};

/* command queue */
struct riscv_iommu_cmd_queue {
    spinlock_t lock;
    struct riscv_iommu_command *cmd;
    uint32_t mask;
    uint32_t tail;
    uint32_t irq;
};

/* fault queue */
struct riscv_iommu_fault_queue {
    struct riscv_iommu_event *event;
    uint32_t mask;
    uint32_t irq;
};

/* page request queue */
struct riscv_iommu_page_req_queue {
    struct riscv_iommu_page_request *req;
    uint32_t mask;
    uint32_t irq;
};

struct riscv_iommu_hw
{
    /* Memory-mapped registers */
    void __iomem *regs;

    /* Capabilities supported by the IOMMU */
    uint64_t capabilities;

    /* Features control register */
    uint32_t fctl;

    /* nuber of interrupt */
    uint32_t nr_irqs;

    /* queues */
    struct riscv_iommu_cmd_queue cmd_queue;
    struct riscv_iommu_fault_queue fault_queue;
    struct riscv_iommu_page_req_queue preq_queue;
};

/* Xen specific code. */
struct iommu_domain
{
    /* Runtime configuration for this iommu_domain */
    atomic_t ref;
    /*
     * Used to link iommu_domain contexts for a same domain.
     * There is at least one per-IOMMU to used by the domain.
     */
    struct list_head list;
};

struct riscv_iommu_device
{
    /* base device */
    struct device *dev;

    /* hardware device */
    struct riscv_iommu_hw hw;

    /* Need to keep a list of IOMMU devices */
    struct list_head devices;

    /* device directory table mode */
    unsigned int ddt_mode;

    /* device directory table level */
    unsigned int level;

    /* true if device context table entry is exetended (64 bytes) */
    bool extended_dc;

    /* true if processId table is supported is supported */
    bool processId;

    /* device directory table pointer */
    void *ddtp;

    /* notification page (used for iofence notification) */
    void *sync;

    /* true if iommu is SiFive iommu-22 */
    bool sifive_iommu_22;
};

struct riscv_iommu_domain
{
    struct riscv_iommu_device *iommu_dev;
    spinlock_t iommu_lock;

    /* Xen domain associated with this IOMMU domain */
    struct domain *d;

    /* GSCID (G-SofContextID) is the Xen Domain ID + 1 */
    uint32_t gscid;

    struct iommu_domain domain;

    /* list of devices attached to this domain with lock */
    spinlock_t devices_lock;
    struct list_head devices;
};

/* Describes information required for a Xen domain */
struct riscv_iommu_xen_domain
{
    spinlock_t lock;
    /* List of iommu domains associated to this domain */
    struct list_head contexts;
};

/* IOMMU private data for each master */
struct riscv_iommu_master
{
    bool attached;
    struct device *dev;
    struct riscv_iommu_device *iommu_dev;
    struct riscv_iommu_domain *domain;
    struct list_head domain_head;

    /* DeviceID array */
    unsigned int *dids;
    unsigned int num_dids;

    /* device context */
    struct riscv_iommu_dc **dc;

    bool ats_enabled;
};

static inline bool is_sifive_iommu_22(struct riscv_iommu_device *iommu_dev) {
    return iommu_dev->sifive_iommu_22;
}

static inline uint64_t iommu_read64(struct riscv_iommu_device *iommu_dev,
                                    unsigned int offset)
{
    return readq(iommu_dev->hw.regs + offset);
}

static inline void iommu_write64(struct riscv_iommu_device *iommu_dev,
                                 unsigned int offset, uint64_t value)
{
    writeq(value, iommu_dev->hw.regs + offset);
}

static inline u32 iommu_read32(struct riscv_iommu_device *iommu_dev,
                               unsigned int offset)
{
    return readl(iommu_dev->hw.regs + offset);
}

static inline void iommu_write32(struct riscv_iommu_device *iommu_dev,
                                 unsigned int offset, uint32_t value)
{
    writel(value, iommu_dev->hw.regs + offset);
}

struct arch_iommu
{
    /* Private information for the IOMMU drivers */
    void *priv;
};

const struct iommu_ops *iommu_get_ops(void);
void iommu_set_ops(const struct iommu_ops *ops);

/*
 * The mapping helpers below should only be used if P2M Table is shared
 * between the CPU and the IOMMU.
 */
int __must_check riscv_iommu_helpers_map_page(struct domain *d, dfn_t dfn,
                                              mfn_t mfn, unsigned int flags,
                                              unsigned int *flush_flags);

int __must_check riscv_iommu_helpers_unmap_page(struct domain *d, dfn_t dfn,
                                                unsigned int order,
                                                unsigned int *flush_flags);

#endif /* __ARCH_RISCV_IOMMU_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
