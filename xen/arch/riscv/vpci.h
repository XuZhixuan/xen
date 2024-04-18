#ifndef __ARCH_RISCV_VPCI_H__
#define __ARCH_RISCV_VPCI_H__

#ifdef CONFIG_HAS_VPCI
int domain_vpci_init(struct domain *d);
unsigned int domain_vpci_get_num_mmio_handlers(struct domain *d);
#else
static inline int domain_vpci_init(struct domain *d)
{
    return 0;
}

static inline unsigned int domain_vpci_get_num_mmio_handlers(struct domain *d)
{
    return 0;
}
#endif

#endif /* __ARCH_RISCV_VPCI_H__ */
