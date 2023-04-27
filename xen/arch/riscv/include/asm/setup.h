#ifndef __RISCV_SETUP_H_
#define __RISCV_SETUP_H_

#include <public/version.h>

extern domid_t max_init_domid;

#define NR_VCPUS 1

/* Devices */
#define PLIC_BASE  0xc000000
#define PLIC_SIZE  0x0210000
#define PLIC_END (PLIC_BASE + PLIC_SIZE)

#endif /* __RISCV_SETUP_H_ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

