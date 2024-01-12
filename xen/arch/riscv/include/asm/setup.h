#ifndef __RISCV_SETUP_H_
#define __RISCV_SETUP_H_

#include <public/version.h>

extern domid_t max_init_domid;

#define NR_VCPUS 1

void create_dom0(void);
void create_domUs(void);

#endif /* __RISCV_SETUP_H_ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

