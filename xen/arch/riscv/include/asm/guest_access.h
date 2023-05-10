#ifndef __ASM_RISCV_GUEST_ACCESS_H__
#define __ASM_RISCV_GUEST_ACCESS_H__

/* common/symbol.c complain with this header: it should moved there */
#include <xen/errno.h>

unsigned long raw_copy_to_guest(void *to, const void *from, unsigned len);
unsigned long raw_copy_from_guest(void *to, const void *from, unsigned len);

#define __raw_copy_to_guest raw_copy_to_guest
#define __raw_copy_from_guest raw_copy_from_guest

#define guest_handle_okay(hnd, nr) (1)
#define guest_handle_subrange_okay(hnd, first, last) (1)

struct domain;
unsigned long copy_to_guest_phys(struct domain *d,
                                 paddr_t gpa,
                                 void *buf,
                                 unsigned int len);

#endif /* __ASM_RISCV_GUEST_ACCESS_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
