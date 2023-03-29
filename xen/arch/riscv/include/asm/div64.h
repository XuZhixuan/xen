#ifndef __ASM_RISCV_DIV64
#define __ASM_RISCV_DIV64

#include <asm/system.h>
#include <xen/types.h>

# define do_div(n,base) ({                                      \
        uint32_t __base = (base);                               \
        uint32_t __rem;                                         \
        __rem = ((uint64_t)(n)) % __base;                       \
        (n) = ((uint64_t)(n)) / __base;                         \
        __rem;                                                  \
 })

#endif
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
