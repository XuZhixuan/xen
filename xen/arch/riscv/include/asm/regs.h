#ifndef __ARM_REGS_H__
#define __ARM_REGS_H__

#ifndef __ASSEMBLY__

#include <xen/lib.h>
#include <asm/current.h>

#define hyp_mode(r)     (0)

static inline bool guest_mode(const struct cpu_user_regs *r)
{
    BUG();
}

#endif


#endif /* __ARM_REGS_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
