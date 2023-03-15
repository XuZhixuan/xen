#ifndef __ARM_BUG_H__
#define __ARM_BUG_H__

/*
 * Please do not include in the header any header that might
 * use BUG/ASSERT/etc maros asthey will be defined later after
 * the return to <xen/bug.h> from the current header:
 * 
 * <xen/bug.h>:
 *  ...
 *   <asm/bug.h>:
 *     ...
 *     <any_header_which_uses_BUG/ASSERT/etc macros.h>
 *     ...
 *  ...
 *  #define BUG() ...
 *  ...
 *  #define ASSERT() ...
 *  ...
 */

#include <xen/types.h>

#if defined(CONFIG_ARM_32)
# include <asm/arm32/bug.h>
#elif defined(CONFIG_ARM_64)
# include <asm/arm64/bug.h>
#else
# error "unknown ARM variant"
#endif

#define BUG_ASM_CONST   "c"

#endif /* __ARM_BUG_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
