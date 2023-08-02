#include <xen/time.h>

#include <asm/processor.h>

void udelay(unsigned long usecs)
{
    s_time_t deadline = get_s_time() + 1000 * (s_time_t) usecs;

    while ( get_s_time() - deadline < 0 )
        cpu_relax();
}
EXPORT_SYMBOL(udelay);