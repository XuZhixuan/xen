#include <xen/bug.h>

void udelay(unsigned long usecs)
{
    assert_failed("need to be implemented");
}
EXPORT_SYMBOL(udelay);

