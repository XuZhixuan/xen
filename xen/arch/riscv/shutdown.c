#include <xen/bug.h>

void machine_halt(void)
{
    WARN();
}

void machine_restart(unsigned int delay_millisecs)
{
    WARN();
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
