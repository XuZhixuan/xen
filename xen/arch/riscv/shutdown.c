#include <xen/bug.h>

void machine_halt(void)
{
    sbi_system_reset(SYSTEM_RESET_SHUTDOWN, SYSTEM_RESET_NO_REASON);
}

void machine_restart(unsigned int delay_millisecs)
{
    for (int i = 0; i < 5; i++ )
    {
        printk("%u... ", 5 - i);
        mdelay(1000);
    }
    sbi_system_reset(SYSTEM_RESET_COLD_REBOOT, SYSTEM_RESET_SYSTEM_FAILURE);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
