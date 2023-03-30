#include <xen/bug.h>
#include <xen/errno.h>

unsigned long raw_copy_to_guest(void *to, const void *from, unsigned len)
{
	WARN();
    return -ENOSYS;
}

unsigned long raw_copy_from_guest(void *to, const void __user *from, unsigned len)
{
	WARN();
    return -ENOSYS;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
