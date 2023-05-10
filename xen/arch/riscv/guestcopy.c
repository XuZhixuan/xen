#include <xen/bug.h>
#include <xen/domain_page.h>
#include <xen/errno.h>
#include <xen/sched.h>

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

unsigned long copy_to_guest_phys(struct domain *d,
                                 paddr_t gpa,
                                 void *buf,
                                 unsigned int len)
{
    /* XXX needs to handle faults */
    uint64_t addr = gpa;
    unsigned offset = addr & ~PAGE_MASK;

    /* This function may not yet be designed for non-dom0 domains */
    BUG_ON( d->domain_id != 0 );
    BUILD_BUG_ON((sizeof(addr)) < sizeof(vaddr_t));
    BUILD_BUG_ON((sizeof(addr)) < sizeof(paddr_t));

    printk(XENLOG_INFO "copying d%d 0x%02lx-0x%02lx to 0x%02lx-0x%02lx\n",
            d->domain_id, (unsigned long)buf, (unsigned long)buf+len, addr, addr+len);

    while ( len )
    {
        void *p;
        unsigned size = min(len, (unsigned)PAGE_SIZE - offset);
        struct page_info *page;

        page = p2m_get_page_from_gfn(d, gaddr_to_gfn(addr), NULL);
        if ( page == NULL )
            return len;

        p = __map_domain_page(page);
        p += offset;
        memcpy(p, buf, size);
        unmap_domain_page(p - offset);

        /* TODO: use put_page for reference counting here */

        len -= size;
        buf += size;
        addr += size;
        /*
         * After the first iteration, guest virtual address is correctly
         * aligned to PAGE_SIZE.
         */
        offset = 0;
    }

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
