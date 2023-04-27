#include <xen/setup.h>
#include <xen/xmalloc.h>
#include <asm/vplic.h>

struct vplic *vplic_alloc(void)
{
    struct vplic *p;
    
    p = xzalloc(struct vplic);

    if ( !p )
        return NULL;

    p->base = PLIC_BASE;
    p->num_contexts = NR_VCPUS * 2;

    if ( p->num_contexts > MAX_CONTEXTS )
        goto err;

    p->contexts = xzalloc_array(struct context, p->num_contexts);

    if ( !p->contexts )
        goto err;

    return p;

err:
    xfree(p);
    return NULL;
}