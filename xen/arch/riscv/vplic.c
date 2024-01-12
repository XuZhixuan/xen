#include <xen/bug.h>
#include <xen/errno.h>
#include <xen/setup.h>
#include <xen/sched.h>
#include <xen/xmalloc.h>

#include <asm/plic.h>
#include <asm/vplic.h>

#define PLIC_ENABLE_BASE 0x002000
#define PLIC_ENABLE_END  0x1FFFFC

/*
 * Every 0x80 bits starting at 0x2000 represents a new context.
 * I.e., 0x2000 == start of context0, 0x2080 == start of context1, ...
 *
 */
#define PLIC_ENABLE_BITS_PER_CONTEXT 0x80

static inline int is_plic_access(struct vcpu *vcpu, unsigned long addr)
{
    return PLIC_BASE < addr && addr < PLIC_END;
}

static int vplic_emulate_store(struct vcpu *vcpu, unsigned long addr, uint32_t in)
{
    printk("%s: TODO: emulate_store()\n", __func__);

    return 0;
}

static int vplic_emulate_load(struct vcpu *vcpu, unsigned long addr, uint32_t *out)
{
    struct vplic *vplic = to_vplic(vcpu->arch.vgic);
    struct context *ctx;
    unsigned context_num;
    unsigned long offset;
    void *p;
    unsigned int out_len = 4;

    BUG_ON( !out );

    offset = addr - vplic->base;

    if ( PLIC_ENABLE_BASE <= offset && offset < PLIC_ENABLE_END )
    {
        context_num = (offset - PLIC_ENABLE_BASE) / PLIC_ENABLE_BITS_PER_CONTEXT;

        if ( context_num > MAX_CONTEXTS )
            return -EIO;

        ctx = &vplic->contexts[context_num];

        p = &ctx->enable;
        offset -= (context_num * 0x80) + PLIC_ENABLE_BASE;

        if ( offset + out_len + PLIC_BASE + PLIC_ENABLE_BASE > PLIC_END )
            return -EIO;

        p += offset;

        memcpy(out, p, out_len);
    }
    else
    {
        printk("vplic emulator doesn't support access to addr @ 0x%02lx yet\n", addr);
        return -EOPNOTSUPP;
    }

    return 0;
}

struct vplic *vplic_alloc(struct vcpu *vcpu)
{
    struct vplic *p;

    p = xzalloc(struct vplic);

    if ( !p )
        return NULL;

    p->vgic.emulate_load = vplic_emulate_load;
    p->vgic.emulate_store = vplic_emulate_store;
    p->vgic.is_access = is_plic_access;

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
