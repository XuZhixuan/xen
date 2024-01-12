#ifndef __ASM_VPLIC_H__
#define __ASM_VPLIC_H__

#include <asm/gic.h>

#define MAX_SOURCES 1024
#define MAX_CONTEXTS 15872

#define to_vplic(v) container_of(v, struct vplic, vgic)

struct context {
    unsigned int enable[MAX_SOURCES/32];
};

struct vplic {
    /* This field should be first */
    struct vgic vgic;

    unsigned int num_contexts;
    struct context *contexts;
    unsigned long base;
};

struct  vcpu;
struct vplic * vplic_alloc(struct vcpu *vcpu);

#endif /* __ASM_VPLIC_H__ */
