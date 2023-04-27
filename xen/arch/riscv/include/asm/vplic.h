#ifndef __ASM_VPLIC_H__
#define __ASM_VPLIC_H__

#define MAX_SOURCES 1024
#define MAX_CONTEXTS 15872

struct context {
    unsigned int enable[MAX_SOURCES/32];
};

struct vplic {
    unsigned int num_contexts;
    struct context *contexts;
    unsigned long base;
};

struct vplic *vplic_alloc(void);

#endif /* __ASM_VPLIC_H__ */
