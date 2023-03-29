#ifndef _RISCV_GUEST_ATOMICS_H
#define _RISCV_GUEST_ATOMICS_H

/*
 * TODO: implement guest atomics
 */

#define guest_testop(name)                                                  \
static inline int guest_##name(struct domain *d, int nr, volatile void *p)  \
{                                                                           \
    (void) d;       \
    (void) nr;      \
    (void) p;       \
                                                                            \
    return 0;                                                               \
}

#define guest_bitop(name)                                                   \
static inline void guest_##name(struct domain *d, int nr, volatile void *p) \
{                                                                           \
    (void) d;                                                               \
    (void) nr;                                                              \
    (void) p;                                                               \
}

guest_bitop(set_bit)
guest_bitop(clear_bit)
guest_bitop(change_bit)

#undef guest_bitop

guest_testop(test_and_set_bit)
guest_testop(test_and_clear_bit)
guest_testop(test_and_change_bit)

#undef guest_testop


#define guest_test_bit(d, nr, p) ((void)(d), test_bit(nr, p))

#endif /* _RISCV_GUEST_ATOMICS_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
