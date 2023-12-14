/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2014 Regents of the University of California */

#ifndef _ASM_RISCV_CMPXCHG_H
#define _ASM_RISCV_CMPXCHG_H

#include <xen/compiler.h>
#include <xen/lib.h>

#include <asm/fence.h>
#include <asm/io.h>
#include <asm/system.h>

#define __xchg_relaxed(ptr, new, size) \
({ \
    __typeof__(ptr) ptr__ = (ptr); \
    __typeof__(new) new__ = (new); \
    __typeof__(*(ptr)) ret__; \
    switch (size) { \
    case 4: \
        asm volatile( \
            "	amoswap.w %0, %2, %1\n" \
            : "=r" (ret__), "+A" (*ptr__) \
            : "r" (new__) \
            : "memory"); \
        break; \
    case 8: \
        asm volatile( \
            "	amoswap.d %0, %2, %1\n" \
            : "=r" (ret__), "+A" (*ptr__) \
            : "r" (new__) \
            : "memory"); \
        break; \
    default: \
        ASSERT_UNREACHABLE(); \
    } \
    ret__; \
})

#define xchg_relaxed(ptr, x) \
({ \
    __typeof__(*(ptr)) x_ = (x); \
    (__typeof__(*(ptr))) __xchg_relaxed((ptr), x_, sizeof(*(ptr))); \
})

#define __xchg_acquire(ptr, new, size) \
({ \
    __typeof__(ptr) ptr__ = (ptr); \
    __typeof__(new) new__ = (new); \
    __typeof__(*(ptr)) ret__; \
    switch (size) { \
    case 4: \
        asm volatile( \
            "	amoswap.w %0, %2, %1\n" \
            RISCV_ACQUIRE_BARRIER \
            : "=r" (ret__), "+A" (*ptr__) \
            : "r" (new__) \
            : "memory"); \
        break; \
    case 8: \
        asm volatile( \
            "	amoswap.d %0, %2, %1\n" \
            RISCV_ACQUIRE_BARRIER \
            : "=r" (ret__), "+A" (*ptr__) \
            : "r" (new__) \
            : "memory"); \
        break; \
    default: \
        ASSERT_UNREACHABLE(); \
    } \
    ret__; \
})

#define xchg_acquire(ptr, x) \
({ \
    __typeof__(*(ptr)) x_ = (x); \
    (__typeof__(*(ptr))) __xchg_acquire((ptr), x_, sizeof(*(ptr))); \
})

#define __xchg_release(ptr, new, size) \
({ \
    __typeof__(ptr) ptr__ = (ptr); \
    __typeof__(new) new__ = (new); \
    __typeof__(*(ptr)) ret__; \
    switch (size) { \
    case 4: \
        asm volatile ( \
            RISCV_RELEASE_BARRIER \
            "	amoswap.w %0, %2, %1\n" \
            : "=r" (ret__), "+A" (*ptr__) \
            : "r" (new__) \
            : "memory"); \
        break; \
    case 8: \
        asm volatile ( \
            RISCV_RELEASE_BARRIER \
            "	amoswap.d %0, %2, %1\n" \
            : "=r" (ret__), "+A" (*ptr__) \
            : "r" (new__) \
            : "memory"); \
        break; \
    default: \
        ASSERT_UNREACHABLE(); \
    } \
    ret__; \
})

#define xchg_release(ptr, x) \
({ \
    __typeof__(*(ptr)) x_ = (x); \
    (__typeof__(*(ptr))) __xchg_release((ptr), x_, sizeof(*(ptr))); \
})

static always_inline uint32_t __xchg_case_4(volatile uint32_t *ptr,
                                            uint32_t new)
{
    __typeof__(*(ptr)) ret;

    asm volatile (
        "   amoswap.w.aqrl %0, %2, %1\n"
        : "=r" (ret), "+A" (*ptr)
        : "r" (new)
        : "memory");

    return ret;
}

static always_inline uint64_t __xchg_case_8(volatile uint64_t *ptr,
                                            uint64_t new)
{
    __typeof__(*(ptr)) ret;

    asm volatile( \
        "   amoswap.d.aqrl %0, %2, %1\n" \
        : "=r" (ret), "+A" (*ptr) \
        : "r" (new) \
        : "memory"); \

    return ret;
}

static always_inline unsigned short __cmpxchg_case_2(volatile uint32_t *ptr,
                                                     uint32_t old,
                                                     uint32_t new);

static always_inline unsigned short __cmpxchg_case_1(volatile uint32_t *ptr,
                                                     uint32_t old,
                                                     uint32_t new);

static inline unsigned long __xchg(volatile void *ptr, unsigned long x, int size)
{
    switch (size) {
    case 1:
        return __cmpxchg_case_1(ptr, (uint32_t)-1, x);
    case 2:
        return __cmpxchg_case_2(ptr, (uint32_t)-1, x);
    case 4:
        return __xchg_case_4(ptr, x);
    case 8:
        return __xchg_case_8(ptr, x);
    default:
        ASSERT_UNREACHABLE();
    }

    return -1;
}

#define xchg(ptr,x) \
({ \
    __typeof__(*(ptr)) ret__; \
    ret__ = (__typeof__(*(ptr))) \
            __xchg((ptr), (unsigned long)(x), sizeof(*(ptr))); \
    ret__; \
})

#define xchg32(ptr, x) \
({ \
    BUILD_BUG_ON(sizeof(*(ptr)) != 4); \
    xchg((ptr), (x)); \
})

#define xchg64(ptr, x) \
({ \
    BUILD_BUG_ON(sizeof(*(ptr)) != 8); \
    xchg((ptr), (x)); \
})

/*
 * Atomic compare and exchange.  Compare OLD with MEM, if identical,
 * store NEW in MEM.  Return the initial value in MEM.  Success is
 * indicated by comparing RETURN with OLD.
 */
#define __cmpxchg_relaxed(ptr, old, new, size) \
({ \
    __typeof__(ptr) ptr__ = (ptr); \
    __typeof__(*(ptr)) __old = (old); \
    __typeof__(*(ptr)) new__ = (new); \
    __typeof__(*(ptr)) ret__; \
    register unsigned int __rc; \
    switch (size) { \
    case 4: \
        asm volatile( \
            "0:	lr.w %0, %2\n" \
            "	bne  %0, %z3, 1f\n" \
            "	sc.w %1, %z4, %2\n" \
            "	bnez %1, 0b\n" \
            "1:\n" \
            : "=&r" (ret__), "=&r" (__rc), "+A" (*ptr__) \
            : "rJ" (__old), "rJ" (new__) \
            : "memory"); \
        break; \
    case 8: \
        asm volatile( \
            "0:	lr.d %0, %2\n" \
            "	bne %0, %z3, 1f\n" \
            "	sc.d %1, %z4, %2\n" \
            "	bnez %1, 0b\n" \
            "1:\n" \
            : "=&r" (ret__), "=&r" (__rc), "+A" (*ptr__) \
            : "rJ" (__old), "rJ" (new__) \
            : "memory"); \
        break; \
    default: \
        ASSERT_UNREACHABLE(); \
    } \
    ret__; \
})

#define cmpxchg_relaxed(ptr, o, n) \
({ \
    __typeof__(*(ptr)) o_ = (o); \
    __typeof__(*(ptr)) n_ = (n); \
    (__typeof__(*(ptr))) __cmpxchg_relaxed((ptr), \
                    o_, n_, sizeof(*(ptr))); \
})

#define __cmpxchg_acquire(ptr, old, new, size) \
({ \
    __typeof__(ptr) ptr__ = (ptr); \
    __typeof__(*(ptr)) __old = (old); \
    __typeof__(*(ptr)) new__ = (new); \
    __typeof__(*(ptr)) ret__; \
    register unsigned int __rc; \
    switch (size) { \
    case 4: \
        asm volatile( \
            "0:	lr.w %0, %2\n" \
            "	bne  %0, %z3, 1f\n" \
            "	sc.w %1, %z4, %2\n" \
            "	bnez %1, 0b\n" \
            RISCV_ACQUIRE_BARRIER \
            "1:\n"	 \
            : "=&r" (ret__), "=&r" (__rc), "+A" (*ptr__) \
            : "rJ" (__old), "rJ" (new__) \
            : "memory"); \
        break; \
    case 8: \
        asm volatile( \
            "0:	lr.d %0, %2\n" \
            "	bne %0, %z3, 1f\n" \
            "	sc.d %1, %z4, %2\n" \
            "	bnez %1, 0b\n" \
            RISCV_ACQUIRE_BARRIER \
            "1:\n" \
            : "=&r" (ret__), "=&r" (__rc), "+A" (*ptr__) \
            : "rJ" (__old), "rJ" (new__) \
            : "memory"); \
        break; \
    default: \
        ASSERT_UNREACHABLE(); \
    } \
    ret__; \
})

#define cmpxchg_acquire(ptr, o, n) \
({ \
    __typeof__(*(ptr)) o_ = (o); \
    __typeof__(*(ptr)) n_ = (n); \
    (__typeof__(*(ptr))) __cmpxchg_acquire((ptr), o_, n_, sizeof(*(ptr))); \
})

#define __cmpxchg_release(ptr, old, new, size) \
({									\
    __typeof__(ptr) ptr__ = (ptr); \
    __typeof__(*(ptr)) __old = (old); \
    __typeof__(*(ptr)) new__ = (new); \
    __typeof__(*(ptr)) ret__; \
    register unsigned int __rc; \
    switch (size) { \
    case 4: \
        asm volatile ( \
            RISCV_RELEASE_BARRIER \
            "0:	lr.w %0, %2\n" \
            "	bne  %0, %z3, 1f\n" \
            "	sc.w %1, %z4, %2\n" \
            "	bnez %1, 0b\n" \
            "1:\n" \
            : "=&r" (ret__), "=&r" (__rc), "+A" (*ptr__)	\
            : "rJ" (__old), "rJ" (new__) \
            : "memory"); \
        break; \
    case 8: \
        asm volatile ( \
            RISCV_RELEASE_BARRIER \
            "0:	lr.d %0, %2\n" \
            "	bne %0, %z3, 1f\n" \
            "	sc.d %1, %z4, %2\n" \
            "	bnez %1, 0b\n" \
            "1:\n" \
            : "=&r" (ret__), "=&r" (__rc), "+A" (*ptr__) \
            : "rJ" (__old), "rJ" (new__) \
            : "memory"); \
        break; \
    default: \
        ASSERT_UNREACHABLE(); \
    } \
    ret__; \
})

#define cmpxchg_release(ptr, o, n) \
({ \
    __typeof__(*(ptr)) _o_ = (o); \
    __typeof__(*(ptr)) _n_ = (n); \
    (__typeof__(*(ptr))) __cmpxchg_release((ptr), _o_, _n_, sizeof(*(ptr))); \
})

static always_inline uint32_t __cmpxchg_case_4(volatile uint32_t *ptr,
                                               uint32_t old,
                                               uint32_t new)
{
    uint32_t ret;
    register uint32_t rc;

    asm volatile (
        "0: lr.w %0, %2\n"
        "   bne  %0, %z3, 1f\n"
        "   sc.w.rl %1, %z4, %2\n"
        "   bnez %1, 0b\n"
        "   fence rw, rw\n"
        "1:\n"
        : "=&r" (ret), "=&r" (rc), "+A" (*ptr)
        : "rJ" (old), "rJ" (new)
        : "memory");

    return ret;
}

static always_inline uint64_t __cmpxchg_case_8(volatile uint64_t *ptr,
                                               uint64_t old,
                                               uint64_t new)
{
    uint64_t ret;
    register uint32_t rc;

    asm volatile(
        "0: lr.d %0, %2\n"
        "   bne %0, %z3, 1f\n"
        "   sc.d.rl %1, %z4, %2\n"
        "   bnez %1, 0b\n"
        "   fence rw, rw\n"
        "1:\n"
        : "=&r" (ret), "=&r" (rc), "+A" (*ptr)
        : "rJ" (old), "rJ" (new)
        : "memory");

    return ret;
}

#define __emulate_cmpxchg_case1_2(ptr, new, read_func, cmpxchg_func, swap_byte_mask_base)\
({                                                                              \
    __typeof__(*(ptr)) read_val;                                                \
    __typeof__(*(ptr)) swapped_new;                                             \
    __typeof__(*(ptr)) ret;                                                     \
    __typeof__(*(ptr)) new_ = (__typeof__(*(ptr)))new;                          \
                                                                                \
    __typeof__(ptr) aligned_ptr = (__typeof__(ptr))((unsigned long)ptr & ~3);   \
    __typeof__(*(ptr)) mask_off = ((unsigned long)ptr & 3) * 8;                 \
    __typeof__(*(ptr)) mask =                                                   \
      (__typeof__(*(ptr)))swap_byte_mask_base << mask_off;                      \
    __typeof__(*(ptr)) masked_new = (new_ << mask_off) & mask;                  \
                                                                                \
    do {                                                                        \
        read_val = read_func(aligned_ptr);                                      \
        swapped_new = read_val & ~mask;                                         \
        swapped_new |= masked_new;                                              \
        ret = cmpxchg_func(aligned_ptr, read_val, swapped_new);                 \
    } while ( ret != read_val );                                                \
                                                                                \
    ret = MASK_EXTR(swapped_new, mask);                                         \
    ret;                                                                        \
})

static always_inline unsigned short __cmpxchg_case_2(volatile uint32_t *ptr,
                                                     uint32_t old,
                                                     uint32_t new)
{
    (void) old;

    if (((unsigned long)ptr & 3) == 3)
    {
#ifdef CONFIG_64BIT
        return __emulate_cmpxchg_case1_2((uint64_t *)ptr, new,
                                         readq, __cmpxchg_case_8, 0xffffU);
#else
        #error "add emulation support of cmpxchg for CONFIG_32BIT"
#endif
    }
    else
        return __emulate_cmpxchg_case1_2((uint32_t *)ptr, new,
                                         readl, __cmpxchg_case_4, 0xffffU);
}

static always_inline unsigned short __cmpxchg_case_1(volatile uint32_t *ptr,
                                                     uint32_t old,
                                                     uint32_t new)
{
    (void) old;

    return __emulate_cmpxchg_case1_2((uint32_t *)ptr, new,
                                     readl, __cmpxchg_case_4, 0xffU);
}

static always_inline unsigned long __cmpxchg(volatile void *ptr,
                                             unsigned long old,
                                             unsigned long new,
                                             int size)
{
    switch (size)
    {
    case 1:
        return __cmpxchg_case_1(ptr, old, new);
    case 2:
        return __cmpxchg_case_2(ptr, old, new);
    case 4:
        return __cmpxchg_case_4(ptr, old, new);
    case 8:
        return __cmpxchg_case_8(ptr, old, new);
    default:
        ASSERT_UNREACHABLE();
    }

    return old;
}

#define cmpxchg(ptr, o, n) \
({ \
    __typeof__(*(ptr)) ret__; \
    ret__ = (__typeof__(*(ptr))) \
            __cmpxchg((ptr), (unsigned long)(o), (unsigned long)(n), \
                      sizeof(*(ptr))); \
    ret__; \
})

#define cmpxchg_local(ptr, o, n) \
    (__cmpxchg_relaxed((ptr), (o), (n), sizeof(*(ptr))))

#define cmpxchg32(ptr, o, n) \
({ \
    BUILD_BUG_ON(sizeof(*(ptr)) != 4); \
    cmpxchg((ptr), (o), (n)); \
})

#define cmpxchg32_local(ptr, o, n) \
({ \
    BUILD_BUG_ON(sizeof(*(ptr)) != 4); \
    cmpxchg_relaxed((ptr), (o), (n)) \
})

#define cmpxchg64(ptr, o, n) \
({ \
    BUILD_BUG_ON(sizeof(*(ptr)) != 8); \
    cmpxchg((ptr), (o), (n)); \
})

#define cmpxchg64_local(ptr, o, n) \
({ \
    BUILD_BUG_ON(sizeof(*(ptr)) != 8); \
    cmpxchg_relaxed((ptr), (o), (n)); \
})

#endif /* _ASM_RISCV_CMPXCHG_H */
