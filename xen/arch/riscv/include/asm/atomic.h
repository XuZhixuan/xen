/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Taken and modified from Linux.
 * 
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2017 SiFive
 * Copyright (C) 2021 Vates SAS
 */

#ifndef _ASM_RISCV_ATOMIC_H
#define _ASM_RISCV_ATOMIC_H

#include <xen/atomic.h>
#include <asm/cmpxchg.h>
#include <asm/fence.h>
#include <asm/io.h>
#include <asm/system.h>

void __bad_atomic_size(void);

static always_inline void read_atomic_size(const volatile void *p,
                                           void *res,
                                           unsigned int size)
{
    switch ( size ) {
    case 1: *(uint8_t *)res = readb((uint8_t *)p); break;
    case 2: *(uint16_t *)res = readw((uint16_t *)p); break;
    case 4: *(uint32_t *)res = readl((uint32_t *)p); break;
    case 8: *(uint32_t *)res  = readq((uint64_t *)p); break;
    default: __bad_atomic_size(); break;
    }
}

#define read_atomic(p) ({                                               \
    union { typeof(*p) val; char c[0]; } x_;                            \
    read_atomic_size(p, x_.c, sizeof(*p));                              \
    x_.val;                                                             \
})


#define write_atomic(p, x) ({                                           \
    typeof(*p) __x = (x);                                               \
    switch ( sizeof(*p) ) {                                             \
    case 1: writeb((uint8_t)__x,  (uint8_t *)  p); break;              \
    case 2: writew((uint16_t)__x, (uint16_t *) p); break;              \
    case 4: writel((uint32_t)__x, (uint32_t *) p); break;              \
    case 8: writeq((uint64_t)__x, (uint64_t *) p); break;              \
    default: __bad_atomic_size(); break;                                \
    }                                                                   \
    __x;                                                                \
})

/* TODO: Fix this */
#define add_sized(p, x) ({                                              \
    typeof(*(p)) __x = (x);                                             \
    switch ( sizeof(*(p)) )                                             \
    {                                                                   \
    case 1: writeb(read_atomic(p) + __x, (uint8_t *)(p)); break;        \
    case 2: writew(read_atomic(p) + __x, (uint16_t *)(p)); break;       \
    case 4: writel(read_atomic(p) + __x, (uint32_t *)(p)); break;       \
    default: __bad_atomic_size(); break;                                \
    }                                                                   \
})

/*
 *  __unqual_scalar_typeof(x) - Declare an unqualified scalar type, leaving
 *               non-scalar types unchanged.
 *
 * Prefer C11 _Generic for better compile-times and simpler code. Note: 'char'
 * is not type-compatible with 'signed char', and we define a separate case.
 */
#define __scalar_type_to_expr_cases(type)               \
    unsigned type:  (unsigned type)0,                   \
    signed type:    (signed type)0

#define __unqual_scalar_typeof(x) typeof(               \
    _Generic((x),                                       \
        char:  (char)0,                                 \
        __scalar_type_to_expr_cases(char),              \
        __scalar_type_to_expr_cases(short),             \
        __scalar_type_to_expr_cases(int),               \
        __scalar_type_to_expr_cases(long),              \
        __scalar_type_to_expr_cases(long long),         \
        default: (x)))

#define READ_ONCE(x)  (*(const volatile __unqual_scalar_typeof(x) *)&(x))
#define WRITE_ONCE(x, val)                                      \
    do {                                                        \
            *(volatile typeof(x) *)&(x) = (val);                \
    } while (0)

#define __atomic_acquire_fence()					\
	__asm__ __volatile__(RISCV_ACQUIRE_BARRIER "" ::: "memory")

#define __atomic_release_fence()					\
	__asm__ __volatile__(RISCV_RELEASE_BARRIER "" ::: "memory");

static inline int atomic_read(const atomic_t *v)
{
	return READ_ONCE(v->counter);
}

static inline int _atomic_read(atomic_t v)
{
    return v.counter;
}

static inline void atomic_set(atomic_t *v, int i)
{
	WRITE_ONCE(v->counter, i);
}

static inline void _atomic_set(atomic_t *v, int i)
{
    v->counter = i;
}

static inline int atomic_sub_and_test(int i, atomic_t *v)
{
    return atomic_sub_return(i, v) == 0;
}

static inline void atomic_inc(atomic_t *v)
{
    atomic_add(1, v);
}

static inline int atomic_inc_return(atomic_t *v)
{
    return atomic_add_return(1, v);
}

static inline void atomic_dec(atomic_t *v)
{
    atomic_sub(1, v);
}

static inline int atomic_dec_return(atomic_t *v)
{
    return atomic_sub_return(1, v);
}


static inline int atomic_dec_and_test(atomic_t *v)
{
    return atomic_sub_return(1, v) == 0;
}

static inline int atomic_add_negative(int i, atomic_t *v)
{
    return atomic_add_return(i, v) < 0;
}

static inline int atomic_inc_and_test(atomic_t *v)
{
    return atomic_add_return(1, v) == 0;
}

/*
 * First, the atomic ops that have no ordering constraints and therefor don't
 * have the AQ or RL bits set.  These don't return anything, so there's only
 * one version to worry about.
 */
#define ATOMIC_OP(op, asm_op, I, asm_type, c_type, prefix)		\
static inline							\
void atomic##prefix##_##op(c_type i, atomic##prefix##_t *v)		\
{									\
	__asm__ __volatile__ (						\
		"	amo" #asm_op "." #asm_type " zero, %1, %0"	\
		: "+A" (v->counter)					\
		: "r" (I)						\
		: "memory");						\
}									\

#define ATOMIC_OPS(op, asm_op, I)					\
        ATOMIC_OP (op, asm_op, I, w, int,   )

ATOMIC_OPS(add, add,  i)
ATOMIC_OPS(sub, add, -i)
ATOMIC_OPS(and, and,  i)
ATOMIC_OPS( or,  or,  i)
ATOMIC_OPS(xor, xor,  i)

#undef ATOMIC_OP
#undef ATOMIC_OPS

/*
 * Atomic ops that have ordered, relaxed, acquire, and release variants.
 * There's two flavors of these: the arithmatic ops have both fetch and return
 * versions, while the logical ops only have fetch versions.
 */
#define ATOMIC_FETCH_OP(op, asm_op, I, asm_type, c_type, prefix)	\
static inline							\
c_type atomic##prefix##_fetch_##op##_relaxed(c_type i,			\
					     atomic##prefix##_t *v)	\
{									\
	register c_type ret;						\
	__asm__ __volatile__ (						\
		"	amo" #asm_op "." #asm_type " %1, %2, %0"	\
		: "+A" (v->counter), "=r" (ret)				\
		: "r" (I)						\
		: "memory");						\
	return ret;							\
}									\
static inline							\
c_type atomic##prefix##_fetch_##op(c_type i, atomic##prefix##_t *v)	\
{									\
	register c_type ret;						\
	__asm__ __volatile__ (						\
		"	amo" #asm_op "." #asm_type ".aqrl  %1, %2, %0"	\
		: "+A" (v->counter), "=r" (ret)				\
		: "r" (I)						\
		: "memory");						\
	return ret;							\
}

#define ATOMIC_OP_RETURN(op, asm_op, c_op, I, asm_type, c_type, prefix)	\
static inline							\
c_type atomic##prefix##_##op##_return_relaxed(c_type i,			\
					      atomic##prefix##_t *v)	\
{									\
        return atomic##prefix##_fetch_##op##_relaxed(i, v) c_op I;	\
}									\
static inline							\
c_type atomic##prefix##_##op##_return(c_type i, atomic##prefix##_t *v)	\
{									\
        return atomic##prefix##_fetch_##op(i, v) c_op I;		\
}

#define ATOMIC_OPS(op, asm_op, c_op, I)					\
        ATOMIC_FETCH_OP( op, asm_op,       I, w, int,   )		\
        ATOMIC_OP_RETURN(op, asm_op, c_op, I, w, int,   )

ATOMIC_OPS(add, add, +,  i)
ATOMIC_OPS(sub, add, +, -i)

#define atomic_add_return_relaxed	atomic_add_return_relaxed
#define atomic_sub_return_relaxed	atomic_sub_return_relaxed
#define atomic_add_return		atomic_add_return
#define atomic_sub_return		atomic_sub_return

#define atomic_fetch_add_relaxed	atomic_fetch_add_relaxed
#define atomic_fetch_sub_relaxed	atomic_fetch_sub_relaxed
#define atomic_fetch_add		atomic_fetch_add
#define atomic_fetch_sub		atomic_fetch_sub

#undef ATOMIC_OPS

#define ATOMIC_OPS(op, asm_op, I)					\
        ATOMIC_FETCH_OP(op, asm_op, I, w, int,   )

ATOMIC_OPS(and, and, i)
ATOMIC_OPS( or,  or, i)
ATOMIC_OPS(xor, xor, i)

#define atomic_fetch_and_relaxed	atomic_fetch_and_relaxed
#define atomic_fetch_or_relaxed		atomic_fetch_or_relaxed
#define atomic_fetch_xor_relaxed	atomic_fetch_xor_relaxed
#define atomic_fetch_and		atomic_fetch_and
#define atomic_fetch_or			atomic_fetch_or
#define atomic_fetch_xor		atomic_fetch_xor

#undef ATOMIC_OPS

#undef ATOMIC_FETCH_OP
#undef ATOMIC_OP_RETURN

/* This is required to provide a full barrier on success. */
static inline int atomic_add_unless(atomic_t *v, int a, int u)
{
       int prev, rc;

	__asm__ __volatile__ (
		"0:	lr.w     %[p],  %[c]\n"
		"	beq      %[p],  %[u], 1f\n"
		"	add      %[rc], %[p], %[a]\n"
		"	sc.w.rl  %[rc], %[rc], %[c]\n"
		"	bnez     %[rc], 0b\n"
		"	fence    rw, rw\n"
		"1:\n"
		: [p]"=&r" (prev), [rc]"=&r" (rc), [c]"+A" (v->counter)
		: [a]"r" (a), [u]"r" (u)
		: "memory");
	return prev;
}
#define atomic_fetch_add_unless atomic_fetch_add_unless

/*
 * atomic_{cmp,}xchg is required to have exactly the same ordering semantics as
 * {cmp,}xchg and the operations that return, so they need a full barrier.
 */
#define ATOMIC_OP(c_t, prefix, size)					\
static inline							\
c_t atomic##prefix##_xchg_relaxed(atomic##prefix##_t *v, c_t n)		\
{									\
	return __xchg_relaxed(&(v->counter), n, size);			\
}									\
static inline							\
c_t atomic##prefix##_xchg_acquire(atomic##prefix##_t *v, c_t n)		\
{									\
	return __xchg_acquire(&(v->counter), n, size);			\
}									\
static inline							\
c_t atomic##prefix##_xchg_release(atomic##prefix##_t *v, c_t n)		\
{									\
	return __xchg_release(&(v->counter), n, size);			\
}									\
static inline							\
c_t atomic##prefix##_xchg(atomic##prefix##_t *v, c_t n)			\
{									\
	return __xchg(&(v->counter), n, size);				\
}									\
static inline							\
c_t atomic##prefix##_cmpxchg_relaxed(atomic##prefix##_t *v,		\
				     c_t o, c_t n)			\
{									\
	return __cmpxchg_relaxed(&(v->counter), o, n, size);		\
}									\
static inline							\
c_t atomic##prefix##_cmpxchg_acquire(atomic##prefix##_t *v,		\
				     c_t o, c_t n)			\
{									\
	return __cmpxchg_acquire(&(v->counter), o, n, size);		\
}									\
static inline							\
c_t atomic##prefix##_cmpxchg_release(atomic##prefix##_t *v,		\
				     c_t o, c_t n)			\
{									\
	return __cmpxchg_release(&(v->counter), o, n, size);		\
}									\
static inline							\
c_t atomic##prefix##_cmpxchg(atomic##prefix##_t *v, c_t o, c_t n)	\
{									\
	return __cmpxchg(&(v->counter), o, n, size);			\
}

#define ATOMIC_OPS()							\
	ATOMIC_OP(int,   , 4)

ATOMIC_OPS()

#define atomic_xchg_relaxed atomic_xchg_relaxed
#define atomic_xchg_acquire atomic_xchg_acquire
#define atomic_xchg_release atomic_xchg_release
#define atomic_xchg atomic_xchg
#define atomic_cmpxchg_relaxed atomic_cmpxchg_relaxed
#define atomic_cmpxchg_acquire atomic_cmpxchg_acquire
#define atomic_cmpxchg_release atomic_cmpxchg_release
#define atomic_cmpxchg atomic_cmpxchg

#undef ATOMIC_OPS
#undef ATOMIC_OP

static inline int atomic_sub_if_positive(atomic_t *v, int offset)
{
       int prev, rc;

	__asm__ __volatile__ (
		"0:	lr.w     %[p],  %[c]\n"
		"	sub      %[rc], %[p], %[o]\n"
		"	bltz     %[rc], 1f\n"
		"	sc.w.rl  %[rc], %[rc], %[c]\n"
		"	bnez     %[rc], 0b\n"
		"	fence    rw, rw\n"
		"1:\n"
		: [p]"=&r" (prev), [rc]"=&r" (rc), [c]"+A" (v->counter)
		: [o]"r" (offset)
		: "memory");
	return prev - offset;
}

#define atomic_dec_if_positive(v)	atomic_sub_if_positive(v, 1)

#endif /* _ASM_RISCV_ATOMIC_H */
