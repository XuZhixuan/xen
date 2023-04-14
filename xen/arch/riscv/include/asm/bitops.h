/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2012 Regents of the University of California */

#ifndef _ASM_RISCV_BITOPS_H
#define _ASM_RISCV_BITOPS_H

#include <asm/system.h>

#define BITOP_BITS_PER_WORD     32
#define BITOP_MASK(nr)	        (1UL << ((nr) % BITOP_BITS_PER_WORD))
#define BITOP_WORD(nr)	        ((nr) / BITOP_BITS_PER_WORD)
#define BITS_PER_BYTE	        8

#define __set_bit(n,p)          set_bit(n,p)
#define __clear_bit(n,p)        clear_bit(n,p)

#define __AMO(op)	"amo" #op ".w"

#define __test_and_op_bit_ord(op, mod, nr, addr, ord)		\
({								\
	unsigned long __res, __mask;				\
	__mask = BITOP_MASK(nr);					\
	__asm__ __volatile__ (					\
		__AMO(op) #ord " %0, %2, %1"			\
		: "=r" (__res), "+A" (addr[BITOP_WORD(nr)])	\
		: "r" (mod(__mask))				\
		: "memory");					\
	((__res & __mask) != 0);				\
})

#define __op_bit_ord(op, mod, nr, addr, ord)			\
	__asm__ __volatile__ (					\
		__AMO(op) #ord " zero, %1, %0"			\
		: "+A" (addr[BITOP_WORD(nr)])			\
		: "r" (mod(BITOP_MASK(nr)))			\
		: "memory");

#define __test_and_op_bit(op, mod, nr, addr) 			\
	__test_and_op_bit_ord(op, mod, nr, addr, .aqrl)

#define __op_bit(op, mod, nr, addr)				\
	__op_bit_ord(op, mod, nr, addr, )

/* Bitmask modifiers */
#define __NOP(x)	(x)
#define __NOT(x)	(~(x))

/**
 * __test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation may be reordered on other architectures than x86.
 */
static inline int __test_and_set_bit(int nr, volatile void *p)
{
	volatile uint32_t *addr = p;

	return __test_and_op_bit(or, __NOP, nr, addr);
}

/**
 * __test_and_clear_bit - Clear a bit and return its old value
 * @nr: Bit to clear
 * @addr: Address to count from
 *
 * This operation can be reordered on other architectures other than x86.
 */
static inline int __test_and_clear_bit(int nr, volatile void *p)
{
	volatile uint32_t *addr = p;

	return __test_and_op_bit(and, __NOT, nr, addr);
}

/**
 * set_bit - Atomically set a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * Note: there are no guarantees that this function will not be reordered
 * on non x86 architectures, so if you are writing portable code,
 * make sure not to rely on its reordering guarantees.
 *
 * Note that @nr may be almost arbitrarily large; this function is not
 * restricted to acting on a single-word quantity.
 */
static inline void set_bit(int nr, volatile void *p)
{
	volatile uint32_t *addr = p;

	__op_bit(or, __NOP, nr, addr);
}

/**
 * clear_bit - Clears a bit in memory
 * @nr: Bit to clear
 * @addr: Address to start counting from
 *
 * Note: there are no guarantees that this function will not be reordered
 * on non x86 architectures, so if you are writing portable code,
 * make sure not to rely on its reordering guarantees.
 */
static inline void clear_bit(int nr, volatile void *p)
{
	volatile uint32_t *addr = p;

	__op_bit(and, __NOT, nr, addr);
}

static inline int test_bit(int nr, const volatile void *p)
{
	const volatile uint32_t *addr = (const volatile uint32_t *)p;

	return 1UL & (addr[BITOP_WORD(nr)] >> (nr & (BITOP_BITS_PER_WORD-1)));
}

#undef __test_and_op_bit
#undef __op_bit
#undef __NOP
#undef __NOT
#undef __AMO

static inline int fls(unsigned int x)
{
    return generic_fls(x);
}

static inline int flsl(unsigned long x)
{
   return generic_flsl(x);
}


#define test_and_set_bit   __test_and_set_bit
#define test_and_clear_bit __test_and_clear_bit

/* Based on linux/include/asm-generic/bitops/find.h */

#ifndef find_next_bit
/**
 * find_next_bit - find the next set bit in a memory region
 * @addr: The address to base the search on
 * @offset: The bitnumber to start searching at
 * @size: The bitmap size in bits
 */
extern unsigned long find_next_bit(const unsigned long *addr, unsigned long
		size, unsigned long offset);
#endif

#ifndef find_next_zero_bit
/**
 * find_next_zero_bit - find the next cleared bit in a memory region
 * @addr: The address to base the search on
 * @offset: The bitnumber to start searching at
 * @size: The bitmap size in bits
 */
extern unsigned long find_next_zero_bit(const unsigned long *addr, unsigned
		long size, unsigned long offset);
#endif

/**
 * find_first_bit - find the first set bit in a memory region
 * @addr: The address to start the search at
 * @size: The maximum size to search
 *
 * Returns the bit number of the first set bit.
 */
extern unsigned long find_first_bit(const unsigned long *addr,
				    unsigned long size);

/**
 * find_first_zero_bit - find the first cleared bit in a memory region
 * @addr: The address to start the search at
 * @size: The maximum size to search
 *
 * Returns the bit number of the first cleared bit.
 */
extern unsigned long find_first_zero_bit(const unsigned long *addr,
					 unsigned long size);

#define ffs(x) ({ unsigned int __t = (x); fls(__t & -__t); })
/**
 * ffs - find first bit in word.
 * @word: The word to search
 *
 * Returns 0 if no bit exists, otherwise returns 1-indexed bit location.
 */
static inline unsigned long __ffs(unsigned long word)
{
	int num = 0;

#if BITS_PER_LONG == 64
	if ((word & 0xffffffff) == 0) {
		num += 32;
		word >>= 32;
	}
#endif
	if ((word & 0xffff) == 0) {
		num += 16;
		word >>= 16;
	}
	if ((word & 0xff) == 0) {
		num += 8;
		word >>= 8;
	}
	if ((word & 0xf) == 0) {
		num += 4;
		word >>= 4;
	}
	if ((word & 0x3) == 0) {
		num += 2;
		word >>= 2;
	}
	if ((word & 0x1) == 0)
		num += 1;
	return num;
}

/**
 * ffsl - find first bit in long.
 * @word: The word to search
 *
 * Returns 0 if no bit exists, otherwise returns 1-indexed bit location.
 */
static inline unsigned int ffsl(unsigned long word)
{
    int num = 1;

    if (!word)
        return 0;

#if BITS_PER_LONG == 64
    if ((word & 0xffffffff) == 0) {
        num += 32;
        word >>= 32;
    }
#endif
    if ((word & 0xffff) == 0) {
        num += 16;
        word >>= 16;
    }
    if ((word & 0xff) == 0) {
        num += 8;
        word >>= 8;
    }
    if ((word & 0xf) == 0) {
        num += 4;
        word >>= 4;
    }
    if ((word & 0x3) == 0) {
        num += 2;
        word >>= 2;
    }
    if ((word & 0x1) == 0)
        num += 1;
    return num;
}

/*
 * ffz - find first zero in word.
 * @word: The word to search
 *
 * Undefined if no zero exists, so code should check against ~0UL first.
 */
#define ffz(x)  __ffs(~(x))

/**
 * find_first_set_bit - find the first set bit in @word
 * @word: the word to search
 *
 * Returns the bit-number of the first set bit (first bit being 0).
 * The input must *not* be zero.
 */
static inline unsigned int find_first_set_bit(unsigned long word)
{
        return ffsl(word) - 1;
}

/**
 * hweightN - returns the hamming weight of a N-bit word
 * @x: the word to weigh
 *
 * The Hamming Weight of a number is the total number of bits set in it.
 */
#define hweight64(x) generic_hweight64(x)

#endif /* _ASM_RISCV_BITOPS_H */
