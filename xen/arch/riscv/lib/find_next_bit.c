/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * find_next_bit.c: fallback find next bit implementation
 *
 * Copyright (C) 2004 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */
#include <xen/bitops.h>
#include <asm/types.h>
#include <asm/byteorder.h>

#ifndef find_next_bit
/*
 * Find the next set bit in a memory region.
 */
unsigned long find_next_bit(const unsigned long *addr, unsigned long size,
			    unsigned long offset)
{
	const unsigned long *p = addr + BIT_WORD(offset);
	unsigned long result = offset & ~(BITS_PER_LONG-1);
	unsigned long tmp;

	if (offset >= size)
		return size;
	size -= result;
	offset %= BITS_PER_LONG;
	if (offset) {
		tmp = *(p++);
		tmp &= (~0UL << offset);
		if (size < BITS_PER_LONG)
			goto found_first;
		if (tmp)
			goto found_middle;
		size -= BITS_PER_LONG;
		result += BITS_PER_LONG;
	}
	while (size & ~(BITS_PER_LONG-1)) {
		if ((tmp = *(p++)))
			goto found_middle;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;
	tmp = *p;

found_first:
	tmp &= (~0UL >> (BITS_PER_LONG - size));
	if (tmp == 0UL)		/* Are any bits set? */
		return result + size;	/* Nope. */
found_middle:
	return result + __ffs(tmp);
}
EXPORT_SYMBOL(find_next_bit);
#endif

#ifndef find_next_zero_bit
/*
 * This implementation of find_{first,next}_zero_bit was stolen from
 * Linus' asm-alpha/bitops.h.
 */
unsigned long find_next_zero_bit(const unsigned long *addr, unsigned long size,
				 unsigned long offset)
{
	const unsigned long *p = addr + BIT_WORD(offset);
	unsigned long result = offset & ~(BITS_PER_LONG-1);
	unsigned long tmp;

	if (offset >= size)
		return size;
	size -= result;
	offset %= BITS_PER_LONG;
	if (offset) {
		tmp = *(p++);
		tmp |= ~0UL >> (BITS_PER_LONG - offset);
		if (size < BITS_PER_LONG)
			goto found_first;
		if (~tmp)
			goto found_middle;
		size -= BITS_PER_LONG;
		result += BITS_PER_LONG;
	}
	while (size & ~(BITS_PER_LONG-1)) {
		if (~(tmp = *(p++)))
			goto found_middle;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;
	tmp = *p;

found_first:
	tmp |= ~0UL << size;
	if (tmp == ~0UL)	/* Are any bits zero? */
		return result + size;	/* Nope. */
found_middle:
	return result + ffz(tmp);
}
EXPORT_SYMBOL(find_next_zero_bit);
#endif

#ifndef find_first_bit
/*
 * Find the first set bit in a memory region.
 */
unsigned long find_first_bit(const unsigned long *addr, unsigned long size)
{
	const unsigned long *p = addr;
	unsigned long result = 0;
	unsigned long tmp;

	while (size & ~(BITS_PER_LONG-1)) {
		if ((tmp = *(p++)))
			goto found;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;

	tmp = (*p) & (~0UL >> (BITS_PER_LONG - size));
	if (tmp == 0UL)		/* Are any bits set? */
		return result + size;	/* Nope. */
found:
	return result + __ffs(tmp);
}
EXPORT_SYMBOL(find_first_bit);
#endif

#ifndef find_first_zero_bit
/*
 * Find the first cleared bit in a memory region.
 */
unsigned long find_first_zero_bit(const unsigned long *addr, unsigned long size)
{
	const unsigned long *p = addr;
	unsigned long result = 0;
	unsigned long tmp;

	while (size & ~(BITS_PER_LONG-1)) {
		if (~(tmp = *(p++)))
			goto found;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;

	tmp = (*p) | (~0UL << size);
	if (tmp == ~0UL)	/* Are any bits zero? */
		return result + size;	/* Nope. */
found:
	return result + ffz(tmp);
}
EXPORT_SYMBOL(find_first_zero_bit);
#endif

#ifdef __BIG_ENDIAN

/* include/linux/byteorder does not support "unsigned long" type */
static inline unsigned long ext2_swabp(const unsigned long * x)
{
#if BITS_PER_LONG == 64
	return (unsigned long) __swab64p((u64 *) x);
#elif BITS_PER_LONG == 32
	return (unsigned long) __swab32p((u32 *) x);
#else
#error BITS_PER_LONG not defined
#endif
}

/* include/linux/byteorder doesn't support "unsigned long" type */
static inline unsigned long ext2_swab(const unsigned long y)
{
#if BITS_PER_LONG == 64
	return (unsigned long) __swab64((u64) y);
#elif BITS_PER_LONG == 32
	return (unsigned long) __swab32((u32) y);
#else
#error BITS_PER_LONG not defined
#endif
}

#ifndef find_next_zero_bit_le
unsigned long find_next_zero_bit_le(const void *addr, unsigned
		long size, unsigned long offset)
{
	const unsigned long *p = addr;
	unsigned long result = offset & ~(BITS_PER_LONG - 1);
	unsigned long tmp;

	if (offset >= size)
		return size;
	p += BIT_WORD(offset);
	size -= result;
	offset &= (BITS_PER_LONG - 1UL);
	if (offset) {
		tmp = ext2_swabp(p++);
		tmp |= (~0UL >> (BITS_PER_LONG - offset));
		if (size < BITS_PER_LONG)
			goto found_first;
		if (~tmp)
			goto found_middle;
		size -= BITS_PER_LONG;
		result += BITS_PER_LONG;
	}

	while (size & ~(BITS_PER_LONG - 1)) {
		if (~(tmp = *(p++)))
			goto found_middle_swap;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;
	tmp = ext2_swabp(p);
found_first:
	tmp |= ~0UL << size;
	if (tmp == ~0UL)	/* Are any bits zero? */
		return result + size; /* Nope. Skip ffz */
found_middle:
	return result + ffz(tmp);

found_middle_swap:
	return result + ffz(ext2_swab(tmp));
}
EXPORT_SYMBOL(find_next_zero_bit_le);
#endif

#ifndef find_next_bit_le
unsigned long find_next_bit_le(const void *addr, unsigned
		long size, unsigned long offset)
{
	const unsigned long *p = addr;
	unsigned long result = offset & ~(BITS_PER_LONG - 1);
	unsigned long tmp;

	if (offset >= size)
		return size;
	p += BIT_WORD(offset);
	size -= result;
	offset &= (BITS_PER_LONG - 1UL);
	if (offset) {
		tmp = ext2_swabp(p++);
		tmp &= (~0UL << offset);
		if (size < BITS_PER_LONG)
			goto found_first;
		if (tmp)
			goto found_middle;
		size -= BITS_PER_LONG;
		result += BITS_PER_LONG;
	}

	while (size & ~(BITS_PER_LONG - 1)) {
		tmp = *(p++);
		if (tmp)
			goto found_middle_swap;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;
	tmp = ext2_swabp(p);
found_first:
	tmp &= (~0UL >> (BITS_PER_LONG - size));
	if (tmp == 0UL)		/* Are any bits set? */
		return result + size; /* Nope. */
found_middle:
	return result + __ffs(tmp);

found_middle_swap:
	return result + __ffs(ext2_swab(tmp));
}
EXPORT_SYMBOL(find_next_bit_le);
#endif

#endif /* __BIG_ENDIAN */
