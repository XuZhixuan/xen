#ifndef __H_DOMAIN_BUILD
#define __H_DOMAIN_BUILD

#include <xen/sched.h>
#include <asm/kernel.h>

#define GUEST_RAM_BANKS   2

#define GUEST_RAM0_BASE   0x80000000UL /* 3GB of low RAM @ 1GB */
#define GUEST_RAM0_SIZE   0x40000000UL

#define GUEST_RAM1_BASE   0x0200000000UL /* 1016GB of RAM @ 8GB */
#define GUEST_RAM1_SIZE   0xfe00000000UL

#define GUEST_RAM_BASE    GUEST_RAM0_BASE /* Lowest RAM address */
/* Largest amount of actual RAM, not including holes */
#define GUEST_RAM_MAX     (GUEST_RAM0_SIZE + GUEST_RAM1_SIZE)
/* Suitable for e.g. const uint64_t ramfoo[] = GUEST_RAM_BANK_FOOS; */
#define GUEST_RAM_BANK_BASES   { GUEST_RAM0_BASE, GUEST_RAM1_BASE }
#define GUEST_RAM_BANK_SIZES   { GUEST_RAM0_SIZE, GUEST_RAM1_SIZE }

/* Current supported guest VCPUs */
#define GUEST_MAX_VCPUS 128

#endif // __H_DOMAIN_BUILD
