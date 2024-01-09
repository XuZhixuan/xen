#ifndef __ASM_RISCV_CPUFEATURE_H
#define __ASM_RISCV_CPUFEATURE_H

#define RISCV_ISA_EXT_a ('a' - 'a')
#define RISCV_ISA_EXT_b ('b' - 'a')
#define RISCV_ISA_EXT_c ('c' - 'a')
#define RISCV_ISA_EXT_d ('d' - 'a')
#define RISCV_ISA_EXT_f ('f' - 'a')
#define RISCV_ISA_EXT_h ('h' - 'a')
#define RISCV_ISA_EXT_i ('i' - 'a')
#define RISCV_ISA_EXT_j ('j' - 'a')
#define RISCV_ISA_EXT_k ('k' - 'a')
#define RISCV_ISA_EXT_m ('m' - 'a')
#define RISCV_ISA_EXT_p ('p' - 'a')
#define RISCV_ISA_EXT_q ('q' - 'a')
#define RISCV_ISA_EXT_s ('s' - 'a')
#define RISCV_ISA_EXT_u ('u' - 'a')
#define RISCV_ISA_EXT_v ('v' - 'a')

/*
 * These macros represent the logical IDs of each multi-letter RISC-V ISA
 * extension and are used in the ISA bitmap. The logical IDs start from
 * RISCV_ISA_EXT_BASE, which allows the 0-25 range to be reserved for single
 * letter extensions. The maximum, RISCV_ISA_EXT_MAX, is defined in order
 * to allocate the bitmap and may be increased when necessary.
 *
 * New extensions should just be added to the bottom, rather than added
 * alphabetically, in order to avoid unnecessary shuffling.
 */
#define RISCV_ISA_EXT_BASE          26

#define RISCV_ISA_EXT_SSCOFPMF      26
#define RISCV_ISA_EXT_SSTC          27
#define RISCV_ISA_EXT_SVINVAL       28
#define RISCV_ISA_EXT_SVPBMT        29
#define RISCV_ISA_EXT_ZBB           30
#define RISCV_ISA_EXT_ZICBOM        31
#define RISCV_ISA_EXT_ZIHINTPAUSE   32
#define RISCV_ISA_EXT_SVNAPOT       33
#define RISCV_ISA_EXT_ZICBOZ        34
#define RISCV_ISA_EXT_SMAIA         35
#define RISCV_ISA_EXT_SSAIA         36
#define RISCV_ISA_EXT_ZBA           37
#define RISCV_ISA_EXT_ZBS           38
#define RISCV_ISA_EXT_ZICNTR        39
#define RISCV_ISA_EXT_ZICSR         40
#define RISCV_ISA_EXT_ZIFENCEI      41
#define RISCV_ISA_EXT_ZIHPM         42
#define RISCV_ISA_EXT_SMSTATEEN     43
#define RISCV_ISA_EXT_ZICOND        44

#define RISCV_ISA_EXT_MAX           64

/*
 * Linux saves the floating-point registers according to the ISA Linux is
 * executing on, as opposed to the ISA the user program is compiled for.  This
 * is necessary for a handful of esoteric use cases: for example, userspace
 * threading libraries must be able to examine the actual machine state in
 * order to fully reconstruct the state of a thread.
 */
#define COMPAT_HWCAP_ISA_I  (1 << ('I' - 'A'))
#define COMPAT_HWCAP_ISA_M  (1 << ('M' - 'A'))
#define COMPAT_HWCAP_ISA_A  (1 << ('A' - 'A'))
#define COMPAT_HWCAP_ISA_F  (1 << ('F' - 'A'))
#define COMPAT_HWCAP_ISA_D  (1 << ('D' - 'A'))
#define COMPAT_HWCAP_ISA_C  (1 << ('C' - 'A'))
#define COMPAT_HWCAP_ISA_V  (1 << ('V' - 'A'))

#ifndef __ASSEMBLY__

static inline int cpu_nr_siblings(unsigned int cpu)
{
    return 1;
}

void riscv_fill_hwcap(void);

bool __riscv_isa_extension_available(const unsigned long *isa_bitmap, int bit);
#define riscv_isa_extension_available(isa_bitmap, ext)  \
    __riscv_isa_extension_available(isa_bitmap, RISCV_ISA_EXT_##ext)

#endif /* __ASSEMBLY__ */

#endif
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

