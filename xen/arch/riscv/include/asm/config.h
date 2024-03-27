/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __RISCV_CONFIG_H__
#define __RISCV_CONFIG_H__

#include <xen/const.h>
#include <xen/page-size.h>

/*
 * RISC-V64 Layout:
 *
#if RV_STAGE1_MODE == SATP_MODE_SV39
 *
 * From the riscv-privileged doc:
 *   When mapping between narrower and wider addresses,
 *   RISC-V zero-extends a narrower physical address to a wider size.
 *   The mapping between 64-bit virtual addresses and the 39-bit usable
 *   address space of Sv39 is not based on zero-extension but instead
 *   follows an entrenched convention that allows an OS to use one or
 *   a few of the most-significant bits of a full-size (64-bit) virtual
 *   address to quickly distinguish user and supervisor address regions.
 *
 * It means that:
 *   top VA bits are simply ignored for the purpose of translating to PA.
 *
 * ============================================================================
 *    Start addr    |   End addr        |  Size  | Slot       |area description
 * ============================================================================
 * FFFFFFFFC0800000 |  FFFFFFFFFFFFFFFF |1016 MB | L2 511     | Unused
 * FFFFFFFFC0600000 |  FFFFFFFFC0800000 |  2 MB  | L2 511     | Fixmap
 * FFFFFFFFC0200000 |  FFFFFFFFC0600000 |  4 MB  | L2 511     | FDT
 * FFFFFFFFC0000000 |  FFFFFFFFC0200000 |  2 MB  | L2 511     | Xen
 *                 ...                  |  1 GB  | L2 510     | Unused
 * 0000003200000000 |  0000007F80000000 | 309 GB | L2 200-509 | Direct map
 *                 ...                  |  1 GB  | L2 199     | Unused
 * 0000003100000000 |  00000031C0000000 |  3 GB  | L2 196-198 | Frametable
 *                 ...                  |  1 GB  | L2 195     | Unused
 * 0000003080000000 |  00000030C0000000 |  1 GB  | L2 194     | VMAP
 *                 ...                  | 194 GB | L2 0 - 193 | Unused
 * ============================================================================
 *
#elif RV_STAGE1_MODE == SATP_MODE_SV48
 * ============================================================================
 *    Start addr    |   End addr        |  Size  | Slot       |area description
 * ============================================================================
 * FFFFFFFFC0800000 |  FFFFFFFFFFFFFFFF |1016 MB | L3 511     | Unused
 * FFFFFFFFC0600000 |  FFFFFFFFC0800000 |  2 MB  | L3 511     | Fixmap
 * FFFFFFFFC0200000 |  FFFFFFFFC0600000 |  4 MB  | L3 511     | FDT
 * FFFFFFFFC0000000 |  FFFFFFFFC0200000 |  2 MB  | L3 511     | Xen
 *                 ...                  |  1 GB  | L3 510     | Unused
 * 0000003200000000 |  0000007F80000000 | 309 GB | L3 200-509 | Direct map
 *                 ...                  |  1 GB  | L3 199     | Unused
 * 0000003100000000 |  00000031C0000000 |  3 GB  | L3 196-198 | Frametable
 *                 ...                  |  1 GB  | L3 195     | Unused
 * 0000003080000000 |  00000030C0000000 |  1 GB  | L3 194     | VMAP
 *                 ...                  | 194 GB | L3 0 - 193 | Unused
 * ============================================================================
#endif
 */

#if defined(CONFIG_RISCV_64)
# define LONG_BYTEORDER 3
# define ELFSIZE 64
# define MAX_VIRT_CPUS 128u
#else
# error "Unsupported RISCV variant"
#endif

#define BYTES_PER_LONG (1 << LONG_BYTEORDER)
#define BITS_PER_LONG  (BYTES_PER_LONG << 3)
#define POINTER_ALIGN  BYTES_PER_LONG

#define BITS_PER_LLONG 64

/* xen_ulong_t is always 64 bits */
#define BITS_PER_XEN_ULONG 64

#define CONFIG_RISCV_L1_CACHE_SHIFT 6
#define CONFIG_PAGEALLOC_MAX_ORDER  18
#define CONFIG_DOMU_MAX_ORDER       9
#define CONFIG_HWDOM_MAX_ORDER      10

#define OPT_CONSOLE_STR "dtuart"
#define INVALID_VCPU_ID MAX_VIRT_CPUS

/* Linkage for RISCV */
#ifdef __ASSEMBLY__
#define ALIGN .align 4

#define ENTRY(name)                                \
  .globl name;                                     \
  ALIGN;                                           \
  name:
#endif

#define VPN_BITS    (9)
#define OFFSET_BITS (12)

#ifdef CONFIG_RISCV_64

#define MAX_XEN_SIZE            MB(2)
#define MAX_FDT_SIZE_           MB(4)
#define MAX_FIXMAP_SIZE         MB(2)

#define SLOTN_ENTRY_BITS        (HYP_PT_ROOT_LEVEL * VPN_BITS + OFFSET_BITS)
#define SLOTN(slot)             (_AT(vaddr_t,slot) << SLOTN_ENTRY_BITS)
#define SLOTN_ENTRY_SIZE        SLOTN(1)

#define XEN_VIRT_START          (0xFFFFFFFFC0000000) /* (_AC(-1, UL) + 1 - GB(1)) */

#define FDT_VIRT_START          (XEN_VIRT_START + MAX_XEN_SIZE)

#define FIXMAP_BASE             (FDT_VIRT_START + MAX_FDT_SIZE_)
#define FIXMAP_ADDR(n)          (FIXMAP_BASE + (n) * PAGE_SIZE)

#define DIRECTMAP_SIZE          (SLOTN_ENTRY_SIZE * (509-200))
#define DIRECTMAP_VIRT_END      (DIRECTMAP_VIRT_START + DIRECTMAP_SIZE - 1)
#define XENHEAP_VIRT_START      directmap_virt_start
#define DIRECTMAP_VIRT_START    SLOTN(200)

#define FRAMETABLE_VIRT_START   SLOTN(196)
#define FRAMETABLE_SIZE         GB(3)
#define FRAMETABLE_NR           (FRAMETABLE_SIZE / sizeof(*frame_table))
#define FRAMETABLE_VIRT_END     (FRAMETABLE_VIRT_START + FRAMETABLE_SIZE - 1)

#define VMAP_VIRT_START         SLOTN(194)
#define VMAP_VIRT_SIZE          GB(1)

#else
#error "RV32 isn't supported"
#endif

#define HYPERVISOR_VIRT_START XEN_VIRT_START

#define SMP_CACHE_BYTES (1 << 6)

#define STACK_SIZE PAGE_SIZE

#ifdef CONFIG_RISCV_64
#define CONFIG_PAGING_LEVELS 4
#define RV_STAGE1_MODE SATP_MODE_SV48
#else
#define CONFIG_PAGING_LEVELS 2
#define RV_STAGE1_MODE SATP_MODE_SV32
#endif

#define HYP_PT_ROOT_LEVEL (CONFIG_PAGING_LEVELS - 1)

#define RAM_BASE  0x4000000000

#endif /* __RISCV_CONFIG_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
