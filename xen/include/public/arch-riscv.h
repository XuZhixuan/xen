/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * arch-riscv.h
 *
 * Guest OS interface to RISC-V Xen.
 * Initially based on the ARM implementation
 *
 * Copyright 2019 (C) Alistair Francis <alistair.francis@wdc.com>
 */

#ifndef __XEN_PUBLIC_ARCH_RISCV_H__
#define __XEN_PUBLIC_ARCH_RISCV_H__

#define  int64_aligned_t  int64_t __attribute__((aligned(8)))
#define uint64_aligned_t uint64_t __attribute__((aligned(8)))

#ifndef __ASSEMBLY__
#define ___DEFINE_XEN_GUEST_HANDLE(name, type)                  \
    typedef union { type *p; unsigned long q; }                 \
        __guest_handle_ ## name;                                \
    typedef union { type *p; uint64_aligned_t q; }              \
        __guest_handle_64_ ## name

/*
 * XEN_GUEST_HANDLE represents a guest pointer, when passed as a field
 * in a struct in memory. On RISCV is always 8 bytes sizes and 8 bytes
 * aligned.
 * XEN_GUEST_HANDLE_PARAM represents a guest pointer, when passed as an
 * hypercall argument. It is 4 bytes on aarch32 and 8 bytes on aarch64.
 */
#define __DEFINE_XEN_GUEST_HANDLE(name, type) \
    ___DEFINE_XEN_GUEST_HANDLE(name, type);   \
    ___DEFINE_XEN_GUEST_HANDLE(const_##name, const type)
#define DEFINE_XEN_GUEST_HANDLE(name)   __DEFINE_XEN_GUEST_HANDLE(name, name)
#define __XEN_GUEST_HANDLE(name)        __guest_handle_64_ ## name
#define XEN_GUEST_HANDLE(name)          __XEN_GUEST_HANDLE(name)
#define XEN_GUEST_HANDLE_PARAM(name)    __guest_handle_ ## name
#define set_xen_guest_handle_raw(hnd, val)                  \
    do {                                                    \
        typeof(&(hnd)) _sxghr_tmp = &(hnd);                 \
        _sxghr_tmp->q = 0;                                  \
        _sxghr_tmp->p = val;                                \
    } while ( 0 )
#define set_xen_guest_handle(hnd, val) set_xen_guest_handle_raw(hnd, val)

typedef uint64_t xen_pfn_t;
#define PRI_xen_pfn PRIx64
#define PRIu_xen_pfn PRIu64

typedef uint64_t xen_ulong_t;
#define PRI_xen_ulong PRIx64

#if defined(__XEN__) || defined(__XEN_TOOLS__)

struct vcpu_guest_context {
};
typedef struct vcpu_guest_context vcpu_guest_context_t;
DEFINE_XEN_GUEST_HANDLE(vcpu_guest_context_t);

struct xen_arch_domainconfig {
};

#endif

struct arch_vcpu_info {
};
typedef struct arch_vcpu_info arch_vcpu_info_t;

struct arch_shared_info {
};
typedef struct arch_shared_info arch_shared_info_t;

/* Maximum number of virtual CPUs in legacy multi-processor guests. */
/* Only one. All other VCPUS must use VCPUOP_register_vcpu_info */
#define XEN_LEGACY_MAX_VCPUS 1

#endif /* __ASSEMBLY__ */

#ifndef __ASSEMBLY__
/* Stub definition of PMU structure */
typedef struct xen_pmu_arch { uint8_t dummy; } xen_pmu_arch_t;
#endif

#endif /*  __XEN_PUBLIC_ARCH_RISCV_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
