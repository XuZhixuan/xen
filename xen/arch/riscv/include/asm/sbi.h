/* SPDX-License-Identifier: (GPL-2.0-or-later) */
/*
 * Copyright (c) 2021-2023 Vates SAS.
 *
 * Taken from xvisor, modified by Bobby Eshleman (bobby.eshleman@gmail.com).
 *
 * Taken/modified from Xvisor project with the following copyright:
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates.
 */

#ifndef __ASM_RISCV_SBI_H__
#define __ASM_RISCV_SBI_H__

#include <xen/types.h>

/* SBI Extension IDs */
#define SBI_EXT_0_1_SET_TIMER               0x0
#define SBI_EXT_0_1_CONSOLE_PUTCHAR         0x1
#define SBI_EXT_0_1_CONSOLE_GETCHAR         0x2
#define SBI_EXT_0_1_CLEAR_IPI               0x3
#define SBI_EXT_0_1_SEND_IPI                0x4
#define SBI_EXT_0_1_REMOTE_FENCE_I          0x5
#define SBI_EXT_0_1_REMOTE_SFENCE_VMA       0x6
#define SBI_EXT_0_1_REMOTE_SFENCE_VMA_ASID  0x7
#define SBI_EXT_0_1_SHUTDOWN                0x8
#define SBI_EXT_BASE                        0x10
#define SBI_EXT_TIME                        0x54494D45
#define SBI_EXT_IPI                         0x735049
#define SBI_EXT_RFENCE                      0x52464E43
#define SBI_EXT_HSM                         0x48534D

/* SBI function IDs for BASE extension */
#define SBI_EXT_BASE_GET_SPEC_VERSION   0x0
#define SBI_EXT_BASE_GET_IMP_ID         0x1
#define SBI_EXT_BASE_GET_IMP_VERSION    0x2
#define SBI_EXT_BASE_PROBE_EXT          0x3
#define SBI_EXT_BASE_GET_MVENDORID      0x4
#define SBI_EXT_BASE_GET_MARCHID        0x5
#define SBI_EXT_BASE_GET_MIMPID         0x6

#define SBI_SPEC_VERSION_MAJOR_SHIFT            24
#define SBI_SPEC_VERSION_MAJOR_MASK             0x7f
#define SBI_SPEC_VERSION_MINOR_MASK             0xffffff

/* SBI function IDs for TIME extension */
#define SBI_EXT_TIME_SET_TIMER                  0x0

/* SBI function IDs for IPI extension */
#define SBI_EXT_IPI_SEND_IPI                    0x0

/* SBI function IDs for RFENCE extension */
#define SBI_EXT_RFENCE_REMOTE_FENCE_I           0x0
#define SBI_EXT_RFENCE_REMOTE_SFENCE_VMA        0x1
#define SBI_EXT_RFENCE_REMOTE_SFENCE_VMA_ASID   0x2
#define SBI_EXT_RFENCE_REMOTE_HFENCE_GVMA       0x3
#define SBI_EXT_RFENCE_REMOTE_HFENCE_GVMA_VMID  0x4
#define SBI_EXT_RFENCE_REMOTE_HFENCE_VVMA       0x5
#define SBI_EXT_RFENCE_REMOTE_HFENCE_VVMA_ASID  0x6

#define SBI_EXT_VENDOR_START    0x09000000
#define SBI_EXT_VENDOR_END      0x09FFFFFF

/* SBI return error codes */
#define SBI_SUCCESS             0
#define SBI_ERR_FAILURE         -1
#define SBI_ERR_NOT_SUPPORTED   -2
#define SBI_ERR_INVALID_PARAM   -3
#define SBI_ERR_DENIED          -4
#define SBI_ERR_INVALID_ADDRESS -5
#define SBI_ERR_ALREADY_AVAILABLE -6
#define SBI_ERR_ALREADY_STARTED   -7
#define SBI_ERR_ALREADY_STOPPED   -8

#define SBI_SPEC_VERSION_DEFAULT	0x1

enum sbi_ext_hsm_fid {
	SBI_EXT_HSM_HART_START = 0,
	SBI_EXT_HSM_HART_STOP,
	SBI_EXT_HSM_HART_STATUS,
	SBI_EXT_HSM_HART_SUSPEND,
};

struct cpumask;

extern unsigned long sbi_spec_version;
extern unsigned long sbi_fw_id, sbi_fw_version;
struct sbiret {
    long error;
    long value;
};

struct sbiret sbi_ecall(unsigned long ext, unsigned long fid,
                        unsigned long arg0, unsigned long arg1,
                        unsigned long arg2, unsigned long arg3,
                        unsigned long arg4, unsigned long arg5);

int sbi_hsm_hart_start(unsigned long hartid, unsigned long saddr,
                       unsigned long priv);

/*
 * Convert SBI spec error code into Xvisor error code
 *
 * @return errno error code
 */
int sbi_err_map_xvisor_errno(int err);

/*
 * Convert logical CPU mask to hardware HART mask
 *
 * @param cmask input logical CPU mask
 * @param hmask output hardware HART mask
 */
void sbi_cpumask_to_hartmask(const struct cpumask *cmask,
                             struct cpumask *hmask);

/*
 * Writes given character to the console device.
 *
 * @param ch The data to be written to the console.
 */
void sbi_console_putchar(int ch);

/*
 * Reads a character from console device.
 *
 * @return the character read from console
 */
int sbi_console_getchar(void);

/*
 * Remove all the harts from executing supervisor code.
 */
void sbi_shutdown(void);

/*
 * Clear any pending IPIs for the calling HART.
 */
void sbi_clear_ipi(void);

/*
 * Send IPIs to a set of target HARTs.
 *
 * @param hart_mask mask representing set of target HARTs
 */
void sbi_send_ipi(const unsigned long *hart_mask);

/*
 * Program the timer for next timer event.
 *
 * @param stime_value Timer value after which next timer event should fire.
 */
void sbi_set_timer(u64 stime_value);

/*
 * Send FENCE_I to a set of target HARTs.
 *
 * @param hart_mask mask representing set of target HARTs
 */
void sbi_remote_fence_i(const unsigned long *hart_mask);

/*
 * Send SFENCE_VMA to a set of target HARTs.
 *
 * @param hart_mask mask representing set of target HARTs
 * @param start virtual address start
 * @param size virtual address size
 */
void sbi_remote_sfence_vma(const unsigned long *hart_mask,
                           unsigned long start,
                           unsigned long size);

/*
 * Send SFENCE_VMA_ASID to a set of target HARTs.
 *
 * @param hart_mask mask representing set of target HARTs
 * @param start virtual address start
 * @param size virtual address size
 * @param asid address space ID
 */
void sbi_remote_sfence_vma_asid(const unsigned long *hart_mask,
                                unsigned long start,
                                unsigned long size,
                                unsigned long asid);

/*
 * Send HFENCE_GVMA to a set of target HARTs.
 *
 * @param hart_mask mask representing set of target HARTs
 * @param start guest physical address start
 * @param size guest physical address size
 */
void sbi_remote_hfence_gvma(const unsigned long *hart_mask,
                            unsigned long start,
                            unsigned long size);

/*
 * Send HFENCE_GVMA_VMID to a set of target HARTs.
 *
 * @param hart_mask mask representing set of target HARTs
 * @param start guest physical address start
 * @param size guest physical address size
 * @param vmid virtual machine ID
 */
void sbi_remote_hfence_gvma_vmid(const unsigned long *hart_mask,
                                 unsigned long start,
                                 unsigned long size,
                                 unsigned long vmid);

/*
 * Send HFENCE_VVMA to a set of target HARTs.
 *
 * @param hart_mask mask representing set of target HARTs
 * @param start virtual address start
 * @param size virtual address size
 */
void sbi_remote_hfence_vvma(const unsigned long *hart_mask,
                            unsigned long start,
                            unsigned long size);

/*
 * Send HFENCE_VVMA_ASID to a set of target HARTs.
 *
 * @param hart_mask mask representing set of target HARTs
 * @param start virtual address start
 * @param size virtual address size
 * @param asid address space ID
 */
void sbi_remote_hfence_vvma_asid(const unsigned long *hart_mask,
                                 unsigned long start,
                                 unsigned long size,
                                 unsigned long asid);

/*
 * Check given SBI extension is supported or not.
 *
 * @param ext extension ID
 * @return >= 0 for supported AND -EOPNOTSUPP for not-supported
 */
int sbi_probe_extension(long ext);

/*
 * Check underlying SBI implementation is v0.1 only
 *
 * @return 1 for SBI v0.1 AND 0 for higer version
 */
int sbi_spec_is_0_1(void);

/*
 * Check underlying SBI implementation has v0.2 RFENCE
 *
 * @return 1 for supported AND 0 for not-supported
 */
int sbi_has_0_2_rfence(void);

/*
 * Get SBI spec major version
 *
 * @return major version number
 */
unsigned long sbi_major_version(void);

/**
 * Get SBI spec minor version
 *
 * @return minor version number
 */
unsigned long sbi_minor_version(void);

/*
 * Initialize SBI library
 *
 * @return 0 on success, otherwise negative errno on failure
 */
int sbi_init(void);

#endif /* __ASM_RISCV_SBI_H__ */
