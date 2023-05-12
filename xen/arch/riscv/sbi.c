/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Taken and modified from the xvisor project with the copyright Copyright (c)
 * 2019 Western Digital Corporation or its affiliates and author Anup Patel
 * (anup.patel@wdc.com).
 *
 * Modified by Bobby Eshleman (bobby.eshleman@gmail.com).
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates.
 * Copyright (c) 2021-2023 Vates SAS.
 */

#include <xen/errno.h>
#include <xen/init.h>
#include <xen/smp.h>

#include <asm/system.h>
#include <asm/sbi.h>

unsigned long sbi_spec_version = SBI_SPEC_VERSION_DEFAULT;
unsigned long sbi_fw_id, sbi_fw_version;

struct sbiret sbi_ecall(unsigned long ext, unsigned long fid,
                        unsigned long arg0, unsigned long arg1,
                        unsigned long arg2, unsigned long arg3,
                        unsigned long arg4, unsigned long arg5)
{
    struct sbiret ret;

    register unsigned long a0 asm ("a0") = arg0;
    register unsigned long a1 asm ("a1") = arg1;
    register unsigned long a2 asm ("a2") = arg2;
    register unsigned long a3 asm ("a3") = arg3;
    register unsigned long a4 asm ("a4") = arg4;
    register unsigned long a5 asm ("a5") = arg5;
    register unsigned long a6 asm ("a6") = fid;
    register unsigned long a7 asm ("a7") = ext;

    asm volatile (  "ecall"
                    : "+r" (a0), "+r" (a1)
                    : "r" (a2), "r" (a3), "r" (a4), "r" (a5), "r" (a6), "r" (a7)
                    : "memory");
    ret.error = a0;
    ret.value = a1;

    return ret;
}

int sbi_err_map_xen_errno(int err)
{
    switch (err) {
    case SBI_SUCCESS:
        return 0;
    case SBI_ERR_DENIED:
        return -EACCES;
    case SBI_ERR_INVALID_PARAM:
        return -EINVAL;
    case SBI_ERR_INVALID_ADDRESS:
        return -EFAULT;
    case SBI_ERR_NOT_SUPPORTED:
    case SBI_ERR_FAILURE:
    default:
        return -EOPNOTSUPP;
    };
}

void sbi_cpumask_to_hartmask(const struct cpumask *cmask,
                 struct cpumask *hmask)
{
    u32 cpu;
    unsigned long hart = INVALID_HARTID;

    if (!cmask || !hmask)
        return;

    cpumask_clear(hmask);
    for_each_cpu(cpu, cmask) {
        if (CONFIG_NR_CPUS <= cpu) {
            printk(XENLOG_ERR "SBI: invalid hart=%lu for cpu=%d\n",
                     hart, cpu);
            continue;
        }
        hart = cpuid_to_hartid_map(pcpu_info[cpu].processor_id);
        cpumask_set_cpu(hart, hmask);
    }
}

void sbi_console_putchar(int ch)
{
    sbi_ecall(SBI_EXT_0_1_CONSOLE_PUTCHAR, 0, ch, 0, 0, 0, 0, 0);
}

int sbi_console_getchar(void)
{
    struct sbiret ret;

    ret = sbi_ecall(SBI_EXT_0_1_CONSOLE_GETCHAR, 0, 0, 0, 0, 0, 0, 0);

    return ret.error;
}

void sbi_shutdown(void)
{
    sbi_ecall(SBI_EXT_0_1_SHUTDOWN, 0, 0, 0, 0, 0, 0, 0);
}

void sbi_clear_ipi(void)
{
    sbi_ecall(SBI_EXT_0_1_CLEAR_IPI, 0, 0, 0, 0, 0, 0, 0);
}

static int __sbi_send_ipi_v01(const unsigned long *hart_mask)
{
    sbi_ecall(SBI_EXT_0_1_SEND_IPI, 0,
          (unsigned long)hart_mask, 0, 0, 0, 0, 0);
    return 0;
}

static void __sbi_set_timer_v01(u64 stime_value)
{
#ifdef CONFIG_RISCV_64
    sbi_ecall(SBI_EXT_0_1_SET_TIMER, 0, stime_value, 0, 0, 0, 0, 0);
#else
    sbi_ecall(SBI_EXT_0_1_SET_TIMER, 0, stime_value,
          stime_value >> 32, 0, 0, 0, 0);
#endif
}

static int __sbi_rfence_v01(unsigned long fid,
                const unsigned long *hart_mask,
                unsigned long start, unsigned long size,
                unsigned long arg4, unsigned long arg5)
{
    int result = 0;

    switch (fid) {
    case SBI_EXT_RFENCE_REMOTE_FENCE_I:
        sbi_ecall(SBI_EXT_0_1_REMOTE_FENCE_I, 0,
              (unsigned long)hart_mask, 0, 0, 0, 0, 0);
        break;
    case SBI_EXT_RFENCE_REMOTE_SFENCE_VMA:
        sbi_ecall(SBI_EXT_0_1_REMOTE_SFENCE_VMA, 0,
              (unsigned long)hart_mask, start, size,
              0, 0, 0);
        break;
    case SBI_EXT_RFENCE_REMOTE_SFENCE_VMA_ASID:
        sbi_ecall(SBI_EXT_0_1_REMOTE_SFENCE_VMA_ASID, 0,
              (unsigned long)hart_mask, start, size,
              arg4, 0, 0);
        break;
    default:
        printk("%s: unknown function ID [%lu]\n", __func__, fid);
        result = -EINVAL;
        break;
    };

    return result;
}

static void __sbi_set_timer_v02(u64 stime_value)
{
#ifdef CONFIG_RISCV_64
    sbi_ecall(SBI_EXT_TIME, SBI_EXT_TIME_SET_TIMER, stime_value, 0,
          0, 0, 0, 0);
#else
    sbi_ecall(SBI_EXT_TIME, SBI_EXT_TIME_SET_TIMER, stime_value,
          stime_value >> 32, 0, 0, 0, 0);
#endif
}

static int __sbi_send_ipi_v02(const unsigned long *hart_mask)
{
    struct cpumask tmask;
    unsigned long hart, hmask, hbase;
    struct sbiret ret = {0};
    int result;

    if (!hart_mask) {
        sbi_cpumask_to_hartmask(&cpu_online_map, &tmask);
        hart_mask = cpumask_bits(&tmask);
    }

    hmask = hbase = 0;
    for_each_set_bit(hart, hart_mask, CONFIG_NR_CPUS) {
        if (hmask && ((hbase + BITS_PER_LONG) <= hart)) {
            ret = sbi_ecall(SBI_EXT_IPI, SBI_EXT_IPI_SEND_IPI,
                    hmask, hbase, 0, 0, 0, 0);
            if (ret.error) {
                result = sbi_err_map_xen_errno(ret.error);
                printk("%s: hmask=0x%lx hbase=%lu failed "
                       "(error %d)\n", __func__, hmask,
                       hbase, result);
                return result;
            }
            hmask = hbase = 0;
        }
        if (!hmask) {
            hbase = hart;
        }
        hmask |= 1UL << (hart - hbase);
    }
    if (hmask) {
        ret = sbi_ecall(SBI_EXT_IPI, SBI_EXT_IPI_SEND_IPI,
                hmask, hbase, 0, 0, 0, 0);
        if (ret.error) {
            result = sbi_err_map_xen_errno(ret.error);
            printk("%s: hmask=0x%lx hbase=%lu failed "
                   "(error %d)\n", __func__, hmask,
                   hbase, result);
            return result;
        }
    }

    return 0;
}

static int __sbi_rfence_v02_real(unsigned long fid,
                 unsigned long hmask, unsigned long hbase,
                 unsigned long start, unsigned long size,
                 unsigned long arg4)
{
    struct sbiret ret = {0};
    int result = 0;

    switch (fid) {
    case SBI_EXT_RFENCE_REMOTE_FENCE_I:
        ret = sbi_ecall(SBI_EXT_RFENCE, fid, hmask, hbase,
                0, 0, 0, 0);
        break;
    case SBI_EXT_RFENCE_REMOTE_SFENCE_VMA:
        ret = sbi_ecall(SBI_EXT_RFENCE, fid, hmask, hbase,
                start, size, 0, 0);
        break;
    case SBI_EXT_RFENCE_REMOTE_SFENCE_VMA_ASID:
        ret = sbi_ecall(SBI_EXT_RFENCE, fid, hmask, hbase,
                start, size, arg4, 0);
        break;
    case SBI_EXT_RFENCE_REMOTE_HFENCE_GVMA:
        ret = sbi_ecall(SBI_EXT_RFENCE, fid, hmask, hbase,
                start, size, 0, 0);
        break;
    case SBI_EXT_RFENCE_REMOTE_HFENCE_GVMA_VMID:
        ret = sbi_ecall(SBI_EXT_RFENCE, fid, hmask, hbase,
                start, size, arg4, 0);
        break;
    case SBI_EXT_RFENCE_REMOTE_HFENCE_VVMA:
        ret = sbi_ecall(SBI_EXT_RFENCE, fid, hmask, hbase,
                start, size, 0, 0);
        break;
    case SBI_EXT_RFENCE_REMOTE_HFENCE_VVMA_ASID:
        ret = sbi_ecall(SBI_EXT_RFENCE, fid, hmask, hbase,
                start, size, arg4, 0);
        break;
    default:
        printk("%s: unknown function ID [%lu]\n",
               __func__, fid);
        result = -EINVAL;
        break;
    };

    if (ret.error) {
        result = sbi_err_map_xen_errno(ret.error);
        printk("%s: hbase=%lu hmask=0x%lx failed (error %d)\n",
               __func__, hbase, hmask, result);
    }

    return result;
}

static int __sbi_rfence_v02(unsigned long fid,
                const unsigned long *hart_mask,
                unsigned long start, unsigned long size,
                unsigned long arg4, unsigned long arg5)
{
    struct cpumask tmask;
    unsigned long hart, hmask, hbase;
    int result;

    if (!hart_mask) {
        sbi_cpumask_to_hartmask(&cpu_online_map, &tmask);
        hart_mask = cpumask_bits(&tmask);
    }

    hmask = hbase = 0;
    for_each_set_bit(hart, hart_mask, CONFIG_NR_CPUS) {
        if (hmask && ((hbase + BITS_PER_LONG) <= hart)) {
            result = __sbi_rfence_v02_real(fid, hmask, hbase,
                            start, size, arg4);
            if (result)
                return result;
            hmask = hbase = 0;
        }
        if (!hmask) {
            hbase = hart;
        }
        hmask |= 1UL << (hart - hbase);
    }
    if (hmask) {
        result = __sbi_rfence_v02_real(fid, hmask, hbase,
                        start, size, arg4);
        if (result)
            return result;
    }

    return 0;
}

static void (*__sbi_set_timer)(u64 stime) = __sbi_set_timer_v01;
static int (*__sbi_send_ipi)(const unsigned long *hart_mask) =
                        __sbi_send_ipi_v01;
static int (*__sbi_rfence)(unsigned long fid,
        const unsigned long *hart_mask,
        unsigned long start, unsigned long size,
        unsigned long arg4, unsigned long arg5) = __sbi_rfence_v01;

void sbi_send_ipi(const unsigned long *hart_mask)
{
    __sbi_send_ipi(hart_mask);
}

void sbi_set_timer(u64 stime_value)
{
    __sbi_set_timer(stime_value);
}

void sbi_remote_fence_i(const unsigned long *hart_mask)
{
    __sbi_rfence(SBI_EXT_RFENCE_REMOTE_FENCE_I,
             hart_mask, 0, 0, 0, 0);
}

void sbi_remote_sfence_vma(const unsigned long *hart_mask,
               unsigned long start,
               unsigned long size)
{
    __sbi_rfence(SBI_EXT_RFENCE_REMOTE_SFENCE_VMA,
             hart_mask, start, size, 0, 0);
}

void sbi_remote_sfence_vma_asid(const unsigned long *hart_mask,
                unsigned long start,
                unsigned long size,
                unsigned long asid)
{
    __sbi_rfence(SBI_EXT_RFENCE_REMOTE_SFENCE_VMA_ASID,
             hart_mask, start, size, asid, 0);
}

void sbi_remote_hfence_gvma(const unsigned long *hart_mask,
                unsigned long start,
                unsigned long size)
{
    __sbi_rfence(SBI_EXT_RFENCE_REMOTE_HFENCE_GVMA,
             hart_mask, start, size, 0, 0);
}

void sbi_remote_hfence_gvma_vmid(const unsigned long *hart_mask,
                 unsigned long start,
                 unsigned long size,
                 unsigned long vmid)
{
    __sbi_rfence(SBI_EXT_RFENCE_REMOTE_HFENCE_GVMA_VMID,
             hart_mask, start, size, vmid, 0);
}

void sbi_remote_hfence_vvma(const unsigned long *hart_mask,
                unsigned long start,
                unsigned long size)
{
    __sbi_rfence(SBI_EXT_RFENCE_REMOTE_HFENCE_VVMA,
             hart_mask, start, size, 0, 0);
}

void sbi_remote_hfence_vvma_asid(const unsigned long *hart_mask,
                 unsigned long start,
                 unsigned long size,
                 unsigned long asid)
{
    __sbi_rfence(SBI_EXT_RFENCE_REMOTE_HFENCE_VVMA_ASID,
             hart_mask, start, size, asid, 0);
}

static long sbi_ext_base_func(long fid)
{
    struct sbiret ret;

    ret = sbi_ecall(SBI_EXT_BASE, fid, 0, 0, 0, 0, 0, 0);
    if (!ret.error)
        return ret.value;
    else
        return ret.error;
}

#define sbi_get_spec_version()		\
    sbi_ext_base_func(SBI_EXT_BASE_GET_SPEC_VERSION)

#define sbi_get_firmware_id()		\
    sbi_ext_base_func(SBI_EXT_BASE_GET_IMP_ID)

#define sbi_get_firmware_version()	\
    sbi_ext_base_func(SBI_EXT_BASE_GET_IMP_VERSION)

int sbi_probe_extension(long extid)
{
    struct sbiret ret;

    ret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_PROBE_EXT, extid,
            0, 0, 0, 0, 0);
    if (!ret.error && ret.value)
        return ret.value;

    return -EOPNOTSUPP;
}

int sbi_spec_is_0_1(void)
{
    return (sbi_spec_version == SBI_SPEC_VERSION_DEFAULT) ? 1 : 0;
}

int sbi_has_0_2_rfence(void)
{
    return (__sbi_rfence == __sbi_rfence_v01) ? 0 : 1;
}

unsigned long sbi_major_version(void)
{
    return (sbi_spec_version >> SBI_SPEC_VERSION_MAJOR_SHIFT) &
        SBI_SPEC_VERSION_MAJOR_MASK;
}

unsigned long sbi_minor_version(void)
{
    return sbi_spec_version & SBI_SPEC_VERSION_MINOR_MASK;
}

int __init sbi_init(void)
{
    int ret;

    ret = sbi_get_spec_version();
    if (ret > 0)
        sbi_spec_version = ret;

    printk("SBI specification v%lu.%lu detected\n",
            sbi_major_version(), sbi_minor_version());

    if (!sbi_spec_is_0_1()) {
        sbi_fw_id = sbi_get_firmware_id();
        sbi_fw_version = sbi_get_firmware_version();

        printk("SBI implementation ID=0x%lx Version=0x%lx\n",
            sbi_fw_id, sbi_fw_version);
        if (sbi_probe_extension(SBI_EXT_TIME) > 0) {
            __sbi_set_timer = __sbi_set_timer_v02;
            printk("SBI v0.2 TIME extension detected\n");
        }
        if (sbi_probe_extension(SBI_EXT_IPI) > 0) {
            __sbi_send_ipi = __sbi_send_ipi_v02;
            printk("SBI v0.2 IPI extension detected\n");
        }
        if (sbi_probe_extension(SBI_EXT_RFENCE) > 0) {
            __sbi_rfence = __sbi_rfence_v02;
            printk("SBI v0.2 RFENCE extension detected\n");
        }
    }

    if (!sbi_has_0_2_rfence()) {
        printk("WARNING: SBI v0.2 RFENCE not available !\n");
    }

    return 0;
}

__initcall(sbi_init);
