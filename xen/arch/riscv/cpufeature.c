/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Taken from Linux kernel,
 * modified by Oleksii Kurochko (oleksii.kurochko@gmail.com).
 *
 * Copyright (C) 2017 SiFive
 * Copyright (C) 2024 Vates
 */

#include <xen/bitmap.h>
#include <xen/cpumask.h>
#include <xen/ctype.h>
#include <xen/device_tree.h>
#include <xen/errno.h>
#include <xen/init.h>

#include <asm/acpi.h>
#include <asm/cpufeature.h>

struct riscv_isainfo {
    DECLARE_BITMAP(isa, RISCV_ISA_EXT_MAX);
};

struct riscv_isa_ext_data {
    const unsigned int id;
    const char *name;
    const char *property;
};

#define NUM_ALPHA_EXTS ('z' - 'a' + 1)

bool __initdata riscv_isa_fallback = true;

unsigned long elf_hwcap __read_mostly;

/* Host ISA bitmap */
static DECLARE_BITMAP(riscv_isa, RISCV_ISA_EXT_MAX) __read_mostly;

/* Per-cpu ISA extensions. */
static struct riscv_isainfo hart_isa[NR_CPUS];

/* 
 * TODO: I don't know the proper place for these variables.
 *       In the Linux kernel, they are defined in riscv/mm/cacheflush.c, but there
 *       is no such file in Xen.
 *       Considering we don't implement extensions RISCV_ISA_EXT_ZICBOM and
 *       RISCV_ISA_EXT_ZICBOZ, these variables can be located here for the time
 *       being.
 */
unsigned int riscv_cbom_block_size;
unsigned int riscv_cboz_block_size;

static inline int is_power_of_2(unsigned long word)
{
    return ( word & -word ) == word;
}

/**
 * __riscv_isa_extension_available() - Check whether given extension
 * is available or not
 *
 * @isa_bitmap: ISA bitmap to use
 * @bit: bit position of the desired extension
 * Return: true or false
 *
 * NOTE: If isa_bitmap is NULL then Host ISA bitmap will be used.
 */
bool __riscv_isa_extension_available(const unsigned long *isa_bitmap, int bit)
{
    const unsigned long *bmap = (isa_bitmap) ? isa_bitmap : riscv_isa;

    if ( bit >= RISCV_ISA_EXT_MAX )
        return false;

    return test_bit(bit, bmap) ? true : false;
}

static bool riscv_isa_extension_check(int id)
{
    switch (id) {
    case RISCV_ISA_EXT_ZICBOM:
        if (!riscv_cbom_block_size) {
            printk(XENLOG_ERR "Zicbom detected in ISA string, disabling as no cbom-block-size found\n");
            return false;
        } else if (!is_power_of_2(riscv_cbom_block_size)) {
            printk(XENLOG_ERR "Zicbom disabled as cbom-block-size present, but is not a power-of-2\n");
            return false;
        }
        return true;
    case RISCV_ISA_EXT_ZICBOZ:
        if (!riscv_cboz_block_size) {
            printk(XENLOG_ERR "Zicboz detected in ISA string, but no cboz-block-size found\n");
            return false;
        } else if (!is_power_of_2(riscv_cboz_block_size)) {
            printk(XENLOG_ERR "cboz-block-size present, but is not a power-of-2\n");
            return false;
        }
        return true;
    }

    return true;
}

#define __RISCV_ISA_EXT_DATA(_name, _id) {  \
    .name = #_name,                         \
    .property = #_name,                     \
    .id = _id,                              \
}

/*
 * The canonical order of ISA extension names in the ISA string is defined in
 * chapter 27 of the unprivileged specification.
 *
 * Ordinarily, for in-kernel data structures, this order is unimportant but
 * isa_ext_arr defines the order of the ISA string in /proc/cpuinfo.
 *
 * The specification uses vague wording, such as should, when it comes to
 * ordering, so for our purposes the following rules apply:
 *
 * 1. All multi-letter extensions must be separated from other extensions by an
 *    underscore.
 *
 * 2. Additional standard extensions (starting with 'Z') must be sorted after
 *    single-letter extensions and before any higher-privileged extensions.
 *
 * 3. The first letter following the 'Z' conventionally indicates the most
 *    closely related alphabetical extension category, IMAFDQLCBKJTPVH.
 *    If multiple 'Z' extensions are named, they must be ordered first by
 *    category, then alphabetically within a category.
 *
 * 3. Standard supervisor-level extensions (starting with 'S') must be listed
 *    after standard unprivileged extensions.  If multiple supervisor-level
 *    extensions are listed, they must be ordered alphabetically.
 *
 * 4. Standard machine-level extensions (starting with 'Zxm') must be listed
 *    after any lower-privileged, standard extensions.  If multiple
 *    machine-level extensions are listed, they must be ordered
 *    alphabetically.
 *
 * 5. Non-standard extensions (starting with 'X') must be listed after all
 *    standard extensions. If multiple non-standard extensions are listed, they
 *    must be ordered alphabetically.
 *
 * An example string following the order is:
 *    rv64imadc_zifoo_zigoo_zafoo_sbar_scar_zxmbaz_xqux_xrux
 *
 * New entries to this struct should follow the ordering rules described above.
 */
const struct riscv_isa_ext_data riscv_isa_ext[] = {
    __RISCV_ISA_EXT_DATA(i, RISCV_ISA_EXT_i),
    __RISCV_ISA_EXT_DATA(m, RISCV_ISA_EXT_m),
    __RISCV_ISA_EXT_DATA(a, RISCV_ISA_EXT_a),
    __RISCV_ISA_EXT_DATA(f, RISCV_ISA_EXT_f),
    __RISCV_ISA_EXT_DATA(d, RISCV_ISA_EXT_d),
    __RISCV_ISA_EXT_DATA(q, RISCV_ISA_EXT_q),
    __RISCV_ISA_EXT_DATA(c, RISCV_ISA_EXT_c),
    __RISCV_ISA_EXT_DATA(b, RISCV_ISA_EXT_b),
    __RISCV_ISA_EXT_DATA(k, RISCV_ISA_EXT_k),
    __RISCV_ISA_EXT_DATA(j, RISCV_ISA_EXT_j),
    __RISCV_ISA_EXT_DATA(p, RISCV_ISA_EXT_p),
    __RISCV_ISA_EXT_DATA(v, RISCV_ISA_EXT_v),
    __RISCV_ISA_EXT_DATA(h, RISCV_ISA_EXT_h),
    __RISCV_ISA_EXT_DATA(zicbom, RISCV_ISA_EXT_ZICBOM),
    __RISCV_ISA_EXT_DATA(zicboz, RISCV_ISA_EXT_ZICBOZ),
    __RISCV_ISA_EXT_DATA(zicntr, RISCV_ISA_EXT_ZICNTR),
    __RISCV_ISA_EXT_DATA(zicond, RISCV_ISA_EXT_ZICOND),
    __RISCV_ISA_EXT_DATA(zicsr, RISCV_ISA_EXT_ZICSR),
    __RISCV_ISA_EXT_DATA(zifencei, RISCV_ISA_EXT_ZIFENCEI),
    __RISCV_ISA_EXT_DATA(zihintpause, RISCV_ISA_EXT_ZIHINTPAUSE),
    __RISCV_ISA_EXT_DATA(zihpm, RISCV_ISA_EXT_ZIHPM),
    __RISCV_ISA_EXT_DATA(zba, RISCV_ISA_EXT_ZBA),
    __RISCV_ISA_EXT_DATA(zbb, RISCV_ISA_EXT_ZBB),
    __RISCV_ISA_EXT_DATA(zbs, RISCV_ISA_EXT_ZBS),
    __RISCV_ISA_EXT_DATA(smaia, RISCV_ISA_EXT_SMAIA),
    __RISCV_ISA_EXT_DATA(smstateen, RISCV_ISA_EXT_SMSTATEEN),
    __RISCV_ISA_EXT_DATA(ssaia, RISCV_ISA_EXT_SSAIA),
    __RISCV_ISA_EXT_DATA(sscofpmf, RISCV_ISA_EXT_SSCOFPMF),
    __RISCV_ISA_EXT_DATA(sstc, RISCV_ISA_EXT_SSTC),
    __RISCV_ISA_EXT_DATA(svinval, RISCV_ISA_EXT_SVINVAL),
    __RISCV_ISA_EXT_DATA(svnapot, RISCV_ISA_EXT_SVNAPOT),
    __RISCV_ISA_EXT_DATA(svpbmt, RISCV_ISA_EXT_SVPBMT),
};

const size_t riscv_isa_ext_count = ARRAY_SIZE(riscv_isa_ext);

static void __init riscv_parse_isa_string(unsigned long *this_hwcap,
                                          struct riscv_isainfo *isainfo,
                                          unsigned long *isa2hwcap,
                                          const char *isa)
{
    /*
     * For all possible cpus, we have already validated in
     * the boot process that they at least contain "rv" and
     * whichever of "32"/"64" this kernel supports, and so this
     * section can be skipped.
     */
    isa += 4;

    while (*isa) {
        const char *ext = isa++;
        const char *ext_end = isa;
        bool ext_long = false, ext_err = false;

        switch (*ext) {
        case 's':
            /*
             * Workaround for invalid single-letter 's' & 'u'(QEMU).
             * No need to set the bit in riscv_isa as 's' & 'u' are
             * not valid ISA extensions. It works until multi-letter
             * extension starting with "Su" appears.
             */
            if (ext[-1] != '_' && ext[1] == 'u') {
                ++isa;
                ext_err = true;
                break;
            }
            fallthrough;
        case 'S':
        case 'x':
        case 'X':
        case 'z':
        case 'Z':
            /*
             * Before attempting to parse the extension itself, we find its end.
             * As multi-letter extensions must be split from other multi-letter
             * extensions with an "_", the end of a multi-letter extension will
             * either be the null character or the "_" at the start of the next
             * multi-letter extension.
             *
             * Next, as the extensions version is currently ignored, we
             * eliminate that portion. This is done by parsing backwards from
             * the end of the extension, removing any numbers. This may be a
             * major or minor number however, so the process is repeated if a
             * minor number was found.
             *
             * ext_end is intended to represent the first character *after* the
             * name portion of an extension, but will be decremented to the last
             * character itself while eliminating the extensions version number.
             * A simple re-increment solves this problem.
             */
            ext_long = true;
            for (; *isa && *isa != '_'; ++isa)
                if (unlikely(!isalnum(*isa)))
                    ext_err = true;

            ext_end = isa;
            if (unlikely(ext_err))
                break;

            if (!isdigit(ext_end[-1]))
                break;

            while (isdigit(*--ext_end))
                ;

            if (tolower(ext_end[0]) != 'p' || !isdigit(ext_end[-1])) {
                ++ext_end;
                break;
            }

            while (isdigit(*--ext_end))
                ;

            ++ext_end;
            break;
        default:
            /*
             * Things are a little easier for single-letter extensions, as they
             * are parsed forwards.
             *
             * After checking that our starting position is valid, we need to
             * ensure that, when isa was incremented at the start of the loop,
             * that it arrived at the start of the next extension.
             *
             * If we are already on a non-digit, there is nothing to do. Either
             * we have a multi-letter extension's _, or the start of an
             * extension.
             *
             * Otherwise we have found the current extension's major version
             * number. Parse past it, and a subsequent p/minor version number
             * if present. The `p` extension must not appear immediately after
             * a number, so there is no fear of missing it.
             *
             */
            if (unlikely(!isalpha(*ext))) {
                ext_err = true;
                break;
            }

            if (!isdigit(*isa))
                break;

            while (isdigit(*++isa))
                ;

            if (tolower(*isa) != 'p')
                break;

            if (!isdigit(*++isa)) {
                --isa;
                break;
            }

            while (isdigit(*++isa))
                ;

            break;
        }

        /*
         * The parser expects that at the start of an iteration isa points to the
         * first character of the next extension. As we stop parsing an extension
         * on meeting a non-alphanumeric character, an extra increment is needed
         * where the succeeding extension is a multi-letter prefixed with an "_".
         */
        if (*isa == '_')
            ++isa;

#define SET_ISA_EXT_MAP(name, bit)                          \
        do {                                                \
            if ((ext_end - ext == strlen(name)) &&          \
                 !strncasecmp(ext, name, strlen(name)) &&   \
                 riscv_isa_extension_check(bit))            \
                set_bit(bit, isainfo->isa);                 \
        } while (false)                                     \

        if (unlikely(ext_err))
            continue;
        if (!ext_long) {
            int nr = tolower(*ext) - 'a';

            if (riscv_isa_extension_check(nr)) {
                *this_hwcap |= isa2hwcap[nr];
                set_bit(nr, isainfo->isa);
            }
        } else {
            for (int i = 0; i < riscv_isa_ext_count; i++)
                SET_ISA_EXT_MAP(riscv_isa_ext[i].name,
                        riscv_isa_ext[i].id);
        }
#undef SET_ISA_EXT_MAP
    }
}

static void __init riscv_fill_hwcap_from_isa_string(unsigned long *isa2hwcap)
{
    const char *isa;
    const struct dt_device_node *cpus = dt_find_node_by_path("/cpus");
    const struct dt_device_node *npcpu;
    unsigned int cpuid = 0;

    if ( !cpus )
    {
        printk(XENLOG_ERR "Missing /cpus node in the device tree?\n");
        return;
    }

    dt_for_each_child_node(cpus, npcpu)
    {
        struct riscv_isainfo *isainfo;
        unsigned long this_hwcap = 0;

        if ( !dt_device_type_is_equal(npcpu, "cpu") )
            continue;

        if ( cpuid >= NR_CPUS )
            assert_failed("dts has more CPU than NR_CPUS\n");

        isainfo = &hart_isa[cpuid++];

        if ( acpi_disabled )
        {
            if ( dt_property_read_string(npcpu, "riscv,isa", &isa) )
            {
                printk(XENLOG_WARNING "Unable to find \"riscv,isa\" devicetree entry\n");
                continue;
            }
        } else
            assert_failed("there is no support for ACPI\n");

        riscv_parse_isa_string(&this_hwcap, isainfo, isa2hwcap, isa);

        /*
        * These ones were as they were part of the base ISA when the
        * port & dt-bindings were upstreamed, and so can be set
        * unconditionally where `i` is in riscv,isa on DT systems.
        */
        if ( acpi_disabled )
        {
            set_bit(RISCV_ISA_EXT_ZICSR, isainfo->isa);
            set_bit(RISCV_ISA_EXT_ZIFENCEI, isainfo->isa);
            set_bit(RISCV_ISA_EXT_ZICNTR, isainfo->isa);
            set_bit(RISCV_ISA_EXT_ZIHPM, isainfo->isa);
        }

        /*
        * All "okay" hart should have same isa. Set HWCAP based on
        * common capabilities of every "okay" hart, in case they don't
        * have.
        */
        if ( elf_hwcap )
            elf_hwcap &= this_hwcap;
        else
            elf_hwcap = this_hwcap;

        if ( bitmap_empty(riscv_isa, RISCV_ISA_EXT_MAX) )
            bitmap_copy(riscv_isa, isainfo->isa, RISCV_ISA_EXT_MAX);
        else
            bitmap_and(riscv_isa, riscv_isa, isainfo->isa, RISCV_ISA_EXT_MAX);
    }

    if ( !acpi_disabled /* && rhct */ )
        assert_failed("there is no support for ACPI\n");
}

static int __init riscv_fill_hwcap_from_ext_list(unsigned long *isa2hwcap)
{
    const char *isa;
    const struct dt_device_node *cpus = dt_find_node_by_path("/cpus");
    const struct dt_device_node *npcpu;
    unsigned int cpuid = 0;

    if ( !cpus )
    {
        printk(XENLOG_ERR "Missing /cpus node in the device tree?\n");
        return -ENOENT;
    }

    dt_for_each_child_node(cpus, npcpu)
    {
        unsigned long this_hwcap = 0;
        struct riscv_isainfo *isainfo;
    
        if ( !dt_device_type_is_equal(npcpu, "cpu") )
            continue;

        if ( dt_property_read_string(npcpu, "riscv,isa-extensions", &isa) )
            continue;

        if ( cpuid >= NR_CPUS )
            assert_failed("dts has more CPU than NR_CPUS\n");

        isainfo = &hart_isa[cpuid++];

        for (int i = 0; i < riscv_isa_ext_count; i++)
        {
            if ( dt_property_match_string(npcpu, "riscv,isa-extensions",
                             riscv_isa_ext[i].property) < 0 )
                continue;

            if ( !riscv_isa_extension_check(riscv_isa_ext[i].id) )
                continue;

            /* Only single letter extensions get set in hwcap */
            if ( strnlen(riscv_isa_ext[i].name, 2) == 1 )
                this_hwcap |= isa2hwcap[riscv_isa_ext[i].id];

            set_bit(riscv_isa_ext[i].id, isainfo->isa);
        }

        /*
         * All "okay" harts should have same isa. Set HWCAP based on
         * common capabilities of every "okay" hart, in case they don't.
         */
        if ( elf_hwcap )
            elf_hwcap &= this_hwcap;
        else
            elf_hwcap = this_hwcap;

        if ( bitmap_empty(riscv_isa, RISCV_ISA_EXT_MAX) )
            bitmap_copy(riscv_isa, isainfo->isa, RISCV_ISA_EXT_MAX);
        else
            bitmap_and(riscv_isa, riscv_isa, isainfo->isa, RISCV_ISA_EXT_MAX);
    }

    if ( bitmap_empty(riscv_isa, RISCV_ISA_EXT_MAX) )
        return -ENOENT;

    return 0;
}

void __init riscv_fill_hwcap(void)
{
    char print_str[NUM_ALPHA_EXTS + 1];
    unsigned long isa2hwcap[26] = {0};
    int i, j;

    isa2hwcap['i' - 'a'] = COMPAT_HWCAP_ISA_I;
    isa2hwcap['m' - 'a'] = COMPAT_HWCAP_ISA_M;
    isa2hwcap['a' - 'a'] = COMPAT_HWCAP_ISA_A;
    isa2hwcap['f' - 'a'] = COMPAT_HWCAP_ISA_F;
    isa2hwcap['d' - 'a'] = COMPAT_HWCAP_ISA_D;
    isa2hwcap['c' - 'a'] = COMPAT_HWCAP_ISA_C;
    isa2hwcap['v' - 'a'] = COMPAT_HWCAP_ISA_V;

    if (!acpi_disabled) {
        riscv_fill_hwcap_from_isa_string(isa2hwcap);
    } else {
        int ret = riscv_fill_hwcap_from_ext_list(isa2hwcap);

        if (ret && riscv_isa_fallback) {
            printk("Falling back to deprecated \"riscv,isa\"\n");
            riscv_fill_hwcap_from_isa_string(isa2hwcap);
        }
    }

    /*
     * We don't support systems with F but without D, so mask those out
     * here.
     */
    if ((elf_hwcap & COMPAT_HWCAP_ISA_F) && !(elf_hwcap & COMPAT_HWCAP_ISA_D)) {
        printk("This kernel does not support systems with F but not D\n");
        elf_hwcap &= ~COMPAT_HWCAP_ISA_F;
    }

    if (elf_hwcap & COMPAT_HWCAP_ISA_V) {
        /* riscv_v_setup_vsize(); */
        /*
         * ISA string in device tree might have 'v' flag, but
         * CONFIG_RISCV_ISA_V is disabled in kernel.
         * Clear V flag in elf_hwcap if CONFIG_RISCV_ISA_V is disabled.
         */
        if (!IS_ENABLED(CONFIG_RISCV_ISA_V))
            elf_hwcap &= ~COMPAT_HWCAP_ISA_V;
    }

    memset(print_str, 0, sizeof(print_str));
    for (i = 0, j = 0; i < NUM_ALPHA_EXTS; i++)
        if (riscv_isa[0] & BITOP_MASK(i))
            print_str[j++] = (char)('a' + i);
    printk("riscv: base ISA extensions %s\n", print_str);

    memset(print_str, 0, sizeof(print_str));
    for (i = 0, j = 0; i < NUM_ALPHA_EXTS; i++)
        if (elf_hwcap & BITOP_MASK(i))
            print_str[j++] = (char)('a' + i);
    printk("riscv: ELF capabilities %s\n", print_str);
}
