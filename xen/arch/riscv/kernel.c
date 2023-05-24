/*
 * Kernel image loading.
 *
 * Copyright (C) 2011 Citrix Systems, Inc.
 */
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/domain_page.h>
#include <xen/sched.h>
#include <asm/byteorder.h>
#include <asm/setup.h>
#include <xen/libfdt/libfdt.h>
#include <xen/gunzip.h>
#include <xen/vmap.h>

#include <asm/fixmap.h>
#include <asm/guest_access.h>
#include <asm/kernel.h>
#include <asm/domain_build.h>

#define ZIMAGE64_MAGIC_V1 0x5643534952 /* Magic number, little endian, "RISCV" */
#define ZIMAGE64_MAGIC_V2 0x05435352 /* Magic number 2, little endian, "RSC\x05" */

/**
 * copy_from_paddr - copy data from a physical address
 * @dst: destination virtual address
 * @paddr: source physical address
 * @len: length to copy
 */
void __init copy_from_paddr(void *dst, paddr_t paddr, unsigned long len)
{
    void *src = (void *)FIXMAP_ADDR(FIXMAP_MISC);

    while (len) {
        unsigned long l, s;

        s = paddr & (PAGE_SIZE-1);
        l = min(PAGE_SIZE - s, len);

        set_fixmap(FIXMAP_MISC, maddr_to_mfn(paddr), PAGE_HYPERVISOR_WC);
        memcpy(dst, src + s, l);
        clear_fixmap(FIXMAP_MISC);

        paddr += l;
        dst += l;
        len -= l;
    }
}

static paddr_t __init kernel_zimage_place(struct kernel_info *info)
{
    /* GUEST_RAM0_BASE + text_offset */
    return GUEST_RAM0_BASE + info->zimage.text_offset;
}

static void __init place_modules(struct kernel_info *info,
                                 paddr_t kernbase, paddr_t kernend)
{
    const paddr_t modsize = fdt_totalsize(info->fdt);
    const paddr_t ramsize = info->mem.bank[0].size;
    const paddr_t dtb_len = fdt_totalsize(info->fdt);
    const paddr_t kernsize = ROUNDUP(kernend, MB(2)) - kernbase;

    if ( modsize + kernsize > ramsize )
        panic("Not enough memory in the first bank for the kernel+dtb+initrd\n");

    info->dtb_paddr = ROUNDUP(kernend, MB(2));

    info->initrd_paddr = info->dtb_paddr + dtb_len;
}

static void __init kernel_zimage_load(struct kernel_info *info)
{
    int rc;
    paddr_t load_addr = kernel_zimage_place(info);
    paddr_t paddr = info->zimage.kernel_addr;
    paddr_t len = info->zimage.len;
    void *kernel;

    info->entry = load_addr;

    place_modules(info, load_addr, load_addr + len);

    printk("Loading zImage from %"PRIpaddr" to %"PRIpaddr"-%"PRIpaddr"\n",
            paddr, load_addr, load_addr + len);

    kernel = ioremap_wc(paddr, len);

    if ( !kernel )
        panic("Unable to map dom0 kernel\n");

    /* Move kernel to proper location in guest phys map */
    rc = copy_to_guest_phys(info->d, load_addr, kernel, len);

    if ( rc )
        panic("Unable to copy kernel to proper guest location\n");

    iounmap(kernel);
}

static __init uint32_t output_length(char *image, unsigned long image_len)
{
    return *(uint32_t *)&image[image_len - 4];
}

static __init int kernel_decompress(struct bootmodule *mod)
{
    char *output, *input;
    char magic[2];
    int rc;
    unsigned kernel_order_out;
    paddr_t output_size;
    struct page_info *pages;
    mfn_t mfn;
    paddr_t addr = mod->start;
    paddr_t size = mod->size;

    if ( size < 2 )
        return -EINVAL;

    copy_from_paddr(magic, addr, sizeof(magic));

    /* only gzip is supported */
    if ( !gzip_check(magic, size) )
        return -EINVAL;

    input = ioremap_cache(addr, size);
    if ( input == NULL )
        return -EFAULT;

    output_size = output_length(input, size);
    kernel_order_out = get_order_from_bytes(output_size);
    pages = alloc_domheap_pages(NULL, kernel_order_out, 0);
    if ( pages == NULL )
    {
        iounmap(input);
        return -ENOMEM;
    }
    mfn = page_to_mfn(pages);
    output = __vmap(&mfn, 1 << kernel_order_out, 1, 1, PAGE_HYPERVISOR, VMAP_DEFAULT);

    rc = perform_gunzip(output, input, size);
    iounmap(input);
    vunmap(output);

    mod->start = page_to_maddr(pages);
    mod->size = output_size;

    return 0;
}

#ifdef CONFIG_RISCV_32
# error "No 32-bit dom0 kernel probe function available"
#endif
/*
 * Check if the image is a 64-bit Image.
 */
static int __init kernel_zimage64_probe(struct kernel_info *info,
                                        paddr_t addr, paddr_t size)
{
    /* riscv/boot-image-header.rst */
    struct {
        u32 code0;		  /* Executable code */
        u32 code1;		  /* Executable code */
        u64 text_offset;  /* Image load offset, little endian */
        u64 image_size;	  /* Effective Image size, little endian */
        u64 flags;		  /* kernel flags, little endian */
        u32 version;	  /* Version of this header */
        u32 res1;		  /* Reserved */
        u64 res2;		  /* Reserved */
        u64 magic;        /* Deprecated: Magic number, little endian, "RISCV" */
        u32 magic2;       /* Magic number 2, little endian, "RSC\x05" */
        u32 res3;		  /* Reserved for PE COFF offset */
    } zimage;
    uint64_t start, end;

    if ( size < sizeof(zimage) )
        return -EINVAL;

    copy_from_paddr(&zimage, addr, sizeof(zimage));

    /* Magic v1 is deprecated and may be removed.  Only use v2 */
    if ( zimage.magic2 != ZIMAGE64_MAGIC_V2 )
        return -EINVAL;

    /* Currently there is no length in the header, so just use the size */
    start = 0;
    end = size;

    /*
     * Given the above this check is a bit pointless, but leave it
     * here in case someone adds a length field in the future.
     */
    if ( (end - start) > size )
        return -EINVAL;

    info->zimage.kernel_addr = addr;
    info->zimage.len = end - start;
    info->zimage.text_offset = zimage.text_offset;
    info->zimage.start = 0;

    info->load = kernel_zimage_load;

    info->type = DOMAIN_64BIT;

    return 0;
}

int __init kernel_probe(struct kernel_info *info,
                        const struct dt_device_node *domain)
{
    struct bootmodule *mod = NULL;
    struct bootcmdline *cmd = NULL;
    int rc;

    /* domain is NULL only for the hardware domain */
    if ( domain == NULL )
    {
        ASSERT(is_hardware_domain(info->d));

        mod = boot_module_find_by_kind(BOOTMOD_KERNEL);

        info->kernel_bootmodule = mod;
        info->initrd_bootmodule = boot_module_find_by_kind(BOOTMOD_RAMDISK);

        cmd = boot_cmdline_find_by_kind(BOOTMOD_KERNEL);
        if ( cmd )
            info->cmdline = &cmd->cmdline[0];
    } else {
        BUG();
    }

    if ( !mod || !mod->size )
    {
        printk(XENLOG_ERR "Missing kernel boot module?\n");
        return -ENOENT;
    }

    printk("Loading %pd kernel from boot module @ %"PRIpaddr"\n",
           info->d, info->kernel_bootmodule->start);
    if ( info->initrd_bootmodule )
        printk("Loading ramdisk from boot module @ %"PRIpaddr"\n",
               info->initrd_bootmodule->start);

    /* if it is a gzip'ed image, 32bit or 64bit, uncompress it */
    rc = kernel_decompress(mod);
    if (rc < 0 && rc != -EINVAL)
        return rc;

    return kernel_zimage64_probe(info, mod->start, mod->size);
}

void __init kernel_load(struct kernel_info *info)
{
    info->load(info);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
