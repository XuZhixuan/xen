#ifndef __BOOTFDT_H__
#define __BOOTFDT_H__

#include <xen/types.h>

#include <asm/bootfdt.h>

#ifndef MIN_FDT_ALIGN
#define MIN_FDT_ALIGN 8
#endif

#ifndef MAX_FDT_SIZE
#define MAX_FDT_SIZE SZ_2M
#endif

void device_tree_get_reg(const __be32 **cell, u32 address_cells,
                         u32 size_cells, u64 *start, u64 *size);
u32 device_tree_get_u32(const void *fdt, int node,
                        const char *prop_name, u32 dflt);
size_t boot_fdt_info(const void *fdt, paddr_t paddr);
const char *boot_fdt_cmdline(const void *fdt);

#endif /* __BOOTFDT_H__ */
