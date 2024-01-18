/* SPDX-License-Identifier: MIT */
/*
 * xen/arch/riscv/fdtdump.c
 *
 * (c) 2024 Microchip Technology Inc.
 */

#include <xen/ctype.h>
#include <xen/lib.h>
#include <xen/libfdt/libfdt.h>

static int fdt_is_printable_string(const void *data, int len)
{
    const char *s = data;
    const char *ss, *se;

    /* zero length is not */
    if ( len == 0 )
        return 0;

    /* must terminate with zero */
    if ( s[len - 1] != '\0' )
        return 0;

    se = s + len;

    while (s < se)
    {
        ss = s;
        while (s < se && *s && isprint(*s))
            s++;

        /* not zero, or not done yet */
        if (*s != '\0' || s == ss)
            return 0;

        s++;
    }

    return 1;
}

static void fdt_print_data(const char *data, int len)
{
    int i;
    const char *p = data;
    const char *s;

    /* no data, don't print */
    if ( len == 0 )
        return;

    if ( fdt_is_printable_string(data, len) )
    {
        printk(" = ");

        s = data;
        do
        {
            printk("\"%s\"", s);
            s += strlen(s) + 1;
            if (s < data + len)
                printk(", ");
        } while (s < data + len);
    }
    else if ( (len % 4) == 0 )
    {
        const uint32_t *cell = (const uint32_t *)data;

        printk(" = <");
        for ( i = 0; i < len / 4; i++ )
            printk("0x%x%s", fdt32_to_cpu(cell[i]),
                   i < (len - 4) ? " " : "");
        printk(">");
    }
    else
    {
        printk(" = [");
        for ( i = 0; i < len; i++ )
            printk("%02x%s", *p++, i < len - 1 ? " " : "");
        printk("]");
    }
}

static void fdt_dump_properties(void *fdt, int node, int tab)
{
    int property;
    const struct fdt_property *prop;

    fdt_for_each_property_offset( property, fdt, node )
    {
        if ( !(prop = fdt_get_property_by_offset(fdt, property, NULL)) )
        {
            printk("OUPPPSSS!!!\n");
            return;
        }

        for ( int x = 0; x < tab; x++ )
            printk("  ");

        printk("%s", fdt_string(fdt, fdt32_to_cpu(prop->nameoff)));
        fdt_print_data(prop->data, fdt32_to_cpu(prop->len));
        printk(";\n");
    }
}

static void fdt_dump_next_node(void *fdt, int off, int tab)
{
    int node;

    fdt_for_each_subnode( node, fdt, off )
    {
        for ( int x = 0; x < tab; x++ )
            printk("  ");

        printk("%s {\n", fdt_get_name(fdt, node, 0));
        fdt_dump_properties(fdt, node, tab + 1);
        fdt_dump_next_node(fdt, node, tab + 1);

        for (int x = 0; x < tab; x++)
            printk("  ");

        printk("};\n");
    }
}

void fdt_dump(void *fdt)
{
    /* check for properties in the main node */
    printk("-------------- DTS DUMP START --------------\n");

    fdt_dump_properties(fdt, 0, 0);
    fdt_dump_next_node(fdt, 0, 0);

    printk("-------------- DTS DUMP END --------------\n");
}
