/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * xen/arch/arm/device.c
 *
 * Helpers to use a device retrieved via the device tree.
 *
 * Julien Grall <julien.grall@linaro.org>
 * Copyright (C) 2013 Linaro Limited.
 */

#include <asm/device.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>

extern const struct device_desc _sdevice[], _edevice[];

#ifdef CONFIG_ACPI
extern const struct acpi_device_desc _asdevice[], _aedevice[];
#endif

int __init device_init(struct dt_device_node *dev, enum device_class class,
                       const void *data)
{
    const struct device_desc *desc;

    ASSERT(dev != NULL);

    if ( !dt_device_is_available(dev) || dt_device_for_passthrough(dev) )
        return  -ENODEV;

    for ( desc = _sdevice; desc != _edevice; desc++ )
    {
        if ( desc->class != class )
            continue;

        if ( dt_match_node(desc->dt_match, dev) )
        {
            ASSERT(desc->init != NULL);

            return desc->init(dev, data);
        }

    }

    return -EBADF;
}

#ifdef CONFIG_ACPI

int __init acpi_device_init(enum device_class class, const void *data, int class_type)
{
    const struct acpi_device_desc *desc;

    for ( desc = _asdevice; desc != _aedevice; desc++ )
    {
        if ( ( desc->class != class ) || ( desc->class_type != class_type ) )
            continue;

        ASSERT(desc->init != NULL);

        return desc->init(data);
    }

    return -EBADF;
}

#endif /* CONFIG_ACPI */

enum device_class device_get_class(const struct dt_device_node *dev)
{
    const struct device_desc *desc;

    ASSERT(dev != NULL);

    for ( desc = _sdevice; desc != _edevice; desc++ )
    {
        if ( dt_match_node(desc->dt_match, dev) )
            return desc->class;
    }

    return DEVICE_UNKNOWN;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
