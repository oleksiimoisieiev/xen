/*
 * xen/arch/arm/coproc/plat/coproc_vgpio.c
 *
 * COPROC VGPIO platform specific code
 *
 * Anastasiia Lukianenko <Anastasiia_Lukianenko@epam.com>
 * Copyright (C) 2020 EPAM Systems Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/device_tree.h>
#include <xen/err.h>

#include "coproc_vgpio.h"

static const char CFG_PINS_STR[] = "pins=";

#define CFG_PINS_STR_SIZE   (strlen(CFG_PINS_STR))
#define CFG_PINS_BASE       16

static int cfg_pins(struct vcoproc_instance **vcoproc, const char *cfg)
{
    struct vgpio_info *vinfo;
    struct gpio_info *info;
    u32 pins;
    char *cfg_end;

    vinfo = (struct vgpio_info *)(*vcoproc)->priv;
    info = (struct gpio_info *)(*vcoproc)->coproc->priv;
    vinfo->pins_allowed = 0;

    if ( !cfg )
        return 0;

    /*
     * The pins assigned to the domain configured with string "pins=" followed
     * with a 32-bit hexadecimal mask. Where bit set to '1' means the
     * correspond pin is assigned to the domain, '0' - means the pin is not
     * assigned to the domain.
     *
     * Such strict rules are established, because detailed string parsing in XEN
     * is inappropriate during to lack of parsing functions in libraries.
     */

    if ( strncmp(cfg, CFG_PINS_STR, CFG_PINS_STR_SIZE) != 0 )
        goto wrong_cfg;
    cfg_end = strchr(cfg, ';');
    pins = simple_strtoul(&cfg[CFG_PINS_STR_SIZE],
                          (const char **)&cfg_end, CFG_PINS_BASE);

    if ( pins & info->pins_assigned )
        goto busy_pins;

    vinfo->pins_allowed |= pins;
    info->pins_assigned |= pins;

    return 0;

wrong_cfg:
    dev_err((*vcoproc)->coproc->dev,
            "Configuration for vcoproc = %s is inappropriate (%s)\n",
            dev_path((*vcoproc)->coproc->dev), cfg);
    return -EINVAL;
busy_pins:
    dev_err((*vcoproc)->coproc->dev,
            "Domain %d is trying to assign busy GPIO pin = %#08x\n",
            (*vcoproc)->domain->domain_id, pins & info->pins_assigned);
    return -EPERM;
}

int vcoproc_vgpio_vcoproc_init(struct vcoproc_instance *vcoproc,
                                      const char *cfg)
{
    vcoproc->priv = xzalloc(struct vgpio_info);
    if ( !vcoproc->priv )
    {
        dev_err(vcoproc->coproc->dev,
                "failed to allocate vcoproc private data\n");
        return -ENOMEM;
    }

    if ( cfg_pins(&vcoproc, cfg) )
        return -EINVAL;

    return 0;
}

void vcoproc_vgpio_vcoproc_deinit(struct vcoproc_instance *vcoproc)
{
    struct vgpio_info *vinfo;
    struct gpio_info *info;

    vinfo = (struct vgpio_info *)(vcoproc)->priv;
    info = (struct gpio_info *)(vcoproc)->coproc->priv;
    info->pins_assigned &= ~(vinfo->pins_allowed);

    xfree(vcoproc->priv);
}

struct coproc_device *coproc_vgpio_alloc(struct dt_device_node *np,
                                   const struct coproc_ops *ops)
{
    struct coproc_device *coproc_vgpio;
    struct device *dev = &np->dev;
    struct gpio_info *info;

    coproc_vgpio = coproc_alloc(np, ops);
    if ( IS_ERR_OR_NULL(coproc_vgpio) )
        return ERR_PTR(-ENOMEM);

    coproc_vgpio->priv = xzalloc(struct gpio_info);
    if ( !coproc_vgpio->priv )
    {
        dev_err(dev, "failed to allocate vgpio coproc private data\n");
        goto out_release_coproc;
    }
    info = (struct gpio_info *)coproc_vgpio->priv;
    info->pins_assigned = 0;

    return coproc_vgpio;

out_release_coproc:
    coproc_release(coproc_vgpio);
    return ERR_PTR(-ENOMEM);
}

void coproc_vgpio_release(struct coproc_device *coproc_vgpio)
{
    if ( IS_ERR_OR_NULL(coproc_vgpio) )
        return;

    xfree(coproc_vgpio->priv);
    coproc_release(coproc_vgpio);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
