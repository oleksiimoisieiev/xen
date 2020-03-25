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

#include "coproc_vgpio.h"

#define DT_MATCH_COPROC_VGPIO DT_MATCH_COMPATIBLE("fsl,imx8qm-gpio")

/* Change this to #define VGPIO_DEBUG here to enable more debug messages */
#undef VGPIO_DEBUG

static const char CFG_PINS_STR[] = "pins=";

#define CFG_PINS_STR_SIZE   (strlen(CFG_PINS_STR))
#define CFG_PINS_BASE       16

static int vcoproc_vgpio_read(struct vcpu *v, mmio_info_t *info, register_t *r,
                              void *priv)
{
    struct mmio *mmio = priv;
    struct vcoproc_rw_context ctx;
    struct vgpio_info *vinfo;
    int offset, size;

    vcoproc_get_rw_context(v->domain, mmio, info, &ctx);
    vinfo = (struct vgpio_info *)ctx.vcoproc->priv;
    offset = (int)ctx.offset;
    size = ctx.dabt.size;

    switch ( offset )
    {
        case VRANGE32(GPIO_DR, GPIO_IMR):
            if ( size != GPIO_WORD_SIZE ) goto bad_width;
            *r = vgpio_read32(ctx.coproc, ctx.offset);
            break ;

        case GPIO_ISR:
            if ( size != GPIO_WORD_SIZE ) goto bad_width;
            *r = vinfo->reg_val_irq_status;
            break ;

        case GPIO_EDGE_SEL:
            if ( size != GPIO_WORD_SIZE ) goto bad_width;
            *r = vgpio_read32(ctx.coproc, ctx.offset);
            break ;

        case VRANGE32(0x20, 0x80):
            goto read_reserved;

        case VRANGE32(GPIO_DR_SET, GPIO_DR_TOGGLE):
            if ( size != GPIO_WORD_SIZE ) goto bad_width;
            *r = vgpio_read32(ctx.coproc, ctx.offset);
            break ;

        default:
            dev_err(ctx.coproc->dev, "unhandled read r%d=%"PRIregister" offset %#08x base %#08x\n",
            ctx.dabt.reg, *r, ctx.offset, (u32)mmio->addr);
            return 0;
    }
    *r &= vinfo->pins_allowed;
#ifdef VGPIO_DEBUG
    dev_dbg(ctx.coproc->dev, "read r%d=%"PRIregister" offset %#08x base %#08x\n",
            ctx.dabt.reg, *r, ctx.offset, (u32)mmio->addr);
#endif
    return 1;

bad_width:
    dev_err(ctx.coproc->dev, "bad read width = %d; r%d=%"PRIregister" offset %#08x base %#08x\n",
            size, ctx.dabt.reg, *r, ctx.offset, (u32)mmio->addr);
    return 0;

read_reserved:
    dev_err(ctx.coproc->dev, "bad read reserved r%d=%"PRIregister" offset %#08x base %#08x\n",
            ctx.dabt.reg, *r, ctx.offset, (u32)mmio->addr);
    return 0;
}

static int vcoproc_vgpio_write(struct vcpu *v, mmio_info_t *info, register_t r,
                               void *priv)
{
    struct mmio *mmio = priv;
    struct vcoproc_rw_context ctx;
    struct vgpio_info *vinfo;
    int offset, size;

    vcoproc_get_rw_context(v->domain, mmio, info, &ctx);
    vinfo = (struct vgpio_info *)ctx.vcoproc->priv;
    offset = (int)ctx.offset;
    size = ctx.dabt.size;

    switch ( offset )
    {
        case VRANGE32(GPIO_DR, GPIO_IMR):
            if ( size != GPIO_WORD_SIZE ) goto bad_width;
            vgpio_write32(ctx.coproc, ctx.offset, r & vinfo->pins_allowed);
            break ;

        case GPIO_ISR:
            if ( size != GPIO_WORD_SIZE ) goto bad_width;
            vinfo->reg_val_irq_status = r;
            break ;

        case GPIO_EDGE_SEL:
            if ( size != GPIO_WORD_SIZE ) goto bad_width;
            vgpio_write32(ctx.coproc, ctx.offset, r & vinfo->pins_allowed);
            break ;

        case VRANGE32(0x20, 0x80):
            goto write_reserved;

        case VRANGE32(GPIO_DR_SET, GPIO_DR_TOGGLE):
            if ( size != GPIO_WORD_SIZE ) goto bad_width;
            vgpio_write32(ctx.coproc, ctx.offset, r & vinfo->pins_allowed);
            break ;

        default:
            dev_err(ctx.coproc->dev, "unhandled write r%d=%"PRIregister" offset %#08x base %#08x\n",
            ctx.dabt.reg, r, ctx.offset, (u32)mmio->addr);
            return 0;
    }
#ifdef VGPIO_DEBUG
    dev_dbg(ctx.coproc->dev, "write r%d=%"PRIregister" offset %#08x base %#08x\n",
            ctx.dabt.reg, r, ctx.offset, (u32)mmio->addr);
#endif
    return 1;

bad_width:
    dev_err(ctx.coproc->dev, "bad write width = %d; r%d=%"PRIregister" offset %#08x base %#08x\n",
            size, ctx.dabt.reg, r, ctx.offset, (u32)mmio->addr);
    return 0;

write_reserved:
    dev_err(ctx.coproc->dev, "bad write reserved r%d=%"PRIregister" offset %#08x base %#08x\n",
            ctx.dabt.reg, r, ctx.offset, (u32)mmio->addr);
    return 0;
}

static const struct mmio_handler_ops vcoproc_vgpio_mmio_handler = {
    .read = vcoproc_vgpio_read,
    .write = vcoproc_vgpio_write,
};

static void coproc_vgpio_irq_handler(int irq, void *dev,
                                     struct cpu_user_regs *regs)
{
    struct coproc_device *coproc_vgpio = dev;
    struct gpio_info *info = (struct gpio_info *)coproc_vgpio->priv;
    struct vgpio_info *vinfo;
    struct vcoproc_instance *vcoproc = NULL;
    u32 irq_status, imr_status, irq_result, irq_check;

    irq_status = readl(info->reg_vaddr_irq_status);
    imr_status = readl(info->reg_vaddr_imr_status);
    irq_result = irq_status & imr_status;
    writel(irq_result, info->reg_vaddr_irq_status);

    irq_check = 0;
    list_for_each_entry( vcoproc, &coproc_vgpio->vcoprocs, vcoproc_elem )
    {
        vinfo = (struct vgpio_info *)vcoproc->priv;
        if ( (irq_check = irq_result & vinfo->pins_allowed) )
        {
            vinfo->reg_val_irq_status = irq_status & vinfo->pins_allowed;
        #ifdef VGPIO_DEBUG
            dev_dbg(coproc_vgpio->dev, "Inject irq (%d) from pin (%#08x) to domain (%d)\n",
                    irq, irq_check, vcoproc->domain->domain_id);
        #endif
            vgic_inject_irq(vcoproc->domain, NULL, irq, true);
            irq_check = 0;
        }
    }
}

/*
 * TODO: Pins configuration processing must be moved to XEN Tools.
 * For now cfg_pins() function is a hack until there is no way to pass
 * specific coprocessor configuration in binary form from XEN Tools to XEN.
 */

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

static int vcoproc_vgpio_vcoproc_init(struct vcoproc_instance *vcoproc,
                                      const char *cfg)
{
    int i;

    vcoproc->priv = xzalloc(struct vgpio_info);
    if ( !vcoproc->priv )
    {
        dev_err(vcoproc->coproc->dev,
                "failed to allocate vcoproc private data\n");
        return -ENOMEM;
    }

    if ( cfg_pins(&vcoproc, cfg) )
        return -EINVAL;

    for ( i = 0; i < vcoproc->coproc->num_mmios; i++ )
    {
        struct mmio *mmio = &vcoproc->coproc->mmios[i];
        register_mmio_handler(vcoproc->domain, &vcoproc_vgpio_mmio_handler,
                              mmio->addr, mmio->size, mmio);
    }

    return 0;
}

static void vcoproc_vgpio_vcoproc_deinit(struct vcoproc_instance *vcoproc)
{
    struct vgpio_info *vinfo;
    struct gpio_info *info;

    vinfo = (struct vgpio_info *)(vcoproc)->priv;
    info = (struct gpio_info *)(vcoproc)->coproc->priv;
    info->pins_assigned &= ~(vinfo->pins_allowed);

    xfree(vcoproc->priv);
}

static const struct coproc_ops vcoproc_vgpio_vcoproc_ops = {
    .vcoproc_init        = vcoproc_vgpio_vcoproc_init,
    .vcoproc_deinit      = vcoproc_vgpio_vcoproc_deinit,
};

static int coproc_vgpio_dt_probe(struct dt_device_node *np)
{
    struct coproc_device *coproc_vgpio;
    struct device *dev = &np->dev;
    int i, ret;
    struct gpio_info *info;
    char *reg_base;

    coproc_vgpio = coproc_alloc(np, &vcoproc_vgpio_vcoproc_ops);
    if ( IS_ERR_OR_NULL(coproc_vgpio) )
        return PTR_ERR(coproc_vgpio);

    coproc_vgpio->priv = xzalloc(struct gpio_info);
    if ( !coproc_vgpio->priv )
    {
        dev_err(dev, "failed to allocate vgpio coproc private data\n");
        ret = -ENOMEM;
        goto out_release_coproc;
    }
    info = (struct gpio_info *)coproc_vgpio->priv;
    info->pins_assigned = 0;
    reg_base = (char *)coproc_vgpio->mmios[0].base;
    info->reg_vaddr_irq_status = (u32 *)(reg_base + GPIO_ISR);
    info->reg_vaddr_imr_status = (u32 *)(reg_base + GPIO_IMR);
    for ( i = 0; i < coproc_vgpio->num_irqs; ++i )
    {
        dev_dbg(dev, "request irq %d (%u)\n", i, coproc_vgpio->irqs[i]);
        ret = request_irq(coproc_vgpio->irqs[i],
                         IRQF_SHARED,
                         coproc_vgpio_irq_handler,
                         "coproc_vgpio irq",
                         coproc_vgpio);
        if ( ret )
        {
            dev_err(dev, "failed to request irq %d (%u)\n", i,
                    coproc_vgpio->irqs[i]);
            goto out_release_irqs;
        }
    }

    ret = coproc_register(coproc_vgpio);
    if ( ret )
    {
        dev_err(dev, "failed to register coproc (%d)\n", ret);
        goto out_release_irqs;
    }

    return 0;

out_release_irqs:
    while ( i-- )
        release_irq(coproc_vgpio->irqs[i], coproc_vgpio);
    xfree(coproc_vgpio->priv);
out_release_coproc:
    coproc_release(coproc_vgpio);
    return ret;

}

static const struct dt_device_match coproc_vgpio_dt_match[] __initconst =
{
    DT_MATCH_COPROC_VGPIO,
    { /* sentinel */ },
};

static __init int coproc_vgpio_init(struct dt_device_node *dev, const void *data)
{
    int ret;

    dt_device_set_used_by(dev, DOMID_XEN);

    ret = coproc_vgpio_dt_probe(dev);
    if ( ret )
        return ret;

    return 0;
}


DT_DEVICE_START(coproc_vgpio, "COPROC_VGPIO", DEVICE_COPROC)
    .dt_match = coproc_vgpio_dt_match,
    .init = coproc_vgpio_init,
DT_DEVICE_END


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
