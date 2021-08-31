/*
 * xen/arch/arm/coproc/plat/coproc_vgpio_imx.c
 *
 * COPROC VGPIO IMX platform specific code
 *
 * Vasyl Gryshchenko <vasyl_gryshchenko@epam.com>
 * Copyright (C) 2021 EPAM Systems Inc.
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

#include <asm/sci.h>
#include <xen/device_tree.h>

#include "coproc_vgpio_imx.h"

#define DT_MATCH_COPROC_VGPIO_IMX DT_MATCH_COMPATIBLE("fsl,imx8qm-gpio")

/* Change this to #define VGPIO_DEBUG here to enable more debug messages */
#undef VGPIO_DEBUG

static int coproc_vgpio_imx_read(struct vcpu *v, mmio_info_t *info, register_t *r,
                              void *priv)
{
    struct mmio *mmio = priv;
    struct vcoproc_rw_context ctx;
    struct vgpio_info *vinfo;
    int offset, size;

    vcoproc_get_rw_context(v->domain, mmio, info, &ctx);
    vinfo = (struct vgpio_info *)ctx.vcoproc->priv;
    offset = ctx.offset;
    size = ctx.dabt.size;

    if ( size != GPIO_WORD_SIZE )
    {
        dev_err(ctx.coproc->dev, "bad read width = %d; r%d=%"PRIregister" offset %#08x base %#08x\n",
            size, ctx.dabt.reg, *r, ctx.offset, (u32)mmio->addr);
        return 0;
    }

    switch ( offset )
    {
        case VRANGE32(GPIO_DR, GPIO_IMR):
            *r = vgpio_read32(ctx.coproc, ctx.offset);
            break ;

        case GPIO_ISR:
            *r = vinfo->reg_val_irq_status;
            break ;

        case GPIO_EDGE_SEL:
            *r = vgpio_read32(ctx.coproc, ctx.offset);
            break ;

        /* Reserved for specific needs to this platform  */
        case VRANGE32(0x20, 0x80):
            goto read_reserved;

        case VRANGE32(GPIO_DR_SET, GPIO_DR_TOGGLE):
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

read_reserved:
    dev_err(ctx.coproc->dev, "bad read reserved r%d=%"PRIregister" offset %#08x base %#08x\n",
            ctx.dabt.reg, *r, ctx.offset, (u32)mmio->addr);
    return 0;
}

static int coproc_vgpio_imx_write(struct vcpu *v, mmio_info_t *info, register_t r,
                               void *priv)
{
    struct mmio *mmio = priv;
    struct vcoproc_rw_context ctx;
    struct vgpio_info *vinfo;
    int offset, size;

    vcoproc_get_rw_context(v->domain, mmio, info, &ctx);
    vinfo = (struct vgpio_info *)ctx.vcoproc->priv;
    offset = ctx.offset;
    size = ctx.dabt.size;

    if ( size != GPIO_WORD_SIZE )
    {
        dev_err(ctx.coproc->dev, "bad write width = %d; r%d=%"PRIregister" offset %#08x base %#08x\n",
            size, ctx.dabt.reg, r, ctx.offset, (u32)mmio->addr);
        return 0;
    }

    switch ( offset )
    {
        case VRANGE32(GPIO_DR, GPIO_IMR):
            vgpio_write32(ctx.coproc, ctx.offset, r & vinfo->pins_allowed);
            break ;

        case GPIO_ISR:
            vinfo->reg_val_irq_status = r;
            break ;

        case GPIO_EDGE_SEL:
            vgpio_write32(ctx.coproc, ctx.offset, r & vinfo->pins_allowed);
            break ;

        /* Reserved for specific needs to this platform */
        case VRANGE32(0x20, 0x80):
            goto write_reserved;

        case VRANGE32(GPIO_DR_SET, GPIO_DR_TOGGLE):
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

write_reserved:
    dev_err(ctx.coproc->dev, "bad write reserved r%d=%"PRIregister" offset %#08x base %#08x\n",
            ctx.dabt.reg, r, ctx.offset, (u32)mmio->addr);
    return 0;
}

const struct mmio_handler_ops vcoproc_vgpio_mmio_handler = {
    .read = coproc_vgpio_imx_read,
    .write = coproc_vgpio_imx_write,
};

static void coproc_vgpio_imx_irq_handler(int irq, void *dev,
                                     struct cpu_user_regs *regs)
{
    struct coproc_device *coproc_vgpio = dev;
    struct gpio_info *info = (struct gpio_info *)coproc_vgpio->priv;
    struct plat_info *pinfo = (struct plat_info *)info->plat_info;
    struct vgpio_info *vinfo;
    struct vcoproc_instance *vcoproc = NULL;
    u32 irq_status, imr_status, irq_result, irq_check;

    irq_status = readl(pinfo->reg_vaddr_irq_status);
    imr_status = readl(pinfo->reg_vaddr_imr_status);
    irq_result = irq_status & imr_status;
    writel(irq_result, pinfo->reg_vaddr_irq_status);

    list_for_each_entry( vcoproc, &coproc_vgpio->vcoprocs, vcoproc_elem )
    {
        vinfo = (struct vgpio_info *)vcoproc->priv;
        irq_check = irq_result & vinfo->pins_allowed;
        if ( irq_check )
        {
            vinfo->reg_val_irq_status = irq_status & vinfo->pins_allowed;
        #ifdef VGPIO_DEBUG
            dev_dbg(coproc_vgpio->dev, "Inject irq (%d) from pin (%#08x) to domain (%d)\n",
                    irq, irq_check, vcoproc->domain->domain_id);
        #endif
            vgic_inject_irq(vcoproc->domain, NULL, irq, true);
        }
    }
}

static int coproc_vgpio_sc_resource_get_id(struct device *dev,
                                           struct dt_device_node *np)
{
    struct dt_device_node *pnode;
    const __be32 *prop;
    u32 resource_id;

    /* Get the handle to the power domain. */
    prop = dt_get_property(np, "power-domains", NULL);
    if ( !prop )
    {
        dev_err(dev, "device has no power domains, can't power on\n");
        return -ENODEV;
    }

    /* Get the power domain's node. */
    pnode = dt_find_node_by_phandle(be32_to_cpup(prop));
    if ( !pnode )
    {
        dev_err(dev, "device has no power domain node, can't power on\n");
        return -ENODEV;
    }

    /* Now get the resource ID of this power domain. */
    if ( !dt_property_read_u32(pnode, "reg", &resource_id) )
    {
        dev_err(dev, "device has no power domain resource, can't power on\n");
        return -ENODEV;
    }

    dev_dbg(dev, "power mode resource id: %d\n", resource_id);
    return resource_id;
}

static int coproc_vgpio_sc_resource_set_power(struct device *dev,
                                              struct gpio_info *info,
                                              sc_pm_power_mode_t mode)
{
    sc_err_t sci_err;

    dev_dbg(dev, "powering %s resource %d\n",
            mode == SC_PM_PW_MODE_ON ? "on" : "off",
            info->sc_resource_id);
    sci_err = sc_pm_set_resource_power_mode(mu_ipcHandle,
                                            info->sc_resource_id,
                                            mode);
    if ( sci_err != SC_ERR_NONE )
    {
        dev_err(dev, "failed to power on resource %d\n", info->sc_resource_id);
        return -ENODEV;
    }

    return 0;
}

static int vcoproc_vgpio_imx_init(struct vcoproc_instance *vcoproc,
                                      const char *cfg)
{
    int i, ret;

    ret = vcoproc_vgpio_vcoproc_init(vcoproc, cfg);

    if ( ret )
        return ret;

    for ( i = 0; i < vcoproc->coproc->num_mmios; i++ )
    {
        struct mmio *mmio = &vcoproc->coproc->mmios[i];
        register_mmio_handler(vcoproc->domain, &vcoproc_vgpio_mmio_handler,
                                mmio->addr, mmio->size, mmio);
    }

    return ret;
}

static const struct coproc_ops coproc_vgpio_imx_ops = {
    .vcoproc_init        = vcoproc_vgpio_imx_init,
    .vcoproc_deinit      = vcoproc_vgpio_vcoproc_deinit,
};

static int coproc_vgpio_imx_dt_probe(struct dt_device_node *np)
{
    struct coproc_device *coproc_vgpio;
    struct device *dev = &np->dev;
    int i, ret;
    struct gpio_info *info;
    char *reg_base;
    struct plat_info *pinfo;

    coproc_vgpio = coproc_vgpio_alloc(np, &coproc_vgpio_imx_ops);
    if ( IS_ERR_OR_NULL(coproc_vgpio) )
        return PTR_ERR(coproc_vgpio);

    info = (struct gpio_info *)coproc_vgpio->priv;
    reg_base = (char *)coproc_vgpio->mmios[0].base;

    pinfo = (struct plat_info *)xzalloc(struct plat_info);
    if ( !coproc_vgpio->priv )
    {
        dev_err(dev, "failed to allocate vgpio coproc plat info\n");
        ret = -ENOMEM;
        goto out_release_coproc_vgpio;
    }
    info->plat_info = pinfo;
    pinfo->reg_vaddr_irq_status = (u32 *)(reg_base + GPIO_ISR);
    pinfo->reg_vaddr_imr_status = (u32 *)(reg_base + GPIO_IMR);
    for ( i = 0; i < coproc_vgpio->num_irqs; ++i )
    {
        dev_dbg(dev, "request irq %d (%u)\n", i, coproc_vgpio->irqs[i]);
        ret = request_irq(coproc_vgpio->irqs[i],
                         IRQF_SHARED,
                         coproc_vgpio_imx_irq_handler,
                         "coproc_vgpio irq",
                         coproc_vgpio);
        if ( ret )
        {
            dev_err(dev, "failed to request irq %d (%u)\n", i,
                    coproc_vgpio->irqs[i]);
            goto out_release_irqs;
        }
    }

    ret = coproc_vgpio_sc_resource_get_id(dev, np);
    if ( ret < 0 )
        goto out_release_irqs;
    info->sc_resource_id = ret;

    ret = coproc_vgpio_sc_resource_set_power(dev, info, SC_PM_PW_MODE_ON);
    if ( ret < 0 )
        goto out_release_irqs;

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
    xfree(pinfo);
out_release_coproc_vgpio:
    coproc_vgpio_release(coproc_vgpio);
    return ret;

}

static const struct dt_device_match coproc_vgpio_imx_dt_match[] __initconst =
{
    DT_MATCH_COPROC_VGPIO_IMX,
    { /* sentinel */ },
};

static __init int coproc_vgpio_imx_init(struct dt_device_node *dev, const void *data)
{
    dt_device_set_used_by(dev, DOMID_XEN);

    return coproc_vgpio_imx_dt_probe(dev);;
}

DT_DEVICE_START(coproc_vgpio, "COPROC_VGPIO", DEVICE_COPROC)
    .dt_match = coproc_vgpio_imx_dt_match,
    .init = coproc_vgpio_imx_init,
DT_DEVICE_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
