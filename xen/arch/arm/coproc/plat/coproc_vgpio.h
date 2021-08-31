/*
 * xen/arch/arm/coproc/plat/coproc_vgpio.h
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

#ifndef __ARCH_ARM_COPROC_PLAT_COPROC_VGPIO_H__
#define __ARCH_ARM_COPROC_PLAT_COPROC_VGPIO_H__

#include "coproc.h"
#include "common.h"

#include <asm/io.h>
#include <xen/err.h>
#include <xen/init.h>
#include <xen/irq.h>

struct gpio_info {
    spinlock_t lock;
    paddr_t base;
    paddr_t size;
    void *plat_info;
    void __iomem *mapbase;
    struct domain *dom;
    u32 pins_assigned;
};

struct vgpio_info {
    u32 reg_val_irq_status;
    u32 pins_allowed;
};

static inline u32 vgpio_read32(struct coproc_device *coproc,
                                    u32 offset)
{
    u32 val = readl((char *)coproc->mmios[0].base + offset);
    return val;
}

static inline void vgpio_write32(struct coproc_device *coproc,
                                 u32 offset, u32 val)
{
    writel(val, (char *)coproc->mmios[0].base + offset);
}

int vcoproc_vgpio_vcoproc_init(struct vcoproc_instance *vcoproc,
                                      const char *cfg);
void vcoproc_vgpio_vcoproc_deinit(struct vcoproc_instance *vcoproc);
struct coproc_device *coproc_vgpio_alloc(struct dt_device_node *np,
                                   const struct coproc_ops *ops);
void coproc_vgpio_release(struct coproc_device *coproc_vgpio);

#endif /* __ARCH_ARM_COPROC_PLAT_COPROC_VGPIO_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
