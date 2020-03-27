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

#include "../coproc.h"
#include "common.h"

#include <asm/io.h>
#include <xen/err.h>
#include <xen/init.h>
#include <xen/irq.h>

#define VRANGE32(start, end) start ... end + 3
#define VRANGE64(start, end) start ... end + 7

#define GPIO_WORD_SIZE  2

#define GPIO_DR         0x0
#define GPIO_GDIR       0x4
#define GPIO_PSR        0x8
#define GPIO_ICR1       0xC
#define GPIO_ICR2       0x10
#define GPIO_IMR        0x14
#define GPIO_ISR        0x18
#define GPIO_EDGE_SEL   0x1C

#define GPIO_DR_SET     0x84
#define GPIO_DR_CLEAR   0x88
#define GPIO_DR_TOGGLE  0x8C

struct gpio_info {
    spinlock_t lock;
    paddr_t base;
    paddr_t size;
    u32 *reg_vaddr_irq_status;
    u32 *reg_vaddr_icr1_status;
    u32 *reg_vaddr_icr2_status;
    u32 *reg_vaddr_imr_status;
    void __iomem *mapbase;
    struct domain *dom;
    u32 pins_assigned;
    u32 sc_resource_id;
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


#endif /* __ARCH_ARM_COPROC_PLAT_COPROC_XXX_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
