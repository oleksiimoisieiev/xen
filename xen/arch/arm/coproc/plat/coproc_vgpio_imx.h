/*
 * xen/arch/arm/coproc/plat/coproc_vgpio_imx.h
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

#include "coproc_vgpio.h"

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

struct plat_info {
    u32 *reg_vaddr_irq_status;
    u32 *reg_vaddr_icr1_status;
    u32 *reg_vaddr_icr2_status;
    u32 *reg_vaddr_imr_status;
    u32 sc_resource_id;
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
