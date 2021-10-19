/*
 * xen/arch/arm/coproc/plat/coproc_vgpio_rcar.h
 *
 * COPROC VGPIO RCAR platform specific code
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

#define GPIO_IOINTSEL 0x00  /* General IO/Interrupt Switching Register */
#define GPIO_INOUTSEL 0x04  /* General Input/Output Switching Register */
#define GPIO_OUTDT 0x08     /* General Output Register */
#define GPIO_INDT 0x0c      /* General Input Register */
#define GPIO_INTDT 0x10     /* Interrupt Display Register */
#define GPIO_INTCLR 0x14    /* Interrupt Clear Register */
#define GPIO_INTMSK 0x18    /* Interrupt Mask Register */
#define GPIO_MSKCLR 0x1c    /* Interrupt Mask Clear Register */
#define GPIO_POSNEG 0x20    /* Positive/Negative Logic Select Register */
#define GPIO_EDGLEVEL 0x24  /* Edge/level Select Register */
#define GPIO_FILONOFF 0x28  /* Chattering Prevention On/Off Register */
#define GPIO_BOTHEDGE 0x4c  /* One Edge/Both Edge Select Register */

struct plat_info {
    u32 *reg_vaddr_irq_status;
    u32 *reg_vaddr_icr_status;
    u32 *reg_vaddr_imr_status;
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
