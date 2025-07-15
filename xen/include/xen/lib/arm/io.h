/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _XEN_LIB_ARM_IO_H
#define _XEN_LIB_ARM_IO_H

#include <xen/types.h>

/*
 * Prototypes for I/O memory access functions.
 */
extern void __memcpy_fromio(void *to, const volatile void __iomem *from,
                     size_t count);
extern void __memcpy_toio(volatile void __iomem *to, const void *from,
                   size_t count);

#endif /* _XEN_LIB_ARM_IO_H */
