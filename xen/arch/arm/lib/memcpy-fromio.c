/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/io.h>

/*
 * Arm implementation notes / limitations:
 * - Uses ordered 8-bit for leading/trailing unaligned bytes and ordered
 *   32-bit accesses for the aligned bulk; no wider accesses are issued.
 * - Only suitable for devices that tolerate 8-bit and 32-bit accesses;
 *   do not use with devices requiring strictly 16-bit or 64-bit accesses.
 * - MMIO must be mapped with appropriate device attributes to preserve
 *   ordering; no extra barriers beyond the ordered accessors are added.
 * - If source or destination is misaligned, leading bytes are copied
 *   byte-by-byte until both sides are 32-bit aligned, then bulk copy uses
 *   32-bit accesses.
 */

void memcpy_fromio(void *to, const volatile void __iomem *from,
                   size_t count)
{
    while ( count && (!IS_ALIGNED((unsigned long)from, 4) ||
                      !IS_ALIGNED((unsigned long)to, 4)) )
    {
        *(uint8_t *)to = readb(from);
        from++;
        to++;
        count--;
    }

    while ( count >= 4 )
    {
        *(uint32_t *)to = readl(from);
        from += 4;
        to += 4;
        count -= 4;
    }

    while ( count )
    {
        *(uint8_t *)to = readb(from);
        from++;
        to++;
        count--;
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 */
