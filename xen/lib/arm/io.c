#include <asm/io.h>
#include <xen/lib/arm/io.h>

/*
 * memcpy_fromio - Copy data from IO memory space to "real" memory space.
 * @to: Where to copy to
 * @from: Where to copy from
 * @count: The size of the area.
 */
void __memcpy_fromio(void *to, const volatile void __iomem *from,
                     size_t count)
{
    while ( count && !IS_ALIGNED((unsigned long)from, 4) )
    {
        *(u8 *)to = readb_relaxed(from);
        from++;
        to++;
        count--;
    }

    while ( count >= 4 )
    {
        *(u32 *)to = readl_relaxed(from);
        from += 4;
        to += 4;
        count -= 4;
    }

    while ( count )
    {
        *(u8 *)to = readb_relaxed(from);
        from++;
        to++;
        count--;
    }
}

/*
 * memcpy_toio - Copy data from "real" memory space to IO memory space.
 * @to: Where to copy to
 * @from: Where to copy from
 * @count: The size of the area.
 */
void __memcpy_toio(volatile void __iomem *to, const void *from,
                   size_t count)
{
    while ( count && !IS_ALIGNED((unsigned long)to, 4) )
    {
        writeb_relaxed(*(u8 *)from, to);
        from++;
        to++;
        count--;
    }

    while ( count >= 4 )
    {
        writel_relaxed(*(u32 *)from, to);
        from += 4;
        to += 4;
        count -= 4;
    }

    while ( count )
    {
        writeb_relaxed(*(u8 *)from, to);
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
