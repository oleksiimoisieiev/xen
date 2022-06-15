/*
 * xen/arch/arm/cpufreq/imx_cpufreq.c
 *
 * SCPI based CPUFreq driver
 *
 * Based on Xen arch/x86/acpi/cpufreq/cpufreq.c
 *
 * Oleksandr Tyshchenko <oleksandr_tyshchenko@epam.com>
 * Copyright (c) 2017 EPAM Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */
#include <xen/sched.h>
#include <xen/cpufreq.h>
#include <xen/pmstat.h>

static unsigned int imx_cpufreq_get(unsigned int cpu)
{
    printk(XENLOG_INFO "<<< %s %d\n", __func__, __LINE__);
    return 0;
}

static int imx_cpufreq_update(int cpuid, struct cpufreq_policy *policy)
{
    printk(XENLOG_INFO "<<< %s %d\n", __func__, __LINE__);
    return 0;
}

static int imx_cpufreq_target(struct cpufreq_policy *policy,
                               unsigned int target_freq, unsigned int relation)
{
    printk(XENLOG_INFO "<<< %s %d\n", __func__, __LINE__);
    return 0;
}

static int imx_cpufreq_verify(struct cpufreq_policy *policy)
{
    printk(XENLOG_INFO "<<< %s %d\n", __func__, __LINE__);
    return 0;
}
static int imx_cpufreq_cpu_init(struct cpufreq_policy *policy)
{
    printk(XENLOG_INFO "<<< %s %d\n", __func__, __LINE__);
    return 0;
}
static int imx_cpufreq_cpu_exit(struct cpufreq_policy *policy)
{
    printk(XENLOG_INFO "<<< %s %d\n", __func__, __LINE__);
    return 0;
}

static struct cpufreq_driver imx_cpufreq_driver = {
    .name   = "imx-cpufreq",

    .verify = imx_cpufreq_verify,
    .target = imx_cpufreq_target,
    .get    = imx_cpufreq_get,
    .init   = imx_cpufreq_cpu_init,
    .exit   = imx_cpufreq_cpu_exit,
    .update = imx_cpufreq_update,
};


int cpufreq_cpu_init(unsigned int cpuid)
{
    printk(XENLOG_INFO "<<< %s %d\n", __func__, __LINE__);
    return 0;
}

static int __init cpufreq_imx_driver_init(void)
{
    printk(XENLOG_INFO "<<< %s %d\n", __func__, __LINE__);

    return cpufreq_register_driver(&imx_cpufreq_driver);
}
__initcall(cpufreq_imx_driver_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
