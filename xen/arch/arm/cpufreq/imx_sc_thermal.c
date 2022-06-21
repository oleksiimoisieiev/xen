/*
 *  i.MX8 SC firmware thermal driver.
 *
 *  Copyright 2018-2020 NXP.
 *  Based on drivers/thermal/imx_sc_thermal.c
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  Based on Linux drivers/thermal/imx_sc_thermal
 *  => commit a11753a89ec610768301d4070e10b8bd60fde8cd
 *  git://source.codeaurora.org/external/imx/linux-imx
 *  branch: lf-5.10.y
 *
 *  Xen modification:
 *  Oleksii Moisieiev <oleksii_moisieiev@epam.com>
 *  Copyright (C) 2022 EPAM Systems Inc.
 *
 */

#include <asm/sci.h>
#include <xen/device_tree.h>
#include <xen/tasklet.h>
#include <xen/delay.h>
#include <xen/err.h>
#include <xen/vmap.h>
#include <xen/irq.h>
#include <xen/shutdown.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <asm/device.h>
#include <asm/io.h>

#include "../platforms/scfw_export_hyper/svc/misc/misc_api.h"
#include "asm-arm/delay.h"
#include "xen/config.h"

//TODO do I need some include ?
extern bool cpufreq_debug;

static bool throttle_enabled = false;
//TODO implement
//extern int imx_cpufreq_throttle(bool enable);

//static bool throttle_enabled = false;
//
//TODO move to common place
#define dev_name(dev) dt_node_full_name(dev_to_dt(dev))
#define CELSIUS(temp) temp >> 3
#define TENTH(temp) (temp - (temp >> 3) * 1000) / 100
#define GET_TEMP(celsius, tenths) celsius * 1000 + tenths * 100

#define PASSIVE "passive"
#define CRITICAL "critical"

#define MAX_SENSORS 2

struct imx_sc_temp {
	int temp;
	int hyst;
};

struct imx_sc_sensor {
	uint32_t resource_id;
	unsigned int polling_delay;
	unsigned int polling_delay_passive;
	struct imx_sc_temp temp_passive;
	struct imx_sc_temp temp_critical;
	struct tasklet work;
};

struct imx_sc_thermal_priv {
	struct dt_device_node *np;
	spinlock_t lock;
	struct imx_sc_sensor *sensors[MAX_SENSORS];
};

static struct imx_sc_thermal_priv *thermal_priv;

static int imx_sc_thermal_get_temp(void *data, int *temp)
{
	int ret;
	int16_t celsius;
	int8_t tenths;
	struct imx_sc_sensor *sensor = data;

	ret = sc_misc_get_temp(mu_ipcHandle, sensor->resource_id, SC_MISC_TEMP,
			&celsius, &tenths);

	if (ret) {
		/*
		 * if the SS power domain is down, read temp will fail, so
		 * we can print error once and return 0 directly.
		 */
		printk(XENLOG_ERR "read temp sensor %d failed, could be SS powered off, ret %d\n",
			     sensor->resource_id, ret);
		*temp = 0;
		return 0;
	}

	*temp = GET_TEMP(celsius, tenths);

	return 0;
}

/*
static int imx_sc_thermal_set_alarm(struct imx_sc_sensor *sensor)
{
	unsigned long flags;
	int ret;
	spin_lock_irqsave(&thermal_priv->lock, flags);
	//TODO test it

    printk(XENLOG_INFO "<<< %s %d\n", __func__, __LINE__);
	if (sensor->temp_critical.temp) {
		ret = sc_misc_set_temp(mu_ipcHandle, sensor->resource_id,
				SC_MISC_TEMP_HIGH, CELSIUS(sensor->temp_critical.temp),
				TENTH(sensor->temp_critical.temp));
		if (ret) {
			printk(XENLOG_ERR "Error setting HIGH temp alarm, ret = %d \n", ret);
			return ret;
		}
	}
    printk(XENLOG_INFO "<<< %s %d\n", __func__, __LINE__);
	//TODO test crit = 0
	//TODO test passive =0

	if (sensor->temp_passive.temp) {
		ret = sc_misc_set_temp(mu_ipcHandle, sensor->resource_id,
				SC_MISC_TEMP_LOW, CELSIUS(sensor->temp_passive.temp),
				TENTH(sensor->temp_passive.temp));
		if (ret) {
			printk(XENLOG_ERR "Error setting HIGH temp alarm, ret = %d \n", ret);
			return ret;
		}
	}
    printk(XENLOG_INFO "<<< %s %d\n", __func__, __LINE__);

	spin_unlock_irqrestore(&thermal_priv->lock, flags);

	return 0;
}
*/

#define CPU_THERMAL0 "cpu-thermal0"
#define CPU_THERMAL1 "cpu-thermal1"
#define PMIC_THERMAL0 "pmic-thermal0"

static bool __init imx_dt_node_is_cpu(struct dt_device_node *node)
{
	//TODO test
	if ((strcmp(node->name, CPU_THERMAL0) == 0) ||
		(strcmp(node->name, CPU_THERMAL1) == 0) ||
		(strcmp(node->name, PMIC_THERMAL0) == 0))
		return true;

	return false;
}

static int __init imx_dt_get_sensor_id(struct dt_device_node *node, uint32_t *id)
{
	struct dt_phandle_args sensor_specs;
	int ret;

	ret = dt_parse_phandle_with_args(node,
			"thermal-sensors",
			"#thermal-sensor-cells",
			0,
			&sensor_specs);

	printk(XENLOG_INFO "<<< %s %d: args_count = %d\n", __func__, __LINE__, sensor_specs.args_count);
	if (sensor_specs.args_count > 1) {
		printk(XENLOG_WARNING "%s: too many cells in sensor specifier %d\n",
				node->name, sensor_specs.args_count);
	}

	*id = sensor_specs.args_count ? sensor_specs.args[0] : 0;
	return 0;
}

static int __init imx_dt_get_trips(struct dt_device_node *node,
		struct imx_sc_temp *crit, struct imx_sc_temp *passive)
{
	struct dt_device_node *child, *np;
	int ret;
	u32 temp;
	u32 hyst;
	const char *type;

	np = dt_find_node_by_name(node, "trips");
	if (!np)
		return -ENODEV;

	dt_for_each_child_node(np, child) {
		printk(XENLOG_INFO "<<< %s %d node: %s\n", __func__, __LINE__, child->name);
		ret = dt_property_read_string(child, "type", &type);
		if (ret)
			return -ENOENT;

		ret = dt_property_read_u32(child, "temperature", &temp);
		if (!ret)
			return -ENOENT;

		ret = dt_property_read_u32(child, "hysteresis", &hyst);
		if (!ret)
			return -ENOENT;


		printk(XENLOG_INFO "<<< %s %d type = %s temperature = %d\n",
				__func__, __LINE__, type, temp);

		if (strcmp(type, PASSIVE) == 0)
		{
			passive->temp = temp;
			passive->hyst = hyst;
		}
		else if (strcmp(type, CRITICAL) == 0)
		{
			crit->temp = temp;
			crit->hyst = hyst;
		}
		else
			printk(XENLOG_WARNING "Unknown trip type %s. Ignorig.\n", type);
	}
	return 0;
}

static unsigned long do_throttling(struct imx_sc_sensor *sensor, int temp)
{
	unsigned long delay = sensor->polling_delay;
    printk(XENLOG_INFO "<<< %s %d\n", __func__, __LINE__);
	if ((sensor->temp_critical.temp) &&
		(temp >= sensor->temp_critical.temp))
	{
		printk("Reached critical temperature (%d C): rebooting machine\n",
			temp / 1000);

		machine_restart(0);
	}
	else
	{
    printk(XENLOG_INFO "<<< %s %d\n", __func__, __LINE__);
		if (!sensor->temp_passive.temp)
			goto out;
    printk(XENLOG_INFO "<<< %s %d\n", __func__, __LINE__);

		delay = sensor->polling_delay_passive;
		if (temp > sensor->temp_passive.temp)
		{
			if (throttle_enabled)
				goto out;

			/*if (scpi_cpufreq_throttle(true)) {
				printk("Failed to enable CPU throttling\n");
				return;
			}*/
			throttle_enabled = true;
		}
		else if (temp < sensor->temp_passive.temp -
				sensor->temp_passive.hyst)
		{
			if (!throttle_enabled)
				goto out;

			//scpi_cpufreq_throttle(false);
			throttle_enabled = false;
		}

	}

out:
	return delay;
}

static void imx_sc_thermal_work(void *data)
{
	int ret;
	unsigned long delay;
	int temp;
	struct imx_sc_sensor *sensor = data;

    printk(XENLOG_INFO "<<< %s %d\n", __func__, __LINE__);
	for ( ; ; )
	{
    printk(XENLOG_INFO "<<< %s %d sens = %d\n", __func__, __LINE__, sensor->resource_id);
		ret = imx_sc_thermal_get_temp(sensor, &temp);
		if (ret)
		{
			printk(XENLOG_WARNING "Unable to read temp from sensor: %d",
					sensor->resource_id);
			//TODO make protection for the case when sensor no longer available
			continue;
		}

    printk(XENLOG_INFO "<<< %s %d\n", __func__, __LINE__);
		delay = do_throttling(sensor, temp);

    printk(XENLOG_INFO "<<< %s %d\n", __func__, __LINE__);
		udelay(delay * 1000);
		tasklet_schedule(&sensor->work);

	}
}

static int __init imx_sc_thermal_probe(struct dt_device_node *np)
{
	struct dt_device_node *child;
	struct imx_sc_sensor *sensor;
	int index = 0;
	int temp;
	int ret;

    printk(XENLOG_INFO "<<< %s %d\n", __func__, __LINE__);
	if (thermal_priv)
		return -EEXIST;


	thermal_priv = xzalloc(struct imx_sc_thermal_priv);
	if (!thermal_priv)
		return -ENOMEM;

	spin_lock_init(&thermal_priv->lock);
	thermal_priv->np = np;

	np = dt_find_node_by_name(NULL, "thermal-zones");
	if (!np)
		return -ENODEV;

	dt_for_each_child_node(np, child) {
		if (!imx_dt_node_is_cpu(child))
			continue;

		printk(XENLOG_INFO "<<< %s %d child %s\n",__func__, __LINE__, child->name);
		sensor = xzalloc(struct imx_sc_sensor);
		if (!sensor) {
			goto err_free;
		}

		ret = dt_property_read_u32(child, "polling-delay", &sensor->polling_delay);
		if (!ret)
			return -ENOENT;

		ret = dt_property_read_u32(child, "polling-delay", &sensor->polling_delay_passive);
		if (!ret)
			return -ENOENT;


		ret = imx_dt_get_sensor_id(child, &sensor->resource_id);
		if (ret < 0) {
			printk(XENLOG_ERR
				"failed to get valid sensor resource id: %d\n",
				ret);
			break;
		}

		ret = imx_dt_get_trips(child, &sensor->temp_critical,
				&sensor->temp_passive);
		if (ret) {
			printk(XENLOG_ERR "Wrong format of the trip dt node\n");
			break;
		}

		printk(XENLOG_INFO "<<< %s %d sens id = %d crit = %d, passive = %d\n",__func__, __LINE__,
				sensor->resource_id,
				sensor->temp_critical.temp, sensor->temp_passive.temp);
/*		ret = imx_sc_thermal_set_alarm(sensor);
		if (ret) {
			printk(XENLOG_ERR "Unable to set alarm for sensor %d\n",
					sensor->resource_id);
			break;
		}
*/

		tasklet_init(&sensor->work, imx_sc_thermal_work, (void *)sensor);

		if (index >= MAX_SENSORS)
			break;

		thermal_priv->sensors[index++] = sensor;
		//TODO remove it
		imx_sc_thermal_get_temp(sensor, &temp);
		printk(XENLOG_INFO "sensor rcid = %d temp %d\n", sensor->resource_id,
				temp);
	}

	return 0;

err_free:
	xfree(thermal_priv);

	return ret;
}
//TODO cleanup function

static const struct dt_device_match imx_sc_thermal_table[] __initconst = {
	{ .compatible = "fsl,imx-sc-thermal", },
	{ },
};

static int __init imx_sc_thermal_init(struct dt_device_node *np,
		const void *data)
{
	//TODO what is void *data?
    //TODO test
	int ret;

	dt_device_set_used_by(np, DOMID_XEN);

	ret = imx_sc_thermal_probe(np);
	if (ret) {
		printk(XENLOG_ERR "%s: failed to init i.MX8 SC THS (%d)\n",
				dev_name(&np->dev), ret);
		return ret;
	}

	return 0;
}

DT_DEVICE_START(imx_sc_thermal, "i.MX8 SC THS", DEVICE_THS)
	.dt_match = imx_sc_thermal_table,
	.init = imx_sc_thermal_init,
DT_DEVICE_END
