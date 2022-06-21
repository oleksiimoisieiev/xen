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

#include "../platforms/scfw_export_hyper/main/scfw.h"
#include "../platforms/scfw_export_hyper/svc/misc/misc_api.h"
#include "xen/config.h"

//TODO do I need some include ?
extern sc_ipc_t mu_ipcHandle;
extern bool cpufreq_debug;

//TODO implement
//extern int imx_cpufreq_throttle(bool enable);

//static bool throttle_enabled = false;
//
//TODO move to common place
#define dev_name(dev) dt_node_full_name(dev_to_dt(dev))
#define CELSIUS(temp) temp >> 3
#define TENTH(temp) (temp - (temp >> 3) * 1000) / 100
#define GET_TEMP(celsius, tenths) celsius * 1000 + tenths * 100

#define MAX_SENSORS 2

struct imx_sc_sensor {
	uint32_t resource_id;
	int temp_passive;
	int temp_critical;
};

struct imx_sc_thermal_priv {
//	struct device *dev;
	struct tasklet work;
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

static int imx_sc_thermal_set_alarm(struct imx_sc_sensor *sensor)
{
	unsigned long flags;
	int ret;
	spin_lock_irqsave(&thermal_priv->lock, flags);
	//TODO test it

	if (sensor->temp_critical) {
		ret = sc_misc_set_temp(mu_ipcHandle, sensor->resource_id,
				SC_MISC_TEMP_HIGH, CELSIUS(sensor->temp_critical),
				TENTH(sensor->temp_critical));
		if (ret) {
			printk(XENLOG_ERR "Error setting HIGH temp alarm, ret = %d \n", ret);
			return ret;
		}
	}

	if (sensor->temp_passive) {
		ret = sc_misc_set_temp(mu_ipcHandle, sensor->resource_id,
				SC_MISC_TEMP_LOW, CELSIUS(sensor->temp_passive),
				TENTH(sensor->temp_passive));
		if (ret) {
			printk(XENLOG_ERR "Error setting HIGH temp alarm, ret = %d \n", ret);
			return ret;
		}
	}

	spin_unlock_irqrestore(&thermal_priv->lock, flags);

	return 0;
}

static int __init imx_dt_get_sensor_id(struct dt_device_node *node, uint32_t *id)
{
	return 0;
}

static int __init imx_dt_get_trips(struct dt_device_node *node,
		int *crit, int *passive)
{
	return 0;
}

static int __init imx_sc_thermal_probe(struct dt_device_node *np)
{
	struct dt_device_node *child;
	struct imx_sc_sensor *sensor;
	int index = 0;
	int temp;
	int ret;

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
		sensor = xzalloc(struct imx_sc_sensor);
		if (!sensor) {
			goto err_free;
		}

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
			printk(XENLOG_ERR "Wrong format of the trip dt node");
			break;
		}
		
		ret = imx_sc_thermal_set_alarm(sensor);
		if (ret) {
			printk(XENLOG_ERR "Unable to set alarm for sensor %d\n",
					sensor->resource_id);
			break;
		}

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
