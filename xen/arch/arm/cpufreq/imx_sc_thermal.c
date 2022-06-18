// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2018-2020 NXP.
 */

#include <xen/config.h>
#include <xen/device_tree.h>
#include <xen/err.h>
#include <xen/vmap.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <asm/device.h>
#include <asm/io.h>

#include "../platforms/scfw_export_hyper/svc/misc/misc_api.h"

#define SC_MISC_FUNC_GET_TEMP	13
#define SC_TEMP_PASSIVE_COOL_DELTA	10000


enum thermal_trend {
	THERMAL_TREND_STABLE, /* temperature is stable */
	THERMAL_TREND_RAISING, /* temperature is raising */
	THERMAL_TREND_DROPPING, /* temperature is dropping */
	THERMAL_TREND_RAISE_FULL, /* apply highest cooling action */
	THERMAL_TREND_DROP_FULL, /* apply lowest cooling action */
};

static struct imx_sc_ipc *thermal_ipc_handle;

struct imx_sc_sensor {
	struct thermal_zone_device *tzd;
	uint32_t resource_id;
	struct thermal_cooling_device *cdev;
	int temp_passive;
	int temp_critical;
};

struct imx_sc_thermal_data {
	struct imx_sc_sensor *sensor;
};

/* The driver support 1 passive trip point and 1 critical trip point */
enum imx_thermal_trip {
	IMX_TRIP_PASSIVE,
	IMX_TRIP_CRITICAL,
	IMX_TRIP_NUM,
};

static int imx_sc_thermal_get_temp(void *data, int *temp)
{
	sc_err_t ret;
	int16_t celsius;
	int8_t tenths;
	struct imx_sc_sensor *sensor = data;

	ret = sc_misc_get_temp(thermal_ipc_handle, sensor->resource_id, *temp,
			&celsius, &tenths);

	if (ret)
	{
		/*
		 * if the SS power domain is down, read temp will fail, so
		 * we can print error once and return 0 directly.
		 */
		printk(XENLOG_ERR "read temp sensor %d failed, could be SS powered off, ret %d\n",
			sensor->resource_id, ret);
		*temp = 0;
		return 0;
	}

	*temp = celsius * 1000 + tenths * 100;
	return 0;
}

static int imx_sc_thermal_get_trend(void *p, int trip, enum thermal_trend *trend)
{
	int trip_temp;
	struct imx_sc_sensor *sensor = p;

	if (!sensor->tzd)
		return 0;

	trip_temp = (trip == IMX_TRIP_PASSIVE) ? sensor->temp_passive :
					     sensor->temp_critical;

	if (sensor->tzd->temperature >=
		(trip_temp - SC_TEMP_PASSIVE_COOL_DELTA))
		*trend = THERMAL_TREND_RAISE_FULL;
	else
		*trend = THERMAL_TREND_DROP_FULL;

	return 0;
}

static int imx_sc_thermal_set_trip_temp(void *p, int trip, int temp)
{
	struct imx_sc_sensor *sensor = p;

	if (trip == IMX_TRIP_CRITICAL)
		sensor->temp_critical = temp;

	if (trip == IMX_TRIP_PASSIVE)
		sensor->temp_passive = temp;

	return 0;
}

static const struct thermal_zone_of_device_ops imx_sc_thermal_ops = {
	.get_temp = imx_sc_thermal_get_temp,
	.get_trend = imx_sc_thermal_get_trend,
	.set_trip_temp = imx_sc_thermal_set_trip_temp,
};

static int imx_sc_thermal_probe(struct platform_device *pdev)
{
	struct device_node *np, *child, *sensor_np;
	struct imx_sc_sensor *sensor;
	const struct thermal_trip *trip;
	int ret;

	ret = imx_scu_get_handle(&thermal_ipc_handle);
	if (ret)
		return ret;

	np = of_find_node_by_name(NULL, "thermal-zones");
	if (!np)
		return -ENODEV;

	sensor_np = of_node_get(pdev->dev.of_node);

	for_each_available_child_of_node(np, child) {
		sensor = devm_kzalloc(&pdev->dev, sizeof(*sensor), GFP_KERNEL);
		if (!sensor) {
			of_node_put(child);
			of_node_put(sensor_np);
			return -ENOMEM;
		}

		ret = thermal_zone_of_get_sensor_id(child,
						    sensor_np,
						    &sensor->resource_id);
		if (ret < 0) {
			dev_err(&pdev->dev,
				"failed to get valid sensor resource id: %d\n",
				ret);
			of_node_put(child);
			break;
		}

		sensor->tzd = devm_thermal_zone_of_sensor_register(&pdev->dev,
								   sensor->resource_id,
								   sensor,
								   &imx_sc_thermal_ops);
		if (IS_ERR(sensor->tzd)) {
			dev_err(&pdev->dev, "failed to register thermal zone\n");
			ret = PTR_ERR(sensor->tzd);
			of_node_put(child);
			break;
		}

		if (devm_thermal_add_hwmon_sysfs(sensor->tzd))
			dev_warn(&pdev->dev, "failed to add hwmon sysfs attributes\n");

		trip = of_thermal_get_trip_points(sensor->tzd);
		sensor->temp_passive = trip[0].temperature;
		sensor->temp_critical = trip[1].temperature;

		sensor->cdev = devfreq_cooling_register();
		if (IS_ERR(sensor->cdev)) {
			dev_err(&pdev->dev,
				"failed to register devfreq cooling device: %d\n",
				ret);
			return ret;
		}

		ret = thermal_zone_bind_cooling_device(sensor->tzd,
			IMX_TRIP_PASSIVE,
			sensor->cdev,
			THERMAL_NO_LIMIT,
			THERMAL_NO_LIMIT,
			THERMAL_WEIGHT_DEFAULT);
		if (ret) {
			dev_err(&sensor->tzd->device,
				"binding zone %s with cdev %s failed:%d\n",
				sensor->tzd->type, sensor->cdev->type, ret);
			devfreq_cooling_unregister(sensor->cdev);
			return ret;
		}
	}

	of_node_put(sensor_np);

	return ret;
}

static int imx_sc_thermal_remove(struct platform_device *pdev)
{
	return 0;
}

static const struct of_device_id imx_sc_thermal_table[] = {
	{ .compatible = "fsl,imx-sc-thermal", },
	{}
};
MODULE_DEVICE_TABLE(of, imx_sc_thermal_table);

static struct platform_driver imx_sc_thermal_driver = {
		.probe = imx_sc_thermal_probe,
		.remove	= imx_sc_thermal_remove,
		.driver = {
			.name = "imx-sc-thermal",
			.of_match_table = imx_sc_thermal_table,
		},
};
module_platform_driver(imx_sc_thermal_driver);

MODULE_AUTHOR("Anson Huang <Anson.Huang@nxp.com>");
MODULE_DESCRIPTION("Thermal driver for NXP i.MX SoCs with system controller");
MODULE_LICENSE("GPL v2");
