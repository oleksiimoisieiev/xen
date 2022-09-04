// SPDX-License-Identifier: GPL-2.0-only
/*
 *  step_wise.c - A step-by-step Thermal throttling governor
 *
 *  Copyright (C) 2012 Intel Corp
 *  Copyright (C) 2012 Durgadoss R <durgadoss.r@intel.com>
 *
 *  Ported to Xen:
 *  xen/drivers/thermal/gov_step_wise.c
 *
 *  Copyright (C) 2022 Oleksii Moisieiev <oleksii_mosieiev@epam.com>
 *
 *  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <xen/cpufreq.h>
#include <xen/lib.h>
#include <xen/init.h>
#include <xen/spinlock.h>
#include <xen/time.h>
#include <xen/timer.h>

#include <xen/thermal.h>

static int usr_freq_step = 100000;
static int usr_delay = 250;

/*
 * If the temperature is higher than a trip point,
 *    a. if the trend is THERMAL_TREND_RAISING, use lower freq
 *       state for this trip point
 *    b. if the trend is THERMAL_TREND_DROPPING, do nothing
 *    c. if the trend is THERMAL_TREND_RAISE_FULL, use lowest freq
 *       for this trip point
 *    d. if the trend is THERMAL_TREND_DROP_FULL, use max limit
 *       for this trip point
 * If the temperature is lower than a trip point,
 *    a. if the trend is THERMAL_TREND_RAISING, do nothing
 *    b. if the trend is THERMAL_TREND_DROPPING, use higher freq
 *       state for this trip point
 *    c. if the trend is THERMAL_TREND_RAISE_FULL, do nothing
 *    d. if the trend is THERMAL_TREND_DROP_FULL, use max freq
 */
static unsigned long get_target_freq(struct thermal_sensor *sensor,
                enum thermal_trend trend, struct cpufreq_policy *policy,
                int throttle)
{
    unsigned long next_freq = policy->max;

    if ( !throttle )
        return next_freq;

    switch ( trend )
    {
    case THERMAL_TREND_RAISING:
        next_freq = policy->cur - usr_freq_step;
        if ( next_freq < policy->min )
            next_freq = policy->min;
        break;
    case THERMAL_TREND_RAISE_FULL:
        next_freq = policy->min;
        break;
    case THERMAL_TREND_STABLE:
        next_freq = policy->cur;
    case THERMAL_TREND_DROPPING:
        next_freq = policy->cur + usr_freq_step;
        if ( next_freq > policy->max )
            next_freq = policy->max;
        break;
    case THERMAL_TREND_DROP_FULL:
        next_freq = policy->max;
        break;
    default:
        break;
    }

    return next_freq;
};

static void thermal_sensor_trip_update(struct thermal_sensor *sensor, int trip)
{
    int trip_temp;
    enum thermal_trend trend;
    int temperature;
    struct cpufreq_policy *cur_policy;
    bool throttle = false;
    unsigned long new_freq;
    int relation;
    int ret;
    unsigned long flags;

    ret = sensor->ops->get_trend(sensor, trip, &trend);
    if ( ret )
    {
        printk(XENLOG_ERR "%s: unable to read trend: %d\n", __func__, ret);
        return;
    }

    if (trip == THERMAL_TRIPS_NONE)
    {
        printk (XENLOG_DEBUG "[Sens %d] Disable throttling\n",
                sensor->sensor_id);
        throttle = false;
    }
    else
    {
        enum thermal_trip_type trip_type;
        sensor->ops->get_trip_temp(sensor->data, trip, &trip_temp);
        sensor->ops->get_trip_type(sensor->data, trip, &trip_type);

        ret = sensor->ops->get_temp(sensor->data, &temperature);
        if ( ret )
        {
            printk(XENLOG_ERR "%s: unable to read temp: %d\n", __func__, ret);
            return;
        }

        throttle = get_throttle_flag(temperature, trip_temp, trend);
        printk(XENLOG_DEBUG "Trip%d[type=%d,temp=%d]:trend=%d,throttle=%d\n",
            trip, trip_type, trip_temp, trend, throttle);
    }

    spin_lock_irqsave(&sensor->lock, flags);

    cur_policy = __cpufreq_get_policy(sensor->sensor_id);
    new_freq = get_target_freq(sensor, trend, cur_policy, throttle);

    if ( throttle )
        __cpufreq_policy_set_owner(cur_policy, OWNER_THERMAL);
    else
        __cpufreq_policy_set_owner(cur_policy, OWNER_CPUFREQ);

    relation = get_target_relation(trend);
    printk(XENLOG_DEBUG "[Policy]min=%d,max=%d,cur=%d,next=%ld,rel=%d\n",
            cur_policy->min, cur_policy->max, cur_policy->cur,
            new_freq, relation);

    ret = __cpufreq_driver_target(cur_policy, new_freq, relation,
                OWNER_THERMAL);

    spin_unlock_irqrestore(&sensor->lock, flags);

    if ( throttle )
        activate_throttle(sensor, usr_delay, trip);
    else
        deactivate_throttle(sensor);
}

/**
 * step_wise_throttle - throttles devices associated with the given zone
 * @sensor_id: id of the sensor
 * @sensor: pointer to the sensor structure
 * @trip: trip point index
 *
 * Throttling Logic: This uses the trend of the thermal zone to throttle.
 * If the thermal zone is 'heating up' this throttles all the cooling
 * devices associated with the zone and its particular trip point, by one
 * step. If the zone is 'cooling down' it brings back the performance of
 * the devices by one step.
 */
static int step_wise_throttle(int sensor_id, struct thermal_sensor *sensor,
        int trip)
{
    thermal_sensor_trip_update(sensor, trip);
    return 0;
}

bool_t step_wise_handle_option(const char *name, const char *val)
{
    if ( !strcmp(name, "freq_step") && val )
        usr_freq_step = simple_strtoul(val, NULL, 0);

    if ( !strcmp(name, "delay") && val )
        usr_delay = simple_strtoul(val, NULL, 0);

    return 0;
}

struct thermal_governor thermal_gov_step_wise = {
    .name        = "step_wise",
    .throttle    = step_wise_throttle,
    .handle_option = step_wise_handle_option,
};

static int __init init_thermal_gov_step_wise(void)
{
    return thermal_register_governor(&thermal_gov_step_wise);
}
__initcall(init_thermal_gov_step_wise);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
