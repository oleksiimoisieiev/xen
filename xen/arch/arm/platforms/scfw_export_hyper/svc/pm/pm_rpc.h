/*
 * Copyright (c) 2016, Freescale Semiconductor, Inc.
 * Copyright 2017-2018 NXP
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * o Redistributions of source code must retain the above copyright notice, this list
 *   of conditions and the following disclaimer.
 *
 * o Redistributions in binary form must reproduce the above copyright notice, this
 *   list of conditions and the following disclaimer in the documentation and/or
 *   other materials provided with the distribution.
 *
 * o Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*!
 * Header file for the PM RPC implementation.
 *
 * @addtogroup PM_SVC
 * @{
 */

#ifndef SC_PM_RPC_H
#define SC_PM_RPC_H

/* Includes */

/* Defines */

/*!
 * @name Defines for RPC PM function calls
 */
/*@{*/
#define PM_FUNC_UNKNOWN 0 /*!< Unknown function */
#define PM_FUNC_SET_SYS_POWER_MODE 19U /*!< Index for pm_set_sys_power_mode() RPC call */
#define PM_FUNC_SET_PARTITION_POWER_MODE 1U /*!< Index for pm_set_partition_power_mode() RPC call */
#define PM_FUNC_GET_SYS_POWER_MODE 2U /*!< Index for pm_get_sys_power_mode() RPC call */
#define PM_FUNC_SET_RESOURCE_POWER_MODE 3U /*!< Index for pm_set_resource_power_mode() RPC call */
#define PM_FUNC_SET_RESOURCE_POWER_MODE_ALL 22U /*!< Index for pm_set_resource_power_mode_all() RPC call */
#define PM_FUNC_GET_RESOURCE_POWER_MODE 4U /*!< Index for pm_get_resource_power_mode() RPC call */
#define PM_FUNC_REQ_LOW_POWER_MODE 16U /*!< Index for pm_req_low_power_mode() RPC call */
#define PM_FUNC_REQ_CPU_LOW_POWER_MODE 20U /*!< Index for pm_req_cpu_low_power_mode() RPC call */
#define PM_FUNC_SET_CPU_RESUME_ADDR 17U /*!< Index for pm_set_cpu_resume_addr() RPC call */
#define PM_FUNC_SET_CPU_RESUME 21U /*!< Index for pm_set_cpu_resume() RPC call */
#define PM_FUNC_REQ_SYS_IF_POWER_MODE 18U /*!< Index for pm_req_sys_if_power_mode() RPC call */
#define PM_FUNC_SET_CLOCK_RATE 5U /*!< Index for pm_set_clock_rate() RPC call */
#define PM_FUNC_GET_CLOCK_RATE 6U /*!< Index for pm_get_clock_rate() RPC call */
#define PM_FUNC_CLOCK_ENABLE 7U /*!< Index for pm_clock_enable() RPC call */
#define PM_FUNC_SET_CLOCK_PARENT 14U /*!< Index for pm_set_clock_parent() RPC call */
#define PM_FUNC_GET_CLOCK_PARENT 15U /*!< Index for pm_get_clock_parent() RPC call */
#define PM_FUNC_RESET 13U /*!< Index for pm_reset() RPC call */
#define PM_FUNC_RESET_REASON 10U /*!< Index for pm_reset_reason() RPC call */
#define PM_FUNC_BOOT 8U /*!< Index for pm_boot() RPC call */
#define PM_FUNC_REBOOT 9U /*!< Index for pm_reboot() RPC call */
#define PM_FUNC_REBOOT_PARTITION 12U /*!< Index for pm_reboot_partition() RPC call */
#define PM_FUNC_CPU_START 11U /*!< Index for pm_cpu_start() RPC call */
/*@}*/

/* Types */

/* Functions */

/*!
 * This function dispatches an incoming PM RPC request.
 *
 * @param[in]     caller_pt   caller partition
 * @param[in]     msg         pointer to RPC message
 */
void pm_dispatch(sc_rm_pt_t caller_pt, sc_rpc_msg_t *msg);

/*!
 * This function translates and dispatches an PM RPC request.
 *
 * @param[in]     ipc         IPC handle
 * @param[in]     msg         pointer to RPC message
 */
void pm_xlate(sc_ipc_t ipc, sc_rpc_msg_t *msg);

#endif /* SC_PM_RPC_H */

/**@}*/

