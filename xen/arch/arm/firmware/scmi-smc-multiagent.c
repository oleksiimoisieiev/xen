/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SCI SCMI multi-agent driver, using SMC/HVC shmem as transport.
 *
 * Oleksii Moisieiev <oleksii_moisieiev@epam.com>
 * Copyright (c) 2025 EPAM Systems
 */

#include <xen/acpi.h>

#include <xen/device_tree.h>
#include <xen/init.h>
#include <xen/iocap.h>
#include <xen/err.h>
#include <xen/libfdt/libfdt.h>
#include <xen/param.h>
#include <xen/sched.h>
#include <xen/vmap.h>

#include <asm/firmware/sci.h>
#include <asm/smccc.h>

#include "scmi-proto.h"
#include "scmi-shmem.h"

#define SCMI_AGENT_ID_INVALID 0xFF

static uint8_t __initdata opt_dom0_scmi_agent_id = SCMI_AGENT_ID_INVALID;
integer_param("dom0_scmi_agent_id", opt_dom0_scmi_agent_id);

#define SCMI_SECONDARY_AGENTS "scmi-secondary-agents"

struct scmi_channel {
    uint32_t agent_id;
    uint32_t func_id;
    domid_t domain_id;
    uint64_t paddr;
    uint64_t len;
    struct scmi_shared_mem __iomem *shmem;
    spinlock_t lock;
    struct list_head list;
};

struct scmi_data {
    struct list_head channel_list;
    spinlock_t channel_list_lock;
    uint32_t func_id;
    bool initialized;
    uint32_t shmem_phandle;
    uint32_t hyp_channel_agent_id;
    struct dt_device_node *dt_dev;
};

static struct scmi_data scmi_data;

static int send_smc_message(struct scmi_channel *chan_info,
                            scmi_msg_header_t *hdr, void *data, int len)
{
    struct arm_smccc_res resp;
    int ret;

    ret = shmem_put_message(chan_info->shmem, hdr, data, len);
    if ( ret )
        return ret;

    arm_smccc_1_1_smc(chan_info->func_id, 0, 0, 0, 0, 0, 0, 0, &resp);

    if ( resp.a0 == ARM_SMCCC_INVALID_PARAMETER )
        return -EINVAL;

    if ( resp.a0 )
        return -EOPNOTSUPP;

    return 0;
}

static int do_smc_xfer(struct scmi_channel *chan_info, scmi_msg_header_t *hdr,
                       void *tx_data, int tx_size, void *rx_data, int rx_size)
{
    int ret = 0;

    ASSERT(chan_info && chan_info->shmem);

    if ( !hdr )
        return -EINVAL;

    spin_lock(&chan_info->lock);

    printk(XENLOG_DEBUG
           "scmi: agent_id = %d msg_id = %x type = %d, proto = %x\n",
           chan_info->agent_id, hdr->id, hdr->type, hdr->protocol);

    ret = send_smc_message(chan_info, hdr, tx_data, tx_size);
    if ( ret )
        goto clean;

    ret = shmem_get_response(chan_info->shmem, hdr, rx_data, rx_size);

clean:
    printk(XENLOG_DEBUG
           "scmi: get smc response agent_id = %d msg_id = %x proto = %x res=%d\n",
           chan_info->agent_id, hdr->id, hdr->protocol, ret);

    spin_unlock(&chan_info->lock);

    return ret;
}

static struct scmi_channel *get_channel_by_id(uint32_t agent_id)
{
    struct scmi_channel *curr;
    bool found = false;

    spin_lock(&scmi_data.channel_list_lock);
    list_for_each_entry(curr, &scmi_data.channel_list, list)
    {
        if ( curr->agent_id == agent_id )
        {
            found = true;
            break;
        }
    }

    spin_unlock(&scmi_data.channel_list_lock);
    if ( found )
        return curr;

    return NULL;
}

static struct scmi_channel *acquire_scmi_channel(struct domain *d,
                                                 uint32_t agent_id)
{
    struct scmi_channel *curr;
    struct scmi_channel *ret = ERR_PTR(-ENOENT);

    spin_lock(&scmi_data.channel_list_lock);
    list_for_each_entry(curr, &scmi_data.channel_list, list)
    {
        if ( curr->agent_id == agent_id )
        {
            if ( curr->domain_id != DOMID_INVALID )
            {
                ret = ERR_PTR(-EEXIST);
                break;
            }

            curr->domain_id = d->domain_id;
            ret = curr;
            break;
        }
    }

    spin_unlock(&scmi_data.channel_list_lock);

    return ret;
}

static void relinquish_scmi_channel(struct scmi_channel *channel)
{
    ASSERT(channel != NULL);

    spin_lock(&scmi_data.channel_list_lock);
    channel->domain_id = DOMID_INVALID;
    spin_unlock(&scmi_data.channel_list_lock);
}

static int map_channel_memory(struct scmi_channel *channel)
{
    ASSERT(channel && channel->paddr);
    channel->shmem = ioremap_nocache(channel->paddr, SCMI_SHMEM_MAPPED_SIZE);
    if ( !channel->shmem )
        return -ENOMEM;

    channel->shmem->channel_status = SCMI_SHMEM_CHAN_STAT_CHANNEL_FREE;
    printk(XENLOG_DEBUG "scmi: Got shmem %lx after vmap %p\n", channel->paddr,
           channel->shmem);

    return 0;
}

static void unmap_channel_memory(struct scmi_channel *channel)
{
    ASSERT(channel && channel->shmem);
    iounmap(channel->shmem);
    channel->shmem = NULL;
}

static struct scmi_channel *smc_create_channel(uint32_t agent_id,
                                               uint32_t func_id, uint64_t addr)
{
    struct scmi_channel *channel;

    channel = get_channel_by_id(agent_id);
    if ( channel )
        return ERR_PTR(EEXIST);

    channel = xmalloc(struct scmi_channel);
    if ( !channel )
        return ERR_PTR(ENOMEM);

    spin_lock_init(&channel->lock);
    channel->agent_id = agent_id;
    channel->func_id = func_id;
    channel->domain_id = DOMID_INVALID;
    channel->shmem = NULL;
    channel->paddr = addr;
    list_add_tail(&channel->list, &scmi_data.channel_list);
    return channel;
}

static void free_channel_list(void)
{
    struct scmi_channel *curr, *_curr;

    list_for_each_entry_safe(curr, _curr, &scmi_data.channel_list, list)
    {
        list_del(&curr->list);
        xfree(curr);
    }
}

static int __init
scmi_dt_read_hyp_channel_addr(struct dt_device_node *scmi_node, u64 *addr,
                              u64 *size)
{
    struct dt_device_node *shmem_node;
    const __be32 *prop;

    prop = dt_get_property(scmi_node, "shmem", NULL);
    if ( !prop )
        return -EINVAL;

    shmem_node = dt_find_node_by_phandle(be32_to_cpu(*prop));
    if ( IS_ERR_OR_NULL(shmem_node) )
    {
        printk(XENLOG_ERR
               "scmi: Device tree error, can't parse reserved memory %ld\n",
               PTR_ERR(shmem_node));
        return PTR_ERR(shmem_node);
    }

    return dt_device_get_address(shmem_node, 0, addr, size);
}

/*
 * Handle Dom0 SCMI specific DT nodes
 *
 * Make a decision on copying SCMI specific nodes into Dom0 device tree.
 * For SCMI multi-agent case:
 * - shmem nodes will not be copied and generated instead if SCMI
 *   is enabled for Dom0
 * - scmi node will be copied if SCMI is enabled for Dom0
 */
static bool scmi_dt_handle_node(struct domain *d, struct dt_device_node *node)
{
    static const struct dt_device_match shmem_matches[] __initconst = {
        DT_MATCH_COMPATIBLE("arm,scmi-shmem"),
        { /* sentinel */ },
    };
    static const struct dt_device_match scmi_matches[] __initconst = {
        DT_MATCH_PATH("/firmware/scmi"),
        { /* sentinel */ },
    };

    if ( !scmi_data.initialized )
        return false;

    /* skip scmi shmem node for dom0 if scmi not enabled */
    if ( dt_match_node(shmem_matches, node) && !sci_domain_is_enabled(d) )
    {
        dt_dprintk("  Skip scmi shmem node\n");
        return true;
    }

    /* drop scmi if not enabled */
    if ( dt_match_node(scmi_matches, node) && !sci_domain_is_enabled(d) )
    {
        dt_dprintk("  Skip scmi node\n");
        return true;
    }

    return false;
}

static int scmi_assign_device(uint32_t agent_id, uint32_t device_id,
                              uint32_t flags)
{
    struct scmi_msg_base_set_device_permissions_a2p tx;
    struct scmi_channel *channel;
    scmi_msg_header_t hdr;

    channel = get_channel_by_id(scmi_data.hyp_channel_agent_id);
    if ( !channel )
        return -EINVAL;

    hdr.id = SCMI_BASE_SET_DEVICE_PERMISSIONS;
    hdr.type = 0;
    hdr.protocol = SCMI_BASE_PROTOCOL;

    tx.agent_id = agent_id;
    tx.device_id = device_id;
    tx.flags = flags;

    return do_smc_xfer(channel, &hdr, &tx, sizeof(tx), NULL, 0);
}

static int scmi_dt_assign_device(struct domain *d,
                                 struct dt_phandle_args *ac_spec)
{
    struct scmi_channel *agent_channel;
    uint32_t scmi_device_id = ac_spec->args[0];
    int ret;

    if ( !d->arch.sci_data )
        return 0;

    /* The access-controllers is specified for DT dev, but it's not a SCMI */
    if ( ac_spec->np != scmi_data.dt_dev )
        return 0;

    agent_channel = d->arch.sci_data;

    spin_lock(&agent_channel->lock);

    ret = scmi_assign_device(agent_channel->agent_id, scmi_device_id,
                             SCMI_BASE_DEVICE_ACCESS_ALLOW);
    if ( ret )
    {
        printk(XENLOG_ERR
               "scmi: could not assign dev for %pd agent:%d dev_id:%u (%d)",
               d, agent_channel->agent_id, scmi_device_id, ret);
    }

    spin_unlock(&agent_channel->lock);
    return ret;
}

static int collect_agent_id(struct scmi_channel *agent_channel)
{
    int ret;
    scmi_msg_header_t hdr;
    struct scmi_msg_base_discover_agent_p2a da_rx;
    struct scmi_msg_base_discover_agent_a2p da_tx;

    ret = map_channel_memory(agent_channel);
    if ( ret )
        return ret;

    hdr.id = SCMI_BASE_DISCOVER_AGENT;
    hdr.type = 0;
    hdr.protocol = SCMI_BASE_PROTOCOL;

    da_tx.agent_id = agent_channel->agent_id;

    ret = do_smc_xfer(agent_channel, &hdr, &da_tx, sizeof(da_tx), &da_rx,
                        sizeof(da_rx));
    if ( agent_channel->domain_id != DOMID_XEN )
        unmap_channel_memory(agent_channel);
    if ( ret )
        return ret;

    printk(XENLOG_DEBUG "id=0x%x name=%s\n", da_rx.agent_id, da_rx.name);
    agent_channel->agent_id = da_rx.agent_id;
    return 0;
}

static __init int collect_agents(struct dt_device_node *scmi_node)
{
    const struct dt_device_node *config_node;
    const __be32 *prop;
    uint32_t len;
    const __be32 *end;
    uint32_t cells_per_entry = 3; /* Default to 3 cells if property is absent. */

    config_node = dt_find_node_by_path("/chosen/xen,config");
    if ( !config_node )
    {
        printk(XENLOG_WARNING "scmi: /chosen/xen,config node not found, no agents to collect.\n");
        return -ENOENT;
    }

    /* Check for the optional '#scmi-secondary-agents-cells' property. */
    if ( dt_property_read_u32(config_node, "#scmi-secondary-agents-cells",
                              &cells_per_entry) )
    {
        if ( cells_per_entry != 2 && cells_per_entry != 3 )
        {
            printk(XENLOG_ERR "scmi: Invalid #scmi-secondary-agents-cells value: %u\n",
                   cells_per_entry);
            return -EINVAL;
        }
    }

    prop = dt_get_property(config_node, SCMI_SECONDARY_AGENTS, &len);
    if ( !prop )
    {
        /* This is not an error, as there may be no secondary agents. */
        printk(XENLOG_WARNING "scmi: No %s property found, no agents to collect.\n",
               SCMI_SECONDARY_AGENTS);
        return -EINVAL;
    }

    /* Validate that the property length is a multiple of the cell size. */
    if ( len == 0 || len % (cells_per_entry * sizeof(uint32_t)) != 0 )
    {
        printk(XENLOG_ERR "scmi: Invalid length of %s property: %u for %u cells per entry\n",
               SCMI_SECONDARY_AGENTS, len, cells_per_entry);
        return -EINVAL;
    }

    end = (const __be32 *)((const u8 *)prop + len);

    for ( ; prop < end; )
    {
        uint32_t agent_id;
        uint32_t smc_id;
        uint32_t shmem_phandle;
        struct dt_device_node *node;
        u64 addr, size;
        int ret;
        struct scmi_channel *agent_channel;

        smc_id = be32_to_cpu(*prop++);
        shmem_phandle = be32_to_cpu(*prop++);

        if ( cells_per_entry == 3 )
            agent_id = be32_to_cpu(*prop++);
        else
            agent_id = SCMI_BASE_AGENT_ID_OWN;

        node = dt_find_node_by_phandle(shmem_phandle);
        if ( !node )
        {
            printk(XENLOG_ERR "scmi: Could not find shmem node for agent %u\n",
                   agent_id);
            return -EINVAL;
        }

        ret = dt_device_get_address(node, 0, &addr, &size);
        if ( ret )
        {
            printk(XENLOG_ERR
                   "scmi: Could not read shmem address for agent %u: %d\n",
                   agent_id, ret);
            return ret;
        }

        if ( !IS_ALIGNED(size, SCMI_SHMEM_MAPPED_SIZE) )
        {
            printk(XENLOG_ERR "scmi: shmem memory is not aligned\n");
            return -EINVAL;
        }

        agent_channel = smc_create_channel(agent_id, smc_id, addr);
        if ( IS_ERR(agent_channel) )
        {
            printk(XENLOG_ERR "scmi: Could not create channel for agent %u: %ld\n",
                   agent_id, PTR_ERR(agent_channel));
            return PTR_ERR(agent_channel);
        }

        if ( cells_per_entry == 2 )
        {
            ret = collect_agent_id(agent_channel);
            if ( ret )
                return ret;
        }

        printk(XENLOG_DEBUG "scmi: Agent %u SMC %X addr %lx\n", agent_channel->agent_id,
               smc_id, (unsigned long)addr);
    }

    return 0;
}

static int scmi_domain_init(struct domain *d,
                            struct xen_domctl_createdomain *config)
{
    struct scmi_channel *channel;
    int ret;

    if ( !scmi_data.initialized )
        return 0;

    /*
     * Special case for Dom0 - the SCMI support is enabled basing on
     * "dom0_sci_agent_id" Xen command line parameter
     */
    if ( is_hardware_domain(d) )
    {
        if ( opt_dom0_scmi_agent_id != SCMI_AGENT_ID_INVALID )
        {
            config->arch.arm_sci_type = XEN_DOMCTL_CONFIG_ARM_SCI_SCMI_SMC_MA;
            config->arch.arm_sci_agent_id = opt_dom0_scmi_agent_id;
        }
        else
            config->arch.arm_sci_type = XEN_DOMCTL_CONFIG_ARM_SCI_NONE;
    }

    if ( config->arch.arm_sci_type == XEN_DOMCTL_CONFIG_ARM_SCI_NONE )
        return 0;

    channel = acquire_scmi_channel(d, config->arch.arm_sci_agent_id);
    if ( IS_ERR(channel) )
    {
        printk(XENLOG_ERR
               "scmi: Failed to acquire SCMI channel for agent_id %u: %ld\n",
               config->arch.arm_sci_agent_id, PTR_ERR(channel));
        return PTR_ERR(channel);
    }

    printk(XENLOG_INFO
           "scmi: Acquire channel id = 0x%x, domain_id = %d paddr = 0x%lx\n",
           channel->agent_id, channel->domain_id, channel->paddr);

    /*
     * Dom0 (if present) needs to have an access to the guest memory range
     * to satisfy iomem_access_permitted() check in XEN_DOMCTL_iomem_permission
     * domctl.
     */
    if ( hardware_domain && !is_hardware_domain(d) )
    {
        ret = iomem_permit_access(hardware_domain, paddr_to_pfn(channel->paddr),
                                  paddr_to_pfn(channel->paddr + PAGE_SIZE - 1));
        if ( ret )
            goto error;
    }

    d->arch.sci_data = channel;
    d->arch.sci_enabled = true;

    return 0;

error:
    relinquish_scmi_channel(channel);
    return ret;
}

int scmi_domain_sanitise_config(struct xen_domctl_createdomain *config)
{
    if ( config->arch.arm_sci_type != XEN_DOMCTL_CONFIG_ARM_SCI_NONE &&
         config->arch.arm_sci_type != XEN_DOMCTL_CONFIG_ARM_SCI_SCMI_SMC_MA )
    {
        dprintk(XENLOG_INFO, "scmi: Unsupported ARM_SCI type\n");
        return -EINVAL;
    }
    else if ( config->arch.arm_sci_type ==
              XEN_DOMCTL_CONFIG_ARM_SCI_SCMI_SMC_MA &&
              config->arch.arm_sci_agent_id == 0 )
    {
        dprintk(XENLOG_INFO,
                "scmi: A zero ARM SCMI agent_id is not supported\n");
        return -EINVAL;
    }

    return 0;
}

static int scmi_relinquish_resources(struct domain *d)
{
    int ret;
    struct scmi_channel *channel, *agent_channel;
    scmi_msg_header_t hdr;
    struct scmi_msg_base_reset_agent_cfg_a2p tx;

    if ( !d->arch.sci_data )
        return 0;

    agent_channel = d->arch.sci_data;

    spin_lock(&agent_channel->lock);
    tx.agent_id = agent_channel->agent_id;
    spin_unlock(&agent_channel->lock);

    channel = get_channel_by_id(scmi_data.hyp_channel_agent_id);
    if ( !channel )
    {
        printk(XENLOG_ERR
               "scmi: Unable to get Hypervisor scmi channel for domain %d\n",
               d->domain_id);
        return -EINVAL;
    }

    hdr.id = SCMI_BASE_RESET_AGENT_CONFIGURATION;
    hdr.type = 0;
    hdr.protocol = SCMI_BASE_PROTOCOL;

    tx.flags = 0;

    ret = do_smc_xfer(channel, &hdr, &tx, sizeof(tx), NULL, 0);
    if ( ret == -EOPNOTSUPP )
        return 0;

    return ret;
}

static void scmi_domain_destroy(struct domain *d)
{
    struct scmi_channel *channel;

    if ( !d->arch.sci_data )
        return;

    channel = d->arch.sci_data;
    spin_lock(&channel->lock);

    relinquish_scmi_channel(channel);
    printk(XENLOG_DEBUG "scmi: Free domain %d\n", d->domain_id);

    d->arch.sci_data = NULL;
    d->arch.sci_enabled = true;

    spin_unlock(&channel->lock);
}

static bool scmi_handle_call(struct cpu_user_regs *regs)
{
    uint32_t fid = (uint32_t)get_user_reg(regs, 0);
    struct scmi_channel *agent_channel;
    struct domain *d = current->domain;
    struct arm_smccc_res resp;
    bool res = false;

    if ( !sci_domain_is_enabled(d) )
        return false;

    agent_channel = d->arch.sci_data;
    spin_lock(&agent_channel->lock);

    if ( agent_channel->func_id != fid )
    {
        res = false;
        goto unlock;
    }

    arm_smccc_1_1_smc(fid,
                      get_user_reg(regs, 1),
                      get_user_reg(regs, 2),
                      get_user_reg(regs, 3),
                      get_user_reg(regs, 4),
                      get_user_reg(regs, 5),
                      get_user_reg(regs, 6),
                      get_user_reg(regs, 7),
                      &resp);

    set_user_reg(regs, 0, resp.a0);
    set_user_reg(regs, 1, resp.a1);
    set_user_reg(regs, 2, resp.a2);
    set_user_reg(regs, 3, resp.a3);
    res = true;
unlock:
    spin_unlock(&agent_channel->lock);

    return res;
}

static const struct sci_mediator_ops scmi_ops = {
    .domain_init = scmi_domain_init,
    .domain_destroy = scmi_domain_destroy,
    .relinquish_resources = scmi_relinquish_resources,
    .handle_call = scmi_handle_call,
    .dom0_dt_handle_node = scmi_dt_handle_node,
    .domain_sanitise_config = scmi_domain_sanitise_config,
    .assign_dt_device = scmi_dt_assign_device,
};

static int __init scmi_check_smccc_ver(void)
{
    if ( smccc_ver < ARM_SMCCC_VERSION_1_1 )
    {
        printk(XENLOG_WARNING
               "scmi: No SMCCC 1.1 support, SCMI calls forwarding disabled\n");
        return -ENOSYS;
    }

    return 0;
}

static int scmi_dt_hyp_channel_read(struct dt_device_node *scmi_node, struct scmi_data *scmi_data,
                                    u64 *addr)
{
    int ret;
    u64 size;

    if ( !dt_property_read_u32(scmi_node, "arm,smc-id", &scmi_data->func_id) )
    {
        printk(XENLOG_ERR "scmi: unable to read smc-id from DT\n");
        return -ENOENT;
    }

    ret = scmi_dt_read_hyp_channel_addr(scmi_node, addr, &size);
    if ( IS_ERR_VALUE(ret) )
        return -ENOENT;

    if ( !IS_ALIGNED(size, SCMI_SHMEM_MAPPED_SIZE) )
    {
        printk(XENLOG_ERR "scmi: shmem memory is not aligned\n");
        return -EINVAL;
    }

    return 0;
}

static __init int scmi_probe(struct dt_device_node *scmi_node, const void *data)
{
    u64 addr;
    int ret;
    struct scmi_channel *channel;
    int n_agents;
    scmi_msg_header_t hdr;
    struct scmi_msg_base_attributes_p2a rx;

    ASSERT(scmi_node != NULL);

    INIT_LIST_HEAD(&scmi_data.channel_list);
    spin_lock_init(&scmi_data.channel_list_lock);

    if ( !acpi_disabled )
    {
        printk(XENLOG_WARNING "scmi: is not supported when using ACPI\n");
        return -EINVAL;
    }

    ret = scmi_check_smccc_ver();
    if ( ret )
        return ret;

    ret = scmi_dt_hyp_channel_read(scmi_node, &scmi_data, &addr);
    if ( ret )
        return ret;

    scmi_data.dt_dev = scmi_node;

    channel = smc_create_channel(SCMI_BASE_AGENT_ID_OWN, scmi_data.func_id, addr);
    if ( IS_ERR(channel) )
        goto out;

    /* Request agent id for Xen management channel  */
    ret = collect_agent_id(channel);
    if ( ret )
        return ret;

    /* Save the agent id for Xen management channel */
    scmi_data.hyp_channel_agent_id = channel->agent_id;

    ret = map_channel_memory(channel);
    if ( ret )
        goto out;

    channel->domain_id = DOMID_XEN;

    hdr.id = SCMI_BASE_PROTOCOL_ATTIBUTES;
    hdr.type = 0;
    hdr.protocol = SCMI_BASE_PROTOCOL;

    ret = do_smc_xfer(channel, &hdr, NULL, 0, &rx, sizeof(rx));
    if ( ret )
        goto error;

    n_agents = SCMI_FIELD_GET(SCMI_BASE_ATTR_NUM_AGENT, rx.attributes);
    printk(XENLOG_DEBUG "scmi: Got agent count %d\n", n_agents);
    ret = collect_agents(scmi_node);
    if ( ret )
        goto error;

    ret = sci_register(&scmi_ops);
    if ( ret )
    {
        printk(XENLOG_ERR "SCMI: mediator already registered (ret = %d)\n",
               ret);
        return ret;
    }

    scmi_data.initialized = true;
    goto out;

error:
    unmap_channel_memory(channel);
    free_channel_list();
out:
    return ret;
}

static const struct dt_device_match scmi_smc_match[] __initconst = {
    DT_MATCH_PATH("/chosen/xen,config/scmi"),
    { /* sentinel */ },
};

DT_DEVICE_START(scmi_smc_ma, "SCMI SMC MEDIATOR", DEVICE_FIRMWARE)
        .dt_match = scmi_smc_match,
        .init = scmi_probe,
DT_DEVICE_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
