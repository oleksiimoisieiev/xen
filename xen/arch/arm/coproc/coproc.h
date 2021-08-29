/*
 * xen/arch/arm/coproc/coproc.h
 *
 * Generic Remote processors framework
 *
 * Oleksandr Tyshchenko <Oleksandr_Tyshchenko@epam.com>
 * Copyright (C) 2016 EPAM Systems Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __ARCH_ARM_COPROC_COPROC_H__
#define __ARCH_ARM_COPROC_COPROC_H__

#include <xen/types.h>
#include <xen/list.h>
#include <xen/spinlock.h>
#include <xen/sched.h>
#include <xen/device_tree.h>
#include <public/domctl.h>

/* coproc memory range */
struct mmio {
    u64 addr;
    u64 size;
    /* ioremapped addr */
    void __iomem *base;

    struct coproc_device *coproc;
};

/* coproc device that represents the real remote processor */
struct coproc_device {
    struct device *dev;

    /* the number of memory ranges for this coproc */
    u32 num_mmios;
    /* the array of memory ranges for this coproc */
    struct mmio *mmios;
    /* the number of irqs for this coproc */
    u32 num_irqs;
    /* the array of irqs for this coproc */
    unsigned int *irqs;

    /*
     * this list is used to append this coproc
     * to the "framework's" global coprocs list
     */
    struct list_head coproc_elem;
    /* to protect the vcoprocs list */
    spinlock_t vcoprocs_lock;
    /*
     * this list is used to keep track of all vcoproc instances that
     * have been created from this coproc
     */
    struct list_head vcoprocs;

    /* coproc callback functions */
    const struct coproc_ops *ops;

    /* coproc implementation specific data */
    void *priv;
};

/* per-domain vcoproc instance */
struct vcoproc_instance {
    struct coproc_device *coproc;
    struct domain *domain;
    spinlock_t lock;

    /*
     * this list is used to append this vcoproc
     * to the "coproc's" vcoprocs list
     */
    struct list_head vcoproc_elem;
    /*
     * this list is used to append this vcoproc
     * to the "domain's" instances list
     * must not be touched by any of vcoprocs
     */
    struct list_head instance_elem;

    /* vcoproc implementation specific data */
    void *priv;
};

/* coproc callback functions */
struct coproc_ops {
    /* callback to perform initialization for the vcoproc instance */
    int (*vcoproc_init)(struct vcoproc_instance *, const char *cfg);
    /* callback to perform deinitialization for the vcoproc instance */
    void (*vcoproc_deinit)(struct vcoproc_instance *);
    /* callback to control MMIO range mapping: check if MMIO range needs to
     * be mapped to the domain given (range_addr and range_size define
     * the MMIO range):
     *  - if not, then return false
     *  - if yes, then return true and set map_addr and map_size
     *    to the range required. If multiple subranges are required to
     *    be mapped, then return the first one in the range, so the framework
     *    calls us again with updated range_addr and range_size
     */
    bool_t (*need_map_range_to_domain)(struct vcoproc_instance *,
                                       u64, u64, u64 *, u64 *);
};

/* vcoproc read/write operation context */
struct vcoproc_rw_context {
    struct coproc_device *coproc;
    struct hsr_dabt dabt;
    uint32_t offset;
    struct vcoproc_instance *vcoproc;
};

bool_t coproc_is_coproc_irq(unsigned int);
void coproc_init(void);
struct coproc_device * coproc_alloc(struct dt_device_node *,
                                    const struct coproc_ops *);
int coproc_register(struct coproc_device *);
void coproc_release(struct coproc_device *);
void *coproc_map_offset(struct coproc_device *, u32 , u64 , u64 );
void coproc_unmap(void *va);
struct vcoproc_instance *coproc_get_vcoproc(struct domain *,
                                            struct coproc_device *);
int coproc_do_domctl(struct xen_domctl *, struct domain *,
                     XEN_GUEST_HANDLE_PARAM(xen_domctl_t));
bool_t coproc_is_attached_to_domain(struct domain *, const char *);
bool_t coproc_need_map_range_to_domain(struct domain *, const char *,
                                       u64 , u64, u64 *, u64 *);
int coproc_release_vcoprocs(struct domain *);

int vcoproc_domain_init(struct domain *);
void vcoproc_domain_free(struct domain *);

#define dev_path(dev) dt_node_full_name(dev_to_dt(dev))

static inline void vcoproc_get_rw_context(struct domain *d, struct mmio *mmio,
                                          mmio_info_t *info,
                                          struct vcoproc_rw_context *ctx)
{
    ctx->coproc = mmio->coproc;
    ctx->dabt = info->dabt;
    ctx->offset = info->gpa - mmio->addr;
    ctx->vcoproc = coproc_get_vcoproc(d, ctx->coproc);
    BUG_ON(ctx->vcoproc == NULL);
}

#endif /* __ARCH_ARM_COPROC_COPROC_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
