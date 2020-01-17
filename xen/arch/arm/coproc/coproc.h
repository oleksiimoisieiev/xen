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
    const struct vcoproc_ops *ops;
};

/* coproc callback functions */
struct vcoproc_ops {
    /* callback to perform initialization for the vcoproc instance */
    struct vcoproc_instance *(*vcoproc_init)(struct domain *,
                                             struct coproc_device *);
    /* callback to perform deinitialization for the vcoproc instance */
    void (*vcoproc_deinit)(struct domain *, struct vcoproc_instance *);
    /*
     * callback to check if the vcoproc instance
     * has been already created for this domain
     */
    bool_t (*vcoproc_is_created)(struct domain *, struct coproc_device *);
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
     */
    struct list_head instance_elem;
};

void coproc_init(void);
int coproc_register(struct coproc_device *);
int coproc_do_domctl(struct xen_domctl *, struct domain *,
                     XEN_GUEST_HANDLE_PARAM(xen_domctl_t));
bool_t coproc_is_attached_to_domain(struct domain *, const char *);
int coproc_release_vcoprocs(struct domain *);

int vcoproc_domain_init(struct domain *);
void vcoproc_domain_free(struct domain *);

#define dev_path(dev) dt_node_full_name(dev_to_dt(dev))

#endif /* __ARCH_ARM_COPROC_COPROC_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
