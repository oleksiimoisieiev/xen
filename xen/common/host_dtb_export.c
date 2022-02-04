/*
 * xen/arch/arm/host_dtb_export.c
 *
 * Export host device-tree to the hypfs so toolstack can access
 * host device-tree from Dom0
 *
 * Oleksii Moisieiev <oleksii_moisieiev@epam.com>
 * Copyright (C) 2021, EPAM Systems.
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

#include <xen/device_tree.h>
#include <xen/err.h>
#include <xen/guest_access.h>
#include <xen/hypfs.h>
#include <xen/init.h>

#define HOST_DT_DIR "devicetree"
#define HYPFS_PROPERTY_MAX_SIZE 256

static HYPFS_DIR_INIT_FUNC(dt_dir, "node_template", NULL);
static HYPFS_VARSIZE_INIT(dt_prop, XEN_HYPFS_TYPE_BLOB, "prop_template",
                            HYPFS_PROPERTY_MAX_SIZE, NULL);

static const char *get_name_from_path(const char *path)
{
    const char *name = strrchr(path, '/');
    if ( !name )
        name = path;
    else
    {
        name++;
        if ( !*name )
            name--;
    }

    return name;
}

static char *get_root_from_path(const char *path, char *name, int sz)
{
    const char *nm = strchr(path, '/');
    if ( !nm )
        nm = path + strlen(path);
    else
    {
        if ( !*nm )
            nm--;
    }

    return memcpy(name, path, (nm - path > sz) ? sz: nm - path);
}

static int host_dt_dir_read(const struct hypfs_entry *entry,
                            XEN_GUEST_HANDLE_PARAM(void) uaddr)
{
    int ret = 0;
    const struct dt_device_node *node;
    const struct dt_device_node *child;
    const struct dt_property *prop;
    struct hypfs_dyndir *data;

    data = hypfs_get_dyndata();
    if ( !data )
        return -EINVAL;

    node = data->content;
    if ( !node )
        return -EINVAL;

    dt_for_each_property_node( node, prop )
    {
        ret = hypfs_read_dyndir_entry(&dt_prop.e, prop->name,
                                      strlen(prop->name),
                                      !prop->next && !node->child,
                                      &uaddr);

        if ( ret )
            break;
    }

    for ( child = node->child; child != NULL; child = child->sibling )
    {
        const char *parsed_name = get_name_from_path(child->full_name);
        data->content = child;

        ret = hypfs_read_dyndir_entry(&dt_dir.e, parsed_name,
                                         strlen(parsed_name),
                                         child->sibling == NULL,
                                         &uaddr);

        if ( ret )
            break;
    }

    return ret;
}

static unsigned int host_dt_dir_getsize(const struct hypfs_entry *entry)
{
    const struct dt_device_node *node;
    const struct dt_device_node *child;
    struct hypfs_dyndir *data;
    const struct dt_property *prop;
    unsigned int size = 0;

    data = hypfs_get_dyndata();
    if ( !data )
        return -EINVAL;

    node = data->content;
    if ( !node )
        return -EINVAL;

    dt_for_each_property_node( node, prop )
    {
        size += hypfs_dyndir_entry_size(entry, prop->name);
    }

    for ( child = node->child; child != NULL; child = child->sibling )
    {
        const char *parsed_name = get_name_from_path(child->full_name);
        size += hypfs_dyndir_entry_size(entry, parsed_name);
    }

    return size;
}

static DEFINE_PER_CPU(bool, data_alloc);

static inline bool data_is_alloc(void)
{
    unsigned int cpu = smp_processor_id();
    return per_cpu(data_alloc, cpu);
}

static inline void set_data_alloc(void)
{
    unsigned int cpu = smp_processor_id();
    ASSERT(!per_cpu(data_alloc, cpu));

    this_cpu(data_alloc) = true;
}

static inline void unset_data_alloc(void)
{
    this_cpu(data_alloc) = false;
}

static const struct hypfs_entry *host_dt_dir_enter(
    const struct hypfs_entry *entry)
{
    struct hypfs_dyndir *data;

    if ( !data_is_alloc() )
    {
        data = hypfs_alloc_dyndata(struct hypfs_dyndir);
        if ( !data )
            return ERR_PTR(-ENOMEM);

        set_data_alloc();
    }

    if ( strcmp(entry->name, HOST_DT_DIR) == 0 )
    {
        data = hypfs_get_dyndata();
        data->content = dt_host;
    }

    return entry;
}

static void host_dt_dir_exit(const struct hypfs_entry *entry)
{
    if ( !data_is_alloc() )
        return;

    hypfs_free_dyndata();
    unset_data_alloc();
}

static struct hypfs_entry *host_dt_dir_findentry(
    const struct hypfs_entry_dir *dir, const char *name, unsigned int name_len)
{
    const struct dt_device_node *node;
    char root_name[HYPFS_DYNDIR_ID_NAMELEN];
    struct dt_device_node *child;
    struct hypfs_dyndir *data;
    struct dt_property *prop;

    data = hypfs_get_dyndata();
    if ( !data )
        return ERR_PTR(-EINVAL);

    node = data->content;
    if ( !node )
        return ERR_PTR(-EINVAL);

    memset(root_name, 0, sizeof(root_name));
    get_root_from_path(name, root_name, HYPFS_DYNDIR_ID_NAMELEN);

    for ( child = node->child; child != NULL; child = child->sibling )
    {
        if ( strcmp(get_name_from_path(child->full_name), root_name) == 0 )
            return hypfs_gen_dyndir_entry(&dt_dir.e,
                                  get_name_from_path(child->full_name), child);
    }

    dt_for_each_property_node( node, prop )
    {

        if ( dt_property_name_is_equal(prop, root_name) )
            return hypfs_gen_dyndir_entry(&dt_prop.e, prop->name, prop);
    }

    return ERR_PTR(-ENOENT);
};

static int host_dt_prop_read(const struct hypfs_entry *entry,
                    XEN_GUEST_HANDLE_PARAM(void) uaddr)
{
    const struct dt_property *prop;
    struct hypfs_dyndir *data;

    data = hypfs_get_dyndata();
    if ( !data )
        return -EINVAL;

    prop = data->content;
    if ( !prop )
        return -EINVAL;

    return copy_to_guest(uaddr, prop->value, prop->length) ?  -EFAULT : 0;
}

static unsigned int host_dt_prop_getsize(const struct hypfs_entry *entry)
{
    const struct hypfs_dyndir *data;
    const struct dt_property *prop;

    data = hypfs_get_dyndata();
    if ( !data )
        return -EINVAL;

    prop = data->content;
    if ( !prop )
        return -EINVAL;

    return prop->length;
}

static const struct hypfs_funcs host_dt_dir_funcs = {
    .enter = host_dt_dir_enter,
    .exit = host_dt_dir_exit,
    .read = host_dt_dir_read,
    .write = hypfs_write_deny,
    .getsize = host_dt_dir_getsize,
    .findentry = host_dt_dir_findentry,
};

const struct hypfs_funcs host_dt_prop_ro_funcs = {
    .enter = host_dt_dir_enter,
    .exit = host_dt_dir_exit,
    .read = host_dt_prop_read,
    .write = hypfs_write_deny,
    .getsize = host_dt_prop_getsize,
    .findentry = hypfs_leaf_findentry,
};

static HYPFS_DIR_INIT_FUNC(host_dt_dir, HOST_DT_DIR, &host_dt_dir_funcs);

static int __init host_dtb_export_init(void)
{
    if ( !dt_host )
        return -ENODEV;

    dt_dir.e.funcs = &host_dt_dir_funcs;
    dt_prop.e.funcs = &host_dt_prop_ro_funcs;

    unset_data_alloc();

    hypfs_add_dir(&hypfs_root, &host_dt_dir, true);
    hypfs_add_dyndir(&hypfs_root, &dt_dir);
    return 0;
}
__initcall(host_dtb_export_init);
