#include <bits/stdint-uintn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <xengnttab.h>
#include <xenctrl.h>
#include <fcntl.h>
#include <sys/ioctl.h>
struct drm_mode_destroy_dumb {
	uint32_t handle;
};

/* create a dumb scanout buffer */
struct drm_mode_create_dumb {
	uint32_t height;
	uint32_t width;
	uint32_t bpp;
	uint32_t flags;
	/* handle, pitch, size will be returned */
	uint32_t handle;
	uint32_t pitch;
	uint64_t size;
};

#define DRM_RDWR O_RDWR
#define DRM_CLOEXEC O_CLOEXEC
struct drm_prime_handle {
	uint32_t handle;

	/** Flags.. only applicable for handle->fd */
	uint32_t flags;

	/** Returned dmabuf file descriptor */
	int32_t fd;
};

#define CREATE_DMABUF _IOR('a', 'a', uint32_t*)
#define DESTROY_DMABUF _IO('a', 'b')
#define DRM_IOCTL_MODE_CREATE_DUMB _IOWR('d', 0xB2, struct drm_mode_create_dumb)
#define DRM_IOCTL_PRIME_HANDLE_TO_FD _IOWR('d', 0x2d, struct drm_prime_handle)
#define DRM_IOCTL_MODE_DESTROY_DUMB _IOWR('d', 0xB4, struct drm_mode_destroy_dumb)
#define CHRET(ret) \
    do { \
        printf("%d ret = %d\n", __LINE__, ret); \
        if (ret) {\
            printf("%d ret = %d\n", __LINE__, ret); \
            goto close; \
        } \
    } while(0);

int main(int argc, char **argv)
{
    int i, ret = 0;
    xengnttab_handle *xgt;
    uint32_t *refs;
    uint32_t fd;
    int chfd;
    uint32_t domid;
    struct drm_mode_create_dumb creq;
    struct drm_mode_destroy_dumb dreq;
    struct drm_prime_handle prime;

    printf("argc %d\n", argc);
    if (argc < 3)
        return -EINVAL;

    domid = atoi(argv[1]);
    printf("domid = %d\n", domid);

    refs = malloc(sizeof(uint32_t) * (argc - 2));
    for (i = 2; i < argc; i++)
    {
        refs[i - 2] = atoi(argv[i]);
        printf("g %d\n", refs[i - 2]);
    }

    xgt = xengnttab_open(NULL, 0);
    if (!xgt) {
        ret = -ENOMEM;
        goto err;
    }

    chfd = open("/dev/dri/card0", 0);
    if (!chfd)
        goto err;

    creq.width = 100;
    creq.height =550;
    creq.bpp = 32;
    ret = ioctl(chfd, DRM_IOCTL_MODE_CREATE_DUMB, &creq);
//    ret = ioctl(chfd, CREATE_DMABUF, (uint32_t *) &fd);
    CHRET(ret);

    printf("handle = %d\n", creq.handle);
    prime.handle = creq.handle;

    ret = ioctl(chfd, DRM_IOCTL_PRIME_HANDLE_TO_FD, &prime);
    CHRET(ret);

    fd = prime.fd;
    printf("fd = %d\n", fd);

    ret = xengnttab_dmabuf_map_refs_to_buf(xgt, domid, 0, argc - 2,
            refs, fd, 0);
    CHRET(ret);

    ret = xengnttab_dmabuf_map_release(xgt, fd);
    CHRET(ret);

    close(fd);
    dreq.handle = creq.handle;
    ret = ioctl(chfd, DRM_IOCTL_MODE_DESTROY_DUMB, &dreq);
    CHRET(ret);

    ret = xengnttab_dmabuf_map_wait_released(xgt, fd, 1000);
    CHRET(ret);

    ret = xengnttab_close(xgt);
    CHRET(ret);
close:
    close(chfd);
err:
    free(refs);
    return ret;
};
