// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/internal/syscall/device.h>
#include <openenclave/internal/syscall/fcntl.h>
#include <openenclave/internal/syscall/fdtable.h>
#include <openenclave/internal/syscall/raise.h>
#include <openenclave/internal/syscall/unistd.h>
#include <openenclave/internal/trace.h>
#include "mount.h"
#include "syscall_t.h"

int __oe_fcntl(int fd, int cmd, uint64_t arg)
{
    int ret = -1;
    oe_fd_t* desc;

    if (cmd == OE_F_DUPFD)
    {
        return oe_dup(fd);
    }

    if (!(desc = oe_fdtable_get(fd, OE_FD_TYPE_ANY)))
        OE_RAISE_ERRNO(oe_errno);

    ret = desc->ops.fd.fcntl(desc, cmd, arg);

done:
    return ret;
}

int oe_open(const char* pathname, int flags, oe_mode_t mode)
{
    int ret = -1;
    int fd;
    oe_device_t* fs;
    oe_fd_t* file = NULL;
    char filepath[OE_PATH_MAX] = {0};

    if (!(fs = oe_mount_resolve(pathname, filepath)))
        OE_RAISE_ERRNO(oe_errno);

    if (!(file = fs->ops.fs.open(fs, filepath, flags, mode)))
        OE_RAISE_ERRNO_MSG(oe_errno, "pathname=%s", pathname);

    if ((fd = oe_fdtable_assign(file)) == -1)
        OE_RAISE_ERRNO(oe_errno);

    ret = fd;
    file = NULL;

done:

    if (file)
        file->ops.fd.close(file);

    return ret;
}

int oe_open_d(uint64_t devid, const char* pathname, int flags, oe_mode_t mode)
{
    int ret = -1;
    int fd;
    oe_fd_t* file = NULL;

    if (devid == OE_DEVID_NONE)
    {
        fd = oe_open(pathname, flags, mode);
    }
    else
    {
        oe_device_t* dev =
            oe_device_table_get(devid, OE_DEVICE_TYPE_FILE_SYSTEM);

        if (!dev)
            OE_RAISE_ERRNO(OE_EINVAL);

        if (!(file = dev->ops.fs.open(dev, pathname, flags, mode)))
            OE_RAISE_ERRNO_MSG(oe_errno, "pathname=%s mode=%u", pathname, mode);

        if ((fd = oe_fdtable_assign(file)) == -1)
            OE_RAISE_ERRNO(oe_errno);
    }

    ret = fd;
    file = NULL;

done:

    if (file)
        file->ops.fd.close(file);

    return ret;
}
