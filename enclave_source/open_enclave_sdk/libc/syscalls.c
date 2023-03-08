// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define __OE_NEED_TIME_CALLS
#define _GNU_SOURCE

#include <errno.h>
#include <openenclave/corelibc/errno.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/syscall.h>
#include <openenclave/internal/syscall/sys/stat.h>
#include <openenclave/internal/syscall/sys/syscall.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/time.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>

static oe_syscall_hook_t _hook;
static oe_spinlock_t _lock;

static const uint64_t _SEC_TO_MSEC = 1000UL;
static const uint64_t _MSEC_TO_USEC = 1000UL;
static const uint64_t _MSEC_TO_NSEC = 1000000UL;

static long _syscall_mmap(long n, ...)
{
    /* Always fail */
    OE_UNUSED(n);
    return EPERM;
}

static long _syscall_clock_gettime(long n, long x1, long x2)
{
    clockid_t clk_id = (clockid_t)x1;
    struct timespec* tp = (struct timespec*)x2;
    int ret = -1;
    uint64_t msec;

    OE_UNUSED(n);

    if (!tp)
        goto done;

    if (clk_id != CLOCK_REALTIME)
    {
        /* Only supporting CLOCK_REALTIME */
        oe_assert("clock_gettime(): panic" == NULL);
        goto done;
    }

    if ((msec = oe_get_time()) == (uint64_t)-1)
        goto done;

    tp->tv_sec = msec / _SEC_TO_MSEC;
    tp->tv_nsec = (msec % _SEC_TO_MSEC) * _MSEC_TO_NSEC;

    ret = 0;

done:

    return ret;
}

static long _syscall_gettimeofday(long n, long x1, long x2)
{
    struct timeval* tv = (struct timeval*)x1;
    void* tz = (void*)x2;
    int ret = -1;
    uint64_t msec;

    OE_UNUSED(n);

    if (tv)
        memset(tv, 0, sizeof(struct timeval));

    if (tz)
        memset(tz, 0, sizeof(struct timezone));

    if (!tv)
        goto done;

    if ((msec = oe_get_time()) == (uint64_t)-1)
        goto done;

    tv->tv_sec = msec / _SEC_TO_MSEC;
    tv->tv_usec = msec % _MSEC_TO_USEC;

    ret = 0;

done:
    return ret;
}

static long _syscall_nanosleep(long n, long x1, long x2)
{
    const struct timespec* req = (struct timespec*)x1;
    struct timespec* rem = (struct timespec*)x2;
    size_t ret = -1;
    uint64_t milliseconds = 0;

    OE_UNUSED(n);

    if (rem)
        memset(rem, 0, sizeof(*rem));

    if (!req)
        goto done;

    /* Convert timespec to milliseconds */
    milliseconds += req->tv_sec * 1000UL;
    milliseconds += req->tv_nsec / 1000000UL;

    /* Perform OCALL */
    ret = oe_sleep_msec(milliseconds);

done:

    return ret;
}

static void _stat_to_oe_stat(struct stat* stat, struct oe_stat* oe_stat)
{
    oe_stat->st_dev = stat->st_dev;
    oe_stat->st_ino = stat->st_ino;
    oe_stat->st_nlink = stat->st_nlink;
    oe_stat->st_mode = stat->st_mode;
    oe_stat->st_uid = stat->st_uid;
    oe_stat->st_gid = stat->st_gid;
    oe_stat->st_rdev = stat->st_rdev;
    oe_stat->st_size = stat->st_size;
    oe_stat->st_blksize = stat->st_blksize;
    oe_stat->st_blocks = stat->st_blocks;
    oe_stat->st_atim.tv_sec = stat->st_atim.tv_sec;
    oe_stat->st_atim.tv_nsec = stat->st_atim.tv_nsec;
    oe_stat->st_ctim.tv_sec = stat->st_ctim.tv_sec;
    oe_stat->st_ctim.tv_nsec = stat->st_ctim.tv_nsec;
    oe_stat->st_mtim.tv_sec = stat->st_mtim.tv_sec;
    oe_stat->st_mtim.tv_nsec = stat->st_mtim.tv_nsec;
}

static void _oe_stat_to_stat(struct oe_stat* oe_stat, struct stat* stat)
{
    stat->st_dev = oe_stat->st_dev;
    stat->st_ino = oe_stat->st_ino;
    stat->st_nlink = oe_stat->st_nlink;
    stat->st_mode = oe_stat->st_mode;
    stat->st_uid = oe_stat->st_uid;
    stat->st_gid = oe_stat->st_gid;
    stat->st_rdev = oe_stat->st_rdev;
    stat->st_size = oe_stat->st_size;
    stat->st_blksize = oe_stat->st_blksize;
    stat->st_blocks = oe_stat->st_blocks;
    stat->st_atim.tv_sec = oe_stat->st_atim.tv_sec;
    stat->st_atim.tv_nsec = oe_stat->st_atim.tv_nsec;
    stat->st_ctim.tv_sec = oe_stat->st_ctim.tv_sec;
    stat->st_ctim.tv_nsec = oe_stat->st_ctim.tv_nsec;
    stat->st_mtim.tv_sec = oe_stat->st_mtim.tv_sec;
    stat->st_mtim.tv_nsec = oe_stat->st_mtim.tv_nsec;
}

static long _dispatch_oe_syscall(
    long n,
    long x1,
    long x2,
    long x3,
    long x4,
    long x5,
    long x6)
{
    long ret;

    switch (n)
    {
#if defined(SYS_stat)
        case SYS_stat:
        {
            struct stat* stat = (struct stat*)x2;
            struct oe_stat oe_stat;

            _stat_to_oe_stat(stat, &oe_stat);
            x2 = (long)&oe_stat;
            ret = oe_syscall(OE_SYS_stat, x1, x2, x3, x4, x5, x6);
            _oe_stat_to_stat(&oe_stat, stat);

            break;
        }
#endif
        case SYS_newfstatat:
        {
            struct stat* stat = (struct stat*)x3;
            struct oe_stat oe_stat;

            _stat_to_oe_stat(stat, &oe_stat);
            x3 = (long)&oe_stat;
            ret = oe_syscall(OE_SYS_newfstatat, x1, x2, x3, x4, x5, x6);
            _oe_stat_to_stat(&oe_stat, stat);

            break;
        }
        default:
        {
            ret = oe_syscall(n, x1, x2, x3, x4, x5, x6);
            break;
        }
    }

    return ret;
}

/* Intercept __syscalls() from MUSL */
long __syscall(long n, long x1, long x2, long x3, long x4, long x5, long x6)
{
    oe_spin_lock(&_lock);
    oe_syscall_hook_t hook = _hook;
    oe_spin_unlock(&_lock);

    /* Invoke the syscall hook if any */
    if (hook)
    {
        long ret = -1;

        if (hook(n, x1, x2, x3, x4, x5, x6, &ret) == OE_OK)
        {
            /* The hook handled the syscall */
            return ret;
        }

        /* The hook ignored the syscall so fall through */
    }

    /* Let liboesyscall handle select system calls. */
    {
        long ret;

        errno = 0;

        ret = _dispatch_oe_syscall(n, x1, x2, x3, x4, x5, x6);

        if (!(ret == -1 && errno == ENOSYS))
        {
            return ret;
        }

        /* Drop through and let the code below handle the syscall. */
        errno = 0;
    }

    switch (n)
    {
        case SYS_nanosleep:
            return _syscall_nanosleep(n, x1, x2);
        case SYS_gettimeofday:
            return _syscall_gettimeofday(n, x1, x2);
        case SYS_clock_gettime:
            return _syscall_clock_gettime(n, x1, x2);
        case SYS_mmap:
            return _syscall_mmap(n, x1, x2, x3, x4, x5, x6);
        default:
        {
            /* All other MUSL-initiated syscalls are aborted. */
            fprintf(stderr, "error: __syscall(): n=%lu\n", n);
            abort();
            return 0;
        }
    }

    return 0;
}

/* Intercept __syscalls_cp() from MUSL */
long __syscall_cp(long n, long x1, long x2, long x3, long x4, long x5, long x6)
{
    return __syscall(n, x1, x2, x3, x4, x5, x6);
}

long syscall(long number, ...)
{
    va_list ap;

    va_start(ap, number);
    long x1 = va_arg(ap, long);
    long x2 = va_arg(ap, long);
    long x3 = va_arg(ap, long);
    long x4 = va_arg(ap, long);
    long x5 = va_arg(ap, long);
    long x6 = va_arg(ap, long);
    long ret = __syscall(number, x1, x2, x3, x4, x5, x6);
    va_end(ap);

    return ret;
}

long __syscall_ret(unsigned long r)
{
    /* Override MUSL __syscall_ret (maps certain return values to errnos). */
    return r;
}

void oe_register_syscall_hook(oe_syscall_hook_t hook)
{
    oe_spin_lock(&_lock);
    _hook = hook;
    oe_spin_unlock(&_lock);
}
