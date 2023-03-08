// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_SYS_POLL_H
#define _OE_SYSCALL_SYS_POLL_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

// clang-format off
#define OE_POLLIN     0x001
#define OE_POLLPRI    0x002
#define OE_POLLOUT    0x004
#define OE_POLLRDNORM 0x040
#define OE_POLLRDBAND 0x080
#define OE_POLLWRNORM 0x100
#define OE_POLLWRBAND 0x200
#define OE_POLLMSG    0x400
#define OE_POLLRDHUP  0x2000
#define OE_POLLERR    0x008
#define OE_POLLHUP    0x010
#define OE_POLLNVAL   0x020
// clang-format on

typedef uint64_t oe_nfds_t;

struct oe_pollfd
{
    int fd;            /* File descriptor to poll.  */
    short int events;  /* Types of events poller cares about.  */
    short int revents; /* Types of events that actually occurred.  */
};

int oe_poll(struct oe_pollfd* fds, oe_nfds_t nfds, int timeout);

OE_EXTERNC_END

#endif /* _OE_SYSCALL_SYS_POLL_H */
