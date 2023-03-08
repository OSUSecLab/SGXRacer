// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_RESOLVER_H
#define _OE_SYSCALL_RESOLVER_H

#include <openenclave/bits/types.h>
#include <openenclave/corelibc/errno.h>
#include <openenclave/internal/syscall/netdb.h>

OE_EXTERNC_BEGIN

typedef struct _oe_resolver oe_resolver_t;

typedef enum _oe_resolver_type
{
    OE_RESOLVER_TYPE_NONE = 0,
    OE_RESOLVER_TYPE_HOST = 1,
} oe_resolver_type_t;

typedef struct _oe_resolver_ops
{
    int (*getaddrinfo)(
        oe_resolver_t* resolver,
        const char* node,
        const char* service,
        const struct oe_addrinfo* hints,
        struct oe_addrinfo** res);

    int (*getnameinfo)(
        oe_resolver_t* resolver,
        const struct oe_sockaddr* sa,
        oe_socklen_t salen,
        char* host,
        oe_socklen_t hostlen,
        char* serv,
        oe_socklen_t servlen,
        int flags);

    int (*release)(oe_resolver_t* resolver);

} oe_resolver_ops_t;

typedef struct _oe_resolver
{
    oe_resolver_type_t type;
    oe_resolver_ops_t* ops;
} oe_resolver_t;

int oe_register_resolver(oe_resolver_t* resolver);

OE_EXTERNC_END

#endif /* _OE_SYSCALL_RESOLVER_H */
