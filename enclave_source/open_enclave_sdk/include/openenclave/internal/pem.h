// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_PEM_H
#define _OE_PEM_H

#include <openenclave/bits/defs.h>

OE_EXTERNC_BEGIN

/* Upper bound used for assertions over constant lengths */
#define OE_PEM_MAX_LEN 255

#define OE_PEM_BEGIN_CERTIFICATE "-----BEGIN CERTIFICATE-----"
#define OE_PEM_BEGIN_CERTIFICATE_LEN (sizeof(OE_PEM_BEGIN_CERTIFICATE) - 1)
#define OE_PEM_END_CERTIFICATE "-----END CERTIFICATE-----"
#define OE_PEM_END_CERTIFICATE_LEN (sizeof(OE_PEM_END_CERTIFICATE) - 1)

#define OE_PEM_BEGIN_PUBLIC_KEY "-----BEGIN PUBLIC KEY-----"
#define OE_PEM_BEGIN_PUBLIC_KEY_LEN (sizeof(OE_PEM_BEGIN_PUBLIC_KEY) - 1)
#define OE_PEM_END_PUBLIC_KEY "-----END PUBLIC KEY-----"
#define OE_PEM_END_PUBLIC_KEY_LEN (sizeof(OE_PEM_END_PUBLIC_KEY) - 1)

#define OE_PEM_BEGIN_PRIVATE_KEY "-----BEGIN PRIVATE KEY-----"
#define OE_PEM_BEGIN_PRIVATE_KEY_LEN (sizeof(OE_PEM_BEGIN_PRIVATE_KEY) - 1)
#define OE_PEM_END_PRIVATE_KEY "-----END PRIVATE KEY-----"
#define OE_PEM_END_PRIVATE_KEY_LEN (sizeof(OE_PEM_END_PRIVATE_KEY) - 1)

#define OE_PEM_BEGIN_RSA_PRIVATE_KEY "-----BEGIN RSA PRIVATE KEY-----"
#define OE_PEM_BEGIN_RSA_PRIVATE_KEY_LEN \
    (sizeof(OE_PEM_BEGIN_RSA_PRIVATE_KEY) - 1)
#define OE_PEM_END_RSA_PRIVATE_KEY "-----END RSA PRIVATE KEY-----"
#define OE_PEM_END_RSA_PRIVATE_KEY_LEN (sizeof(OE_PEM_END_RSA_PRIVATE_KEY) - 1)

#define OE_PEM_BEGIN_EC_PRIVATE_KEY "-----BEGIN EC PRIVATE KEY-----"
#define OE_PEM_BEGIN_EC_PRIVATE_KEY_LEN \
    (sizeof(OE_PEM_BEGIN_EC_PRIVATE_KEY) - 1)
#define OE_PEM_END_EC_PRIVATE_KEY "-----END EC PRIVATE KEY-----"
#define OE_PEM_END_EC_PRIVATE_KEY_LEN (sizeof(OE_PEM_END_EC_PRIVATE_KEY) - 1)

OE_EXTERNC_END

#endif /* _OE_PEM_H */
