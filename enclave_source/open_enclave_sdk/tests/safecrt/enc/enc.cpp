// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/properties.h>
#include <openenclave/enclave.h>

#include "../common/test.h"
#include "safecrt_t.h"

void enc_test_memcpy_s()
{
    test_memcpy_s();
}

void enc_test_memmove_s()
{
    test_memmove_s();
}

void enc_test_strncpy_s()
{
    test_strncpy_s();
}

void enc_test_strncat_s()
{
    test_strncat_s();
}

void enc_test_memset_s()
{
    test_memset_s();
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */

#define TA_UUID                                            \
    { /* 91dc6667-7a33-4bbc-ab3e-ab4fca5215b7 */           \
        0x91dc6667, 0x7a33, 0x4bbc,                        \
        {                                                  \
            0xab, 0x3e, 0xab, 0x4f, 0xca, 0x52, 0x15, 0xb7 \
        }                                                  \
    }

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,
    1 * 1024 * 1024,
    12 * 1024,
    TA_FLAG_EXEC_DDR,
    "1.0.0",
    "Safe CRT test")
