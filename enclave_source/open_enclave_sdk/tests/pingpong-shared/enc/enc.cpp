// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include "pingpong_t.h"

void Ping(const char* in, char* out)
{
    Pong(in, out);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    256,  /* StackPageCount */
    4);   /* TCSCount */

#define TA_UUID                                            \
    { /* e229cc0f-3199-4ad3-91a7-47906fcbcc59 */           \
        0xe229cc0f, 0x3199, 0x4ad3,                        \
        {                                                  \
            0x91, 0xa7, 0x47, 0x90, 0x6f, 0xcb, 0xcc, 0x59 \
        }                                                  \
    }

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,
    1 * 1024 * 1024,
    12 * 1024,
    TA_FLAG_EXEC_DDR,
    "1.0.0",
    "Ping-Pong Shared test")
