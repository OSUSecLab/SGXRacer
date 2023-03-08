// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include "create_errors_t.h"

int test(void)
{
    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */

#define TA_UUID                                            \
    { /* 1083bbac-751e-4d26-ada6-c254bbfbe653 */           \
        0x1083bbac, 0x751e, 0x4d26,                        \
        {                                                  \
            0xad, 0xa6, 0xc2, 0x54, 0xbb, 0xfb, 0xe6, 0x53 \
        }                                                  \
    }

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,
    1 * 1024 * 1024,
    12 * 1024,
    TA_FLAG_EXEC_DDR,
    "1.0.0",
    "Create Errors test")
