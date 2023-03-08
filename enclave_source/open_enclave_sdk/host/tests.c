// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include "dupenv.h"

uint32_t oe_get_create_flags(void)
{
#if __aarch64__
    /* OE_ENCLAVE_FLAG_DEBUG is not available on ARM TrustZone. */
    uint32_t result = 0;
#else
    uint32_t result = OE_ENCLAVE_FLAG_DEBUG;
#endif

    char* env = NULL;

    if (!(env = oe_dupenv("OE_SIMULATION")))
        goto done;

    if (strcmp(env, "1") == 0)
        result |= OE_ENCLAVE_FLAG_SIMULATE;

done:

    if (env)
        free(env);

    return result;
}
