// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <stdio.h>
#include "switchless_t.h"

void enclave_add_N_switchless(int* m, int n)
{
    // Call back into the host switchlessly
    for (int i = 0; i < n; i++)
    {
        oe_result_t result = host_increment_switchless(m);
        if (result != OE_OK)
        {
            fprintf(stderr, "host_increment_switchless(): result=%u", result);
        }
    }
}

void enclave_add_N_regular(int* m, int n)
{
    // Call back into the host
    for (int i = 0; i < n; i++)
    {
        oe_result_t result = host_increment_regular(m);
        if (result != OE_OK)
        {
            fprintf(stderr, "host_increment_regular(): result=%u", result);
        }
    }
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
