// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "oe_gdb_test_u.h"

extern void assert_debugger_binary_contract_host_side();

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave1 = NULL;
    bool simulation_mode = false;

    if (argc < 2)
    {
        fprintf(
            stderr, "Usage: %s ENCLAVE_PATH [--simulation-mode]\n", argv[0]);
        return 1;
    }

    uint32_t flags = oe_get_create_flags();

    simulation_mode =
        (argc == 3 && (strcmp(argv[2], "--simulation-mode") == 0));

    if (simulation_mode)
    {
        // Force simulation mode if --simulation-mode is specified.
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    }

    if ((result = oe_create_oe_gdb_test_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave1)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    {
        int c = 0;
        OE_TEST(enc_add(enclave1, &c, 5, 6) == OE_OK);

        // Test that the debugger was able to change the return value in the
        // enclave.
        OE_TEST(c == 10000);
    }

    assert_debugger_binary_contract_host_side();
    OE_TEST(enc_assert_debugger_binary_contract(enclave1) == OE_OK);

    result = oe_terminate_enclave(enclave1);
    OE_TEST(result == OE_OK);

    printf(
        "=== passed all tests (oegdb-test%s)\n",
        simulation_mode ? "-simulation-mode" : "");

    return 0;
}
