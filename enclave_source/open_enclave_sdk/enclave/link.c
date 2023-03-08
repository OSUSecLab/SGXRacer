// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/malloc.h>
#include "tee_t.h"

//
// start.S (the compilation unit containing the entry point) contains a
// reference to this function, which sets up a dependency chain from the
// object file containing the entry point to all symbols referenced in
// the array below (as well as symbols reachable from those symbols).
// This forces the collection of symbols to be included in the enclave
// image so that the linker will consider them when resolving symbols in
// subsequently linked libraries. The main purpose of this mechanism is
// to resolve reverse dependencies that liboecore has on liboeenclave.
//
const void* oe_link_enclave(void)
{
    static const void* symbols[] = {
        oe_verify_report_ecall,
        oe_get_public_key_by_policy_ecall,
        oe_get_public_key_ecall,
#if defined(OE_USE_DEBUG_MALLOC)
        oe_debug_malloc_check,
#endif /* defined(OE_USE_DEBUG_MALLOC) */
    };

    return symbols;
}
