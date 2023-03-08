// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SWITCHLESSCALLS_H
#define _OE_SWITCHLESSCALLS_H

#include <openenclave/internal/switchless.h>

bool oe_is_switchless_initialized();

oe_result_t oe_handle_init_switchless(uint64_t arg_in);

oe_result_t oe_post_switchless_ocall(oe_call_host_function_args_t* args);

#endif // _OE_SWITCHLESSCALLS_H
