// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_ENCLAVE_H
#define _OE_HOST_ENCLAVE_H

#include <pthread.h>

#include <tee_client_api.h>
#include <tee_client_api_extensions.h>

#include <openenclave/host.h>

#define ENCLAVE_MAGIC 0x85ab45987c7ef1e3

struct _oe_enclave
{
    /* A "magic number" to validate structure */
    uint64_t magic;

    /* UUID of the TA */
    TEEC_UUID uuid;

    /* Path (UUID in string form) of the enclave file */
    char* path;

    /* TEE client context */
    TEEC_Context ctx;

    /* TEE client seesion */
    TEEC_Session session;

    /* Thread that handles TA RPCs (a.k.a OCALLs) */
    pthread_t grpc_thread;

    /* Mutex to ensure single-threaded-ness for TAs */
    pthread_mutex_t mutex;

    /* Array of ocall functions */
    const oe_ocall_func_t* ocalls;
    size_t num_ocalls;
};

#endif /* _OE_HOST_ENCLAVE_H */
