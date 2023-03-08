// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/host.h>
#include <openenclave/host_verify.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include "../common/sgx/quote.h"
#include "quote.h"
#include "sgx_u.h"
#include "tee_u.h"

#include "sgxquoteprovider.h"

OE_STATIC_ASSERT(OE_REPORT_DATA_SIZE == sizeof(sgx_report_data_t));

static oe_result_t _get_local_report(
    oe_enclave_t* enclave,
    const void* opt_params,
    size_t opt_params_size,
    void* report_buffer,
    size_t* report_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint32_t retval;

    // opt_params, if specified, must be a sgx_target_info_t. When opt_params is
    // NULL, opt_params_size must be zero.
    if (opt_params != NULL && opt_params_size != sizeof(sgx_target_info_t))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (opt_params == NULL && opt_params_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (report_buffer_size == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (report_buffer == NULL || *report_buffer_size < sizeof(sgx_report_t))
    {
        *report_buffer_size = sizeof(sgx_report_t);
        OE_RAISE_NO_TRACE(OE_BUFFER_TOO_SMALL);
    }

    OE_CHECK(oe_get_sgx_report_ecall(
        enclave,
        &retval,
        opt_params,
        opt_params_size,
        (sgx_report_t*)report_buffer));

    *report_buffer_size = sizeof(sgx_report_t);

    result = (oe_result_t)retval;

done:

    return result;
}

static oe_result_t _get_remote_report(
    oe_enclave_t* enclave,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t* report_buffer,
    size_t* report_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    sgx_target_info_t* sgx_target_info = NULL;
    sgx_report_t* sgx_report = NULL;
    size_t sgx_report_size = sizeof(sgx_report_t);

    // For remote attestation, the Quoting Enclave's target info is used.
    // opt_params must not be supplied.
    if (opt_params != NULL || opt_params_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (report_buffer_size == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (report_buffer == NULL)
        *report_buffer_size = 0;

    /*
     * Get target info from Quoting Enclave.
     */
    sgx_target_info = calloc(1, sizeof(sgx_target_info_t));

    if (sgx_target_info == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(sgx_get_qetarget_info(sgx_target_info));

    /*
     * Get sgx_report_t from the enclave.
     */
    sgx_report = (sgx_report_t*)calloc(1, sizeof(sgx_report_t));

    if (sgx_report == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(_get_local_report(
        enclave,
        sgx_target_info,
        sizeof(*sgx_target_info),
        (uint8_t*)sgx_report,
        &sgx_report_size));

    /*
     * Get quote from Quoting Enclave.
     */
    OE_CHECK(sgx_get_quote(sgx_report, report_buffer, report_buffer_size));

    result = OE_OK;

done:

    if (sgx_target_info)
    {
        oe_secure_zero_fill(sgx_target_info, sizeof(*sgx_target_info));
        free(sgx_target_info);
    }

    if (sgx_report)
    {
        oe_secure_zero_fill(sgx_report, sizeof(*sgx_report));
        free(sgx_report);
    }

    return result;
}

static oe_result_t _oe_get_report_internal(
    oe_enclave_t* enclave,
    uint32_t flags,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t* report_buffer,
    size_t* report_buffer_size)
{
    oe_result_t result = OE_FAILURE;
    oe_report_header_t* header = (oe_report_header_t*)report_buffer;

#if defined(OE_LINK_SGX_DCAP_QL)
    // The two host side attestation API's are oe_get_report and
    // oe_verify_report. Initialize the quote provider in both these APIs.
    OE_CHECK(oe_initialize_quote_provider());
#else
    if (flags & OE_REPORT_FLAGS_REMOTE_ATTESTATION)
        return OE_UNSUPPORTED;
#endif

    // Reserve space in the buffer for header.
    if (report_buffer && report_buffer_size)
    {
        if (*report_buffer_size >= sizeof(oe_report_header_t))
        {
            OE_CHECK(oe_safe_add_u64(
                (uint64_t)report_buffer,
                sizeof(oe_report_header_t),
                (uint64_t*)&report_buffer));
            *report_buffer_size -= sizeof(oe_report_header_t);
        }
    }

    if (flags & OE_REPORT_FLAGS_REMOTE_ATTESTATION)
    {
        OE_CHECK(_get_remote_report(
            enclave,
            opt_params,
            opt_params_size,
            report_buffer,
            report_buffer_size));
    }
    else
    {
        // If no flags are specified, default to locally attestable report.
        OE_CHECK(_get_local_report(
            enclave,
            opt_params,
            opt_params_size,
            report_buffer,
            report_buffer_size));
    }

    header->version = OE_REPORT_HEADER_VERSION;
    header->report_type = (flags & OE_REPORT_FLAGS_REMOTE_ATTESTATION)
                              ? OE_REPORT_TYPE_SGX_REMOTE
                              : OE_REPORT_TYPE_SGX_LOCAL;
    header->report_size = *report_buffer_size;
    OE_CHECK(oe_safe_add_u64(
        *report_buffer_size, sizeof(oe_report_header_t), report_buffer_size));
    result = OE_OK;

done:
    if (result == OE_BUFFER_TOO_SMALL)
    {
        *report_buffer_size += sizeof(oe_report_header_t);
    }

    return result;
}

oe_result_t oe_get_report_v2(
    oe_enclave_t* enclave,
    uint32_t flags,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** report_buffer,
    size_t* report_buffer_size)
{
    oe_result_t result;
    uint8_t* tmp_report_buffer = NULL;
    size_t tmp_report_buffer_size = 0;

    if (!report_buffer || !report_buffer_size)
        return OE_INVALID_PARAMETER;

    *report_buffer = NULL;
    *report_buffer_size = 0;

    result = _oe_get_report_internal(
        enclave,
        flags,
        opt_params,
        opt_params_size,
        NULL,
        &tmp_report_buffer_size);
    if (result != OE_BUFFER_TOO_SMALL)
    {
        if (result == OE_OK)
        {
            result = OE_UNEXPECTED;
        }
        return result;
    }

    tmp_report_buffer = calloc(1, tmp_report_buffer_size);
    if (tmp_report_buffer == NULL)
    {
        return OE_OUT_OF_MEMORY;
    }

    result = _oe_get_report_internal(
        enclave,
        flags,
        opt_params,
        opt_params_size,
        tmp_report_buffer,
        &tmp_report_buffer_size);
    if (result != OE_OK)
    {
        free(tmp_report_buffer);
        return result;
    }

    *report_buffer = tmp_report_buffer;
    *report_buffer_size = tmp_report_buffer_size;

    return OE_OK;
}

void oe_free_report(uint8_t* report_buffer)
{
    free(report_buffer);
}

oe_result_t oe_verify_report(
    oe_enclave_t* enclave,
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_report_t oe_report = {0};
    oe_report_header_t* header = (oe_report_header_t*)report;

    if (report == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (report_size == 0 || report_size > OE_MAX_REPORT_SIZE)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Ensure that the report is parseable before using the header.
    OE_CHECK(oe_parse_report(report, report_size, &oe_report));

    if (header->report_type == OE_REPORT_TYPE_SGX_REMOTE)
    {
        // Intialize the quote provider if we want to verify a remote quote.
        // Note that we don't have the OE_LINK_SGX_DCAP_QL guard here since we
        // don't need the sgx libraries to verify the quote. All we need is the
        // quote provider.
        OE_CHECK(oe_initialize_quote_provider());

        // Quote attestation can be done entirely on the host side.
        OE_CHECK(oe_verify_quote_internal_with_collaterals(
            header->report, header->report_size, NULL, 0, NULL));
    }
    else if (header->report_type == OE_REPORT_TYPE_SGX_LOCAL)
    {
        uint32_t retval;

        if (enclave == NULL)
            OE_RAISE(OE_INVALID_PARAMETER);

        OE_CHECK(oe_verify_report_ecall(enclave, &retval, report, report_size));

        OE_CHECK(retval);
    }
    else
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    // Optionally return parsed report.
    if (parsed_report != NULL)
        OE_CHECK(oe_parse_report(report, report_size, parsed_report));

    result = OE_OK;
done:
    return result;
}
