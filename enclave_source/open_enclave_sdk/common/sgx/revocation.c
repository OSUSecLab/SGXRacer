// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "revocation.h"
#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/crypto/cert.h>
#include <openenclave/internal/crypto/crl.h>
#include <openenclave/internal/crypto/ec.h>
#include <openenclave/internal/crypto/sha.h>
#include <openenclave/internal/datetime.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgxcertextensions.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include "../common.h"
#include "tcbinfo.h"

// Defaults to Intel SGX 1.8 Release Date.
oe_datetime_t _sgx_minimim_crl_tcb_issue_date = {2017, 3, 17};

oe_result_t __oe_sgx_set_minimum_crl_tcb_issue_date(
    uint32_t year,
    uint32_t month,
    uint32_t day,
    uint32_t hours,
    uint32_t minutes,
    uint32_t seconds)
{
    oe_result_t result = OE_FAILURE;
    oe_datetime_t tmp = {year, month, day, hours, minutes, seconds};

    OE_CHECK(oe_datetime_is_valid(&tmp));
    _sgx_minimim_crl_tcb_issue_date = tmp;

    result = OE_OK;
done:
    return result;
}

static oe_result_t _get_tcb_info_validity(
    const oe_parsed_tcb_info_t* parsed_tcb_info,
    oe_datetime_t* from,
    oe_datetime_t* until)
{
    *from = parsed_tcb_info->issue_date;
    *until = parsed_tcb_info->next_update;

    return OE_OK;
}

static oe_result_t _get_crl_validity(
    const oe_crl_t* crls,
    const uint32_t crls_count,
    oe_datetime_t* from,
    oe_datetime_t* until)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_datetime_t crl_this_update_date = {0};
    oe_datetime_t crl_next_update_date = {0};

    if (crls_count > 0)
    {
        OE_CHECK_MSG(
            oe_crl_get_update_dates(&crls[0], from, until),
            "Failed to get CRL update dates. %s",
            oe_result_str(result));

        for (uint32_t i = 0; i < crls_count; ++i)
        {
            OE_CHECK_MSG(
                oe_crl_get_update_dates(
                    &crls[0], &crl_this_update_date, &crl_next_update_date),
                "Failed to get CRL update dates. %s",
                oe_result_str(result));

            if (oe_datetime_compare(&crl_this_update_date, from) > 0)
            {
                *from = crl_this_update_date;
            }
            if (oe_datetime_compare(&crl_next_update_date, until) < 0)
            {
                *until = crl_next_update_date;
            }
        }

        result = OE_OK;
    }

done:
    return result;
}

static oe_result_t _get_revocation_validity(
    const oe_parsed_tcb_info_t* parsed_tcb_info,
    const oe_crl_t* crls,
    const uint32_t crls_count,
    oe_datetime_t* from,
    oe_datetime_t* until)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_datetime_t latest_from = {0};
    oe_datetime_t earliest_until = {0};
    oe_datetime_t current_from = {0};
    oe_datetime_t current_until = {0};

    OE_CHECK_MSG(
        _get_tcb_info_validity(parsed_tcb_info, &latest_from, &earliest_until),
        "Failed to get TCB info validity datetime info. %s",
        oe_result_str(result));
    oe_datetime_log("TCB info validity from date: ", &latest_from);
    oe_datetime_log("TCB info validity until date: ", &earliest_until);

    OE_CHECK_MSG(
        _get_crl_validity(crls, crls_count, &current_from, &current_until),
        "Failed to get CRL validity datetime info. %s",
        oe_result_str(result));
    oe_datetime_log("CRL validity from date: ", &current_from);
    oe_datetime_log("CRL validity until date: ", &current_until);

    // Currently we are ignoring TCB Info validity dates because
    // the data is expired.  See Icm 148493545
    latest_from = current_from;
    earliest_until = current_until;

    oe_datetime_log("Revocation overall validity from date: ", &latest_from);
    oe_datetime_log(
        "Revocation overall validity until date: ", &earliest_until);

    *from = latest_from;
    *until = earliest_until;
    result = OE_OK;

done:
    return result;
}

/**
 * Parse sgx extensions from given cert.
 */
static oe_result_t _parse_sgx_extensions(
    oe_cert_t* leaf_cert,
    ParsedExtensionInfo* parsed_extension_info)
{
    oe_result_t result = OE_FAILURE;

    // The size of buffer required to parse extensions is not known beforehand.
    size_t buffer_size = 1024;
    uint8_t* buffer = NULL;

    buffer = (uint8_t*)oe_malloc(buffer_size);
    if (buffer == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    // Try parsing the extensions.
    result = ParseSGXExtensions(
        leaf_cert, buffer, &buffer_size, parsed_extension_info);

    if (result == OE_BUFFER_TOO_SMALL)
    {
        // Allocate larger buffer. extensions_buffer_size contains required size
        // of buffer.
        oe_free(buffer);
        buffer = (uint8_t*)oe_malloc(buffer_size);

        result = ParseSGXExtensions(
            leaf_cert, buffer, &buffer_size, parsed_extension_info);
    }

done:
    oe_free(buffer);
    return result;
}

typedef struct _url
{
    char str[256];
} url_t;

/**
 * Get CRL distribution points from given cert.
 */

static oe_result_t _get_crl_distribution_point(oe_cert_t* cert, char** url)
{
    oe_result_t result = OE_FAILURE;
    size_t buffer_size = 512;
    uint8_t* buffer = oe_malloc(buffer_size);
    const char** urls = NULL;
    uint64_t num_urls = 0;
    size_t url_length = 0;

    if (buffer == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    result = oe_get_crl_distribution_points(
        cert, &urls, &num_urls, buffer, &buffer_size);

    if (result == OE_BUFFER_TOO_SMALL)
    {
        oe_free(buffer);
        buffer = oe_malloc(buffer_size);
        if (buffer == NULL)
            OE_RAISE(OE_OUT_OF_MEMORY);

        result = oe_get_crl_distribution_points(
            cert, &urls, &num_urls, buffer, &buffer_size);
    }

    if (result == OE_OK)
    {
        // At most 1 distribution point is expected.
        if (num_urls != 1)
            OE_RAISE(OE_FAILURE);

        // Sanity check. No URL should be this large.
        url_length = oe_strlen(urls[0]);
        if (url_length > OE_INT16_MAX)
            OE_RAISE(OE_OUT_OF_BOUNDS);

        // Add +1 to include null character.
        url_length++;

        *url = (char*)oe_malloc(url_length);
        if (*url == NULL)
            OE_RAISE(OE_OUT_OF_MEMORY);

        OE_CHECK(oe_memcpy_s(*url, url_length, urls[0], url_length));
        result = OE_OK;
    }

done:
    oe_free(buffer);
    return result;
}

/**
 * Call into host to fetch revocation information given the CA and PCK
 * certificates.
 */
oe_result_t oe_get_revocation_info_from_certs(
    oe_cert_t* leaf_cert,
    oe_cert_t* intermediate_cert,
    oe_get_revocation_info_args_t* args)
{
    oe_result_t result = OE_FAILURE;
    ParsedExtensionInfo parsed_extension_info = {{0}};
    char* intermediate_crl_url = NULL;
    char* leaf_crl_url = NULL;

    if (intermediate_cert == NULL || leaf_cert == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Gather fmspc.
    OE_CHECK(_parse_sgx_extensions(leaf_cert, &parsed_extension_info));
    OE_CHECK(oe_memcpy_s(
        args->fmspc,
        sizeof(args->fmspc),
        parsed_extension_info.fmspc,
        sizeof(parsed_extension_info.fmspc)));

    // Gather CRL distribution point URLs from certs.
    OE_CHECK(
        _get_crl_distribution_point(intermediate_cert, &intermediate_crl_url));
    OE_CHECK(_get_crl_distribution_point(leaf_cert, &leaf_crl_url));

    args->crl_urls[0] = leaf_crl_url;
    args->crl_urls[1] = intermediate_crl_url;
    args->num_crl_urls = 2;

    OE_CHECK(oe_get_revocation_info(args));

    result = OE_OK;
done:

    oe_free(leaf_crl_url);
    oe_free(intermediate_crl_url);

    return result;
}

oe_result_t oe_validate_revocation_list(
    oe_cert_t* pck_cert,
    oe_get_revocation_info_args_t* revocation_args,
    oe_datetime_t* validity_from,
    oe_datetime_t* validity_until)
{
    oe_result_t result = OE_UNEXPECTED;

    ParsedExtensionInfo parsed_extension_info = {{0}};
    oe_cert_chain_t tcb_issuer_chain = {0};
    oe_cert_chain_t crl_issuer_chain[3] = {{{0}}};
    oe_cert_t tcb_cert = {0};
    oe_parsed_tcb_info_t parsed_tcb_info = {0};
    oe_tcb_level_t platform_tcb_level = {{0}};

    oe_crl_t crls[2] = {{{0}}};
    const oe_crl_t* crl_ptrs[2] = {&crls[0], &crls[1]};
    oe_datetime_t from = {0};
    oe_datetime_t until = {0};
    oe_datetime_t latest_from = {0};
    oe_datetime_t earliest_until = {0};

    if (pck_cert == NULL || revocation_args == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_STATIC_ASSERT(
        OE_COUNTOF(crl_issuer_chain) ==
        OE_COUNTOF(revocation_args->crl_issuer_chain));

    OE_CHECK_MSG(
        _parse_sgx_extensions(pck_cert, &parsed_extension_info),
        "Failed to parse SGX extensions from leaf cert. %s",
        oe_result_str(result));

    // Apply revocation info.
    OE_CHECK_MSG(
        oe_cert_chain_read_pem(
            &tcb_issuer_chain,
            revocation_args->tcb_issuer_chain,
            revocation_args->tcb_issuer_chain_size),
        "Failed to read TCB chain certificate. %s",
        oe_result_str(result));

    // Read CRLs for each cert other than root. If any CRL is missing, the read
    // will error out.
    for (uint32_t i = 0; i < revocation_args->num_crl_urls; ++i)
    {
        OE_CHECK_MSG(
            oe_crl_read_der(
                &crls[i],
                revocation_args->crl[i],
                revocation_args->crl_size[i]),
            "Failed to read CRL. %s",
            oe_result_str(result));
        OE_CHECK_MSG(
            oe_cert_chain_read_pem(
                &crl_issuer_chain[i],
                revocation_args->crl_issuer_chain[i],
                revocation_args->crl_issuer_chain_size[i]),
            "Failed to read CRL cert chain. %s",
            oe_result_str(result));
        OE_TRACE_VERBOSE(
            "CRL certificate[%d]: \n[%s]\n",
            i,
            revocation_args->crl_issuer_chain[i]);
    }

    // Verify the leaf cert.
    // oe_cert_verify incorporates openssl -crl_check_all semantics.
    // For successful verification:
    //    1. The certificate chain must be valid. Each cert must
    //       have its issuer CA in the chain.
    //    2. Each issuer CA (ie all certs other than the leaf cert)
    //       must also have a matching CRL issued by the issuer CA.
    //    3. The certificate chain must pass signature verification.
    //    4. No certificate in the chain must be revoked.
    // Note: An issuer CA can revoke only the certs that it has issued.
    // this follows that the certificate chain and CRL issuer chains must
    // be the same. We pass the crl_issuer_chain here to assert that
    // constraint. If the crl_issuer_chain was different from the certificate
    // chain, then verification would fail because the CRLs will not be found
    // for certificates in the chain.
    OE_CHECK_MSG(
        oe_cert_verify(
            pck_cert, crl_issuer_chain, crl_ptrs, OE_COUNTOF(crl_ptrs)),
        "Failed to verify leaf certificate. %s",
        oe_result_str(result));

    for (uint32_t i = 0; i < OE_COUNTOF(platform_tcb_level.sgx_tcb_comp_svn);
         ++i)
    {
        platform_tcb_level.sgx_tcb_comp_svn[i] =
            parsed_extension_info.comp_svn[i];
    }
    platform_tcb_level.pce_svn = parsed_extension_info.pce_svn;
    platform_tcb_level.status = OE_TCB_LEVEL_STATUS_UNKNOWN;

    OE_CHECK_MSG(
        oe_parse_tcb_info_json(
            revocation_args->tcb_info,
            revocation_args->tcb_info_size,
            &platform_tcb_level,
            &parsed_tcb_info),
        "Failed to parse TCB info. %s",
        oe_result_str(result));

    OE_CHECK_MSG(
        oe_verify_ecdsa256_signature(
            parsed_tcb_info.tcb_info_start,
            parsed_tcb_info.tcb_info_size,
            (sgx_ecdsa256_signature_t*)parsed_tcb_info.signature,
            &tcb_issuer_chain),
        "Failed to verify ECDSA 256 signature in TCB. %s",
        oe_result_str(result));

    OE_CHECK_MSG(
        _get_revocation_validity(
            &parsed_tcb_info,
            crls,
            OE_COUNTOF(crls),
            &latest_from,
            &earliest_until),
        "Failed to get revocation validity datetime info. %s",
        oe_result_str(result));

    if (oe_datetime_compare(&latest_from, &_sgx_minimim_crl_tcb_issue_date) < 0)
    {
        oe_datetime_log("Latest issue date : ", &latest_from);
        oe_datetime_log(
            " is earlier than minimum issue date: ",
            &_sgx_minimim_crl_tcb_issue_date);
        OE_RAISE_MSG(
            OE_INVALID_REVOCATION_INFO,
            "Revocation validation failed minimum issue date. %s",
            oe_result_str(result));
    }

    if (oe_datetime_compare(&earliest_until, &_sgx_minimim_crl_tcb_issue_date) <
        0)
    {
        oe_datetime_log("Next update date : ", &earliest_until);
        oe_datetime_log(
            " is earlier than minimum issue date: ",
            &_sgx_minimim_crl_tcb_issue_date);
        OE_RAISE_MSG(
            OE_INVALID_REVOCATION_INFO,
            "Revocation validation failed minimum issue date. %s",
            oe_result_str(result));
    }

    // Get TCB cert validity period.
    OE_CHECK_MSG(
        oe_cert_chain_get_leaf_cert(&tcb_issuer_chain, &tcb_cert),
        "Failed to get TCB certificate.",
        NULL);
    oe_cert_get_validity_dates(&tcb_cert, &from, &until);
    oe_datetime_log("TCB cert issue date: ", &from);
    oe_datetime_log("TCB cert next update: ", &until);

    if (oe_datetime_compare(&from, &latest_from) > 0)
        latest_from = from;
    if (oe_datetime_compare(&until, &earliest_until) < 0)
        earliest_until = until;
    oe_datetime_log("Revocation overall issue date: ", &latest_from);
    oe_datetime_log("Revocation overall next update: ", &earliest_until);

    if (oe_datetime_compare(&latest_from, &earliest_until) > 0)
        OE_RAISE_MSG(
            OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD,
            "Failed to find an overall revocation validity period.",
            NULL);

    *validity_from = latest_from;
    *validity_until = earliest_until;
    result = OE_OK;

done:
    for (int32_t i = (int32_t)revocation_args->num_crl_urls - 1; i >= 0; --i)
    {
        oe_crl_free(&crls[i]);
    }
    for (uint32_t i = 0; i < revocation_args->num_crl_urls; ++i)
    {
        oe_cert_chain_free(&crl_issuer_chain[i]);
    }
    oe_cert_chain_free(&tcb_issuer_chain);
    oe_cert_free(&tcb_cert);

    return result;
}