// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "dispatcher.h"
#include <openenclave/enclave.h>

ecall_dispatcher::ecall_dispatcher(
    const char* name,
    enclave_config_data_t* enclave_config)
    : m_crypto(NULL), m_attestation(NULL)
{
    m_enclave_config = enclave_config;
    m_initialized = initialize(name);
}

ecall_dispatcher::~ecall_dispatcher()
{
    if (m_crypto)
        delete m_crypto;

    if (m_attestation)
        delete m_attestation;
}

bool ecall_dispatcher::initialize(const char* name)
{
    bool ret = false;
    uint8_t* modulus = NULL;
    size_t modulus_size;

    m_name = name;
    m_crypto = new Crypto();
    if (m_crypto == NULL)
    {
        goto exit;
    }

    // Extract modulus from raw PEM.
    if (!m_crypto->get_rsa_modulus_from_pem(
            m_enclave_config->other_enclave_pubkey_pem,
            m_enclave_config->other_enclave_pubkey_pem_size,
            &modulus,
            &modulus_size))
    {
        goto exit;
    }

    // Reverse the modulus and compute sha256 on it.
    for (size_t i = 0; i < modulus_size / 2; i++)
    {
        uint8_t tmp = modulus[i];
        modulus[i] = modulus[modulus_size - 1 - i];
        modulus[modulus_size - 1 - i] = tmp;
    }

    // Calculate the MRSIGNER value which is the SHA256 hash of the
    // little endian representation of the public key modulus. This value
    // is populated by the signer_id sub-field of a parsed oe_report_t's
    // identity field.
    if (m_crypto->Sha256(modulus, modulus_size, m_other_enclave_mrsigner) != 0)
    {
        goto exit;
    }

    m_attestation = new Attestation(m_crypto, m_other_enclave_mrsigner);
    if (m_attestation == NULL)
    {
        goto exit;
    }
    ret = true;

exit:
    if (modulus != NULL)
        free(modulus);

    return ret;
}

int ecall_dispatcher::get_target_info(
    uint8_t** target_info_buffer,
    size_t* target_info_size)
{
    oe_result_t result = OE_OK;
    uint8_t* report = NULL;
    size_t report_size = 0;
    int ret = 1;
    uint8_t* info_buffer = NULL;

    TRACE_ENCLAVE("get_target_info");
    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    // Generate a report for the public key so that the enclave that
    // receives the key can attest this enclave.
    if (m_attestation->generate_local_report(
            NULL, 0, NULL, 0, &report, &report_size))
    {
        size_t info_size = 0;

        TRACE_ENCLAVE("report_size = %ld", report_size);
        // get the target info
        // caller of info_buffer needs to free this memory
        result = oe_get_target_info(
            report, report_size, (void**)&info_buffer, &info_size);
        if (result != OE_OK)
        {
            TRACE_ENCLAVE(
                "oe_get_target_info: query buffer info failed with %x", result);
            goto exit;
        }
        TRACE_ENCLAVE("info_size = %ld", info_size);

        // Allocate memory on the host and copy the target info over.
        *target_info_buffer = (uint8_t*)oe_host_malloc(info_size);
        if (*target_info_buffer == NULL)
        {
            ret = OE_OUT_OF_MEMORY;
            goto exit;
        }
        memcpy(*target_info_buffer, info_buffer, info_size);
        *target_info_size = info_size;
        oe_free_target_info(info_buffer);
        ret = 0;
    }

exit:

    if (report)
        oe_free_report(report);

    if (ret != 0)
    {
        TRACE_ENCLAVE("get_target_info failed.");
        if (info_buffer)
            oe_free_target_info(info_buffer);
    }
    return ret;
}

/**
 * Return the public key of this enclave along with the enclave's local report.
 * The enclave that receives the key will use the local report to attest this
 * enclave.
 */
int ecall_dispatcher::get_targeted_report_with_pubkey(
    uint8_t* target_info_buffer,
    size_t target_info_size,
    uint8_t** pem_key,
    size_t* key_size,
    uint8_t** local_report,
    size_t* local_report_size)
{
    uint8_t pem_public_key[512];
    uint8_t* report = NULL;
    size_t report_size = 0;
    uint8_t* key_buf = NULL;
    int ret = 1;

    TRACE_ENCLAVE("get_targeted_report_with_pubkey");
    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    m_crypto->retrieve_public_key(pem_public_key);

    // Generate a report for the public key so that the enclave that
    // receives the key can attest this enclave.
    if (m_attestation->generate_local_report(
            target_info_buffer,
            target_info_size,
            pem_public_key,
            sizeof(pem_public_key),
            &report,
            &report_size))
    {
        // Allocate memory on the host and copy the report over.
        *local_report = (uint8_t*)oe_host_malloc(report_size);
        if (*local_report == NULL)
        {
            ret = OE_OUT_OF_MEMORY;
            goto exit;
        }
        memcpy(*local_report, report, report_size);
        *local_report_size = report_size;
        oe_free_report(report);

        key_buf = (uint8_t*)oe_host_malloc(512);
        if (key_buf == NULL)
        {
            ret = OE_OUT_OF_MEMORY;
            goto exit;
        }
        memcpy(key_buf, pem_public_key, sizeof(pem_public_key));

        *pem_key = key_buf;
        *key_size = sizeof(pem_public_key);

        ret = 0;
        TRACE_ENCLAVE("get_targeted_report_with_pubkey succeeded");
    }
    else
    {
        TRACE_ENCLAVE("get_targeted_report_with_pubkey failed.");
    }

exit:

    if (ret != 0)
    {
        if (report)
            oe_free_report(report);

        if (key_buf)
            oe_host_free(key_buf);

        if (*local_report)
            oe_host_free(*local_report);
    }
    return ret;
}

int ecall_dispatcher::verify_report_and_set_pubkey(
    uint8_t* pem_key,
    size_t pem_key_size,
    uint8_t* local_report,
    size_t local_report_size)
{
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    // Attest the report and accompanying key.
    if (m_attestation->attest_local_report(
            local_report, local_report_size, pem_key, pem_key_size))
    {
        memcpy(
            m_crypto->get_the_other_enclave_public_key(),
            pem_key,
            pem_key_size);
    }
    else
    {
        TRACE_ENCLAVE("verify_report_and_set_pubkey failed.");
        goto exit;
    }
    ret = 0;
    TRACE_ENCLAVE("verify_report_and_set_pubkey succeeded.");

exit:
    return ret;
}

int ecall_dispatcher::generate_encrypted_message(uint8_t** data, size_t* size)
{
    uint8_t encrypted_data_buf[1024];
    size_t encrypted_data_size;
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    encrypted_data_size = sizeof(encrypted_data_buf);
    if (m_crypto->Encrypt(
            m_crypto->get_the_other_enclave_public_key(),
            m_enclave_config->enclave_secret_data,
            ENCLAVE_SECRET_DATA_SIZE,
            encrypted_data_buf,
            &encrypted_data_size))
    {
        uint8_t* host_buf = (uint8_t*)oe_host_malloc(encrypted_data_size);
        memcpy(host_buf, encrypted_data_buf, encrypted_data_size);
        TRACE_ENCLAVE(
            "enclave: generate_encrypted_message: encrypted_data_size = %ld",
            encrypted_data_size);
        *data = host_buf;
        *size = encrypted_data_size;
    }
    else
    {
        goto exit;
    }
    ret = 0;
exit:
    return ret;
}

int ecall_dispatcher::process_encrypted_msg(
    uint8_t* encrypted_data,
    size_t encrypted_data_size)
{
    uint8_t data[1024];
    size_t data_size = 0;
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    data_size = sizeof(data);
    if (m_crypto->decrypt(
            encrypted_data, encrypted_data_size, data, &data_size))
    {
        // This is where the business logic for verifying the data should be.
        // In this sample, both enclaves start with identical data in
        // m_enclave_config->enclave_secret_data.
        // The following checking is to make sure the decrypted values are what
        // we have expected.
        TRACE_ENCLAVE("Decrypted data: ");
        for (uint32_t i = 0; i < data_size; ++i)
        {
            printf("%d ", data[i]);
            if (m_enclave_config->enclave_secret_data[i] != data[i])
            {
                printf(
                    "Expecting [0x%x] but received unexpected value "
                    "[0x%x]\n ",
                    m_enclave_config->enclave_secret_data[i],
                    data[i]);
                ret = 1;
                break;
            }
        }
        printf("\n");
    }
    else
    {
        TRACE_ENCLAVE("Encalve:ecall_dispatcher::process_encrypted_msg failed");
        goto exit;
    }
    TRACE_ENCLAVE("Decrypted data matches with the enclave internal secret "
                  "data: descryption validation succeeded");
    ret = 0;
exit:
    return ret;
}
