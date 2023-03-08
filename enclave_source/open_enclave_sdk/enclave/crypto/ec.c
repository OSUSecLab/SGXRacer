// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "ec.h"
#include <mbedtls/asn1.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/ecp.h>
#include <openenclave/bits/safecrt.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
#include "key.h"
#include "pem.h"
#include "random_internal.h"

static uint64_t _PRIVATE_KEY_MAGIC = 0xf12c37bb02814eeb;
static uint64_t _PUBLIC_KEY_MAGIC = 0xd7490a56f6504ee6;

OE_STATIC_ASSERT(sizeof(oe_private_key_t) <= sizeof(oe_ec_private_key_t));
OE_STATIC_ASSERT(sizeof(oe_public_key_t) <= sizeof(oe_ec_public_key_t));

static mbedtls_ecp_group_id _get_group_id(oe_ec_type_t ec_type)
{
    switch (ec_type)
    {
        case OE_EC_TYPE_SECP256R1:
            return MBEDTLS_ECP_DP_SECP256R1;
        default:
            return MBEDTLS_ECP_DP_NONE;
    }
}

static oe_result_t _copy_key(
    mbedtls_pk_context* dest,
    const mbedtls_pk_context* src,
    bool copy_private_fields)
{
    oe_result_t result = OE_UNEXPECTED;
    const mbedtls_pk_info_t* info;
    int rc = 0;

    if (dest)
        mbedtls_pk_init(dest);

    /* Check parameters */
    if (!dest || !src)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Lookup the info for this key type */
    if (!(info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)))
        OE_RAISE(OE_PUBLIC_KEY_NOT_FOUND);

    /* Setup the context for this key type */
    rc = mbedtls_pk_setup(dest, info);
    if (rc != 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "rc = 0x%x", rc);

    /* Copy all fields of the key structure */
    {
        mbedtls_ecp_keypair* ec_dest = mbedtls_pk_ec(*dest);
        const mbedtls_ecp_keypair* ec_src = mbedtls_pk_ec(*src);

        if (!ec_dest || !ec_src)
            OE_RAISE(OE_FAILURE);

        if (mbedtls_ecp_group_copy(&ec_dest->grp, &ec_src->grp) != 0)
            OE_RAISE(OE_CRYPTO_ERROR);

        if (copy_private_fields)
        {
            if (mbedtls_mpi_copy(&ec_dest->d, &ec_src->d) != 0)
                OE_RAISE(OE_CRYPTO_ERROR);
        }

        if (mbedtls_ecp_copy(&ec_dest->Q, &ec_src->Q) != 0)
            OE_RAISE(OE_CRYPTO_ERROR);
    }

    result = OE_OK;

done:

    if (result != OE_OK)
        mbedtls_pk_free(dest);

    return result;
}

static oe_result_t oe_public_key_equal(
    const oe_public_key_t* public_key1,
    const oe_public_key_t* public_key2,
    bool* equal)
{
    oe_result_t result = OE_UNEXPECTED;

    if (equal)
        *equal = false;

    /* Reject bad parameters */
    if (!oe_public_key_is_valid(public_key1, _PUBLIC_KEY_MAGIC) ||
        !oe_public_key_is_valid(public_key2, _PUBLIC_KEY_MAGIC) || !equal)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Compare the groups and EC points */
    {
        const mbedtls_ecp_keypair* ec1 = mbedtls_pk_ec(public_key1->pk);
        const mbedtls_ecp_keypair* ec2 = mbedtls_pk_ec(public_key2->pk);

        if (!ec1 || !ec2)
            OE_RAISE(OE_INVALID_PARAMETER);

        if (ec1->grp.id == ec2->grp.id &&
            mbedtls_ecp_point_cmp(&ec1->Q, &ec2->Q) == 0)
        {
            *equal = true;
        }
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_ec_public_key_init(
    oe_ec_public_key_t* public_key,
    const mbedtls_pk_context* pk)
{
    return oe_public_key_init(
        (oe_public_key_t*)public_key, pk, _copy_key, _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_ec_private_key_init(
    oe_ec_private_key_t* private_key,
    const mbedtls_pk_context* pk)
{
    return oe_private_key_init(
        (oe_private_key_t*)private_key, pk, _copy_key, _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_ec_private_key_read_pem(
    oe_ec_private_key_t* private_key,
    const uint8_t* pem_data,
    size_t pem_size)
{
    return oe_private_key_read_pem(
        pem_data,
        pem_size,
        (oe_private_key_t*)private_key,
        MBEDTLS_PK_ECKEY,
        _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_ec_private_key_write_pem(
    const oe_ec_private_key_t* private_key,
    uint8_t* pem_data,
    size_t* pem_size)
{
    return oe_private_key_write_pem(
        (const oe_private_key_t*)private_key,
        pem_data,
        pem_size,
        _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_ec_public_key_read_pem(
    oe_ec_public_key_t* private_key,
    const uint8_t* pem_data,
    size_t pem_size)
{
    return oe_public_key_read_pem(
        pem_data,
        pem_size,
        (oe_public_key_t*)private_key,
        MBEDTLS_PK_ECKEY,
        _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_ec_public_key_write_pem(
    const oe_ec_public_key_t* private_key,
    uint8_t* pem_data,
    size_t* pem_size)
{
    return oe_public_key_write_pem(
        (const oe_public_key_t*)private_key,
        pem_data,
        pem_size,
        _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_ec_private_key_free(oe_ec_private_key_t* private_key)
{
    return oe_private_key_free(
        (oe_private_key_t*)private_key, _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_ec_public_key_free(oe_ec_public_key_t* public_key)
{
    return oe_public_key_free((oe_public_key_t*)public_key, _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_ec_private_key_sign(
    const oe_ec_private_key_t* private_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    uint8_t* signature,
    size_t* signature_size)
{
    return oe_private_key_sign(
        (oe_private_key_t*)private_key,
        hash_type,
        hash_data,
        hash_size,
        signature,
        signature_size,
        _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_ec_public_key_verify(
    const oe_ec_public_key_t* public_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    const uint8_t* signature,
    size_t signature_size)
{
    return oe_public_key_verify(
        (oe_public_key_t*)public_key,
        hash_type,
        hash_data,
        hash_size,
        signature,
        signature_size,
        _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_ec_generate_key_pair_from_private(
    oe_ec_type_t curve,
    const uint8_t* private_key_buf,
    size_t private_key_buf_size,
    oe_ec_private_key_t* private_key,
    oe_ec_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    int mbedtls_result;
    mbedtls_pk_context key;
    mbedtls_ecp_keypair* keypair;
    mbedtls_ctr_drbg_context* drbg;

    mbedtls_pk_init(&key);

    /* Reject invalid parameters */
    if (!private_key_buf || !private_key || !public_key)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Load all the mbedtls variables. */
    mbedtls_result =
        mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (mbedtls_result != 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "mbedtls error: 0x%x", mbedtls_result);

    keypair = mbedtls_pk_ec(key);
    mbedtls_result =
        mbedtls_ecp_group_load(&keypair->grp, _get_group_id(curve));
    if (mbedtls_result != 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "mbedtls error: 0x%x", mbedtls_result);

    mbedtls_result = mbedtls_mpi_read_binary(
        &keypair->d, private_key_buf, private_key_buf_size);

    if (mbedtls_result != 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "mbedtls error: 0x%x", mbedtls_result);

    mbedtls_result = mbedtls_ecp_check_privkey(&keypair->grp, &keypair->d);
    if (mbedtls_result != 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "mbedtls error: 0x%x", mbedtls_result);

    if (!(drbg = oe_mbedtls_get_drbg()))
        OE_RAISE(OE_CRYPTO_ERROR);

    /*
     * To get the public key, we perform the elliptical curve point
     * multiplication with the factors being the private key and the base
     * generator point of the curve.
     */
    mbedtls_result = mbedtls_ecp_mul(
        &keypair->grp,
        &keypair->Q,
        &keypair->d,
        &keypair->grp.G,
        mbedtls_ctr_drbg_random,
        drbg);

    if (mbedtls_result != 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "mbedtls error: 0x%x", mbedtls_result);

    mbedtls_result = mbedtls_ecp_check_pubkey(&keypair->grp, &keypair->Q);
    if (mbedtls_result != 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "mbedtls error: 0x%x", mbedtls_result);

    /* Export to OE structs. */
    OE_CHECK(oe_ec_public_key_init(public_key, &key));
    result = oe_ec_private_key_init(private_key, &key);
    if (result != OE_OK)
    {
        /* Need to free the public key before exiting. */
        oe_ec_public_key_free(public_key);
        OE_RAISE(result);
    }

    result = OE_OK;

done:
    mbedtls_pk_free(&key);
    return result;
}

oe_result_t oe_ec_public_key_equal(
    const oe_ec_public_key_t* public_key1,
    const oe_ec_public_key_t* public_key2,
    bool* equal)
{
    return oe_public_key_equal(
        (oe_public_key_t*)public_key1, (oe_public_key_t*)public_key2, equal);
}

oe_result_t oe_ec_public_key_from_coordinates(
    oe_ec_public_key_t* public_key,
    oe_ec_type_t ec_type,
    const uint8_t* x_data,
    size_t x_size,
    const uint8_t* y_data,
    size_t y_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_public_key_t* impl = (oe_public_key_t*)public_key;
    const mbedtls_pk_info_t* info = NULL;
    int rc = 0;

    if (public_key)
        oe_secure_zero_fill(public_key, sizeof(oe_ec_public_key_t));

    if (impl)
        mbedtls_pk_init(&impl->pk);

    /* Reject invalid parameters */
    if (!public_key || !x_data || !x_size || !y_data || !y_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Lookup the info for this key type */
    if (!(info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)))
        OE_RAISE(OE_PUBLIC_KEY_NOT_FOUND);

    /* Setup the context for this key type */
    rc = mbedtls_pk_setup(&impl->pk, info);
    if (rc != 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "rc = 0x%x", rc);

    /* Initialize the key */
    {
        mbedtls_ecp_keypair* ecp = mbedtls_pk_ec(impl->pk);
        mbedtls_ecp_group_id group_id;

        if ((group_id = _get_group_id(ec_type)) == MBEDTLS_ECP_DP_NONE)
            OE_RAISE(OE_FAILURE);

        if (mbedtls_ecp_group_load(&ecp->grp, group_id) != 0)
            OE_RAISE(OE_CRYPTO_ERROR);

        if (mbedtls_mpi_read_binary(&ecp->Q.X, x_data, x_size) != 0)
            OE_RAISE(OE_CRYPTO_ERROR);

        if (mbedtls_mpi_read_binary(&ecp->Q.Y, y_data, y_size) != 0)
            OE_RAISE(OE_CRYPTO_ERROR);

        // Used internally by MBEDTLS. Set Z to 1 to indicate that X-Y
        // represents a standard coordinate point. Zero indicates that the
        // point is zero or infinite, and values >= 2 have internal meaning
        // only to MBEDTLS.
        if (mbedtls_mpi_lset(&ecp->Q.Z, 1) != 0)
            OE_RAISE(OE_CRYPTO_ERROR);
    }

    /* Set the magic number */
    impl->magic = _PUBLIC_KEY_MAGIC;

    result = OE_OK;

done:

    if (result != OE_OK && impl)
        mbedtls_pk_free(&impl->pk);

    return result;
}

oe_result_t oe_ecdsa_signature_write_der(
    unsigned char* signature,
    size_t* signature_size,
    const uint8_t* data,
    size_t size,
    const uint8_t* s_data,
    size_t s_size)
{
    oe_result_t result = OE_UNEXPECTED;
    mbedtls_mpi r;
    mbedtls_mpi s;
    unsigned char buf[MBEDTLS_ECDSA_MAX_LEN];
    unsigned char* p = buf + sizeof(buf);
    int n;
    size_t len = 0;

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    /* Reject invalid parameters */
    if (!signature_size || !data || !size || !s_data || !s_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If signature is null, then signature_size must be zero */
    if (!signature && *signature_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Convert raw R data to big number */
    if (mbedtls_mpi_read_binary(&r, data, size) != 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Convert raw S data to big number */
    if (mbedtls_mpi_read_binary(&s, s_data, s_size) != 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Write S to ASN.1 */
    {
        if ((n = mbedtls_asn1_write_mpi(&p, buf, &s)) < 0)
            OE_RAISE(OE_CRYPTO_ERROR);

        len += (size_t)n;
    }

    /* Write R to ASN.1 */
    {
        if ((n = mbedtls_asn1_write_mpi(&p, buf, &r)) < 0)
            OE_RAISE(OE_CRYPTO_ERROR);

        len += (size_t)n;
    }

    /* Write the length to ASN.1 */
    {
        if ((n = mbedtls_asn1_write_len(&p, buf, len)) < 0)
            OE_RAISE_MSG(OE_CRYPTO_ERROR, "n = 0x%x\n", n);

        len += (size_t)n;
    }

    /* Write the tag to ASN.1 */
    {
        unsigned char tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;

        if ((n = mbedtls_asn1_write_tag(&p, buf, tag)) < 0)
            OE_RAISE_MSG(OE_CRYPTO_ERROR, "n = 0x%x\n", n);

        len += (size_t)n;
    }

    /* Check that buffer is big enough */
    if (len > *signature_size)
    {
        *signature_size = len;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    OE_CHECK(oe_memcpy_s(signature, *signature_size, p, len));
    *signature_size = len;

    result = OE_OK;

done:

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return result;
}

bool oe_ec_valid_raw_private_key(
    oe_ec_type_t type,
    const uint8_t* key,
    size_t keysize)
{
    mbedtls_mpi num;
    mbedtls_ecp_group group;
    bool is_valid = false;
    int res;

    mbedtls_mpi_init(&num);
    mbedtls_ecp_group_init(&group);

    if (!key)
        goto done;

    res = mbedtls_mpi_read_binary(&num, key, keysize);
    if (res != 0)
    {
        OE_TRACE_ERROR("mbedtls_error = 0x%x", res);
        goto done;
    }

    res = mbedtls_ecp_group_load(&group, _get_group_id(type));
    if (res != 0)
    {
        OE_TRACE_ERROR("mbedtls_error = 0x%x", res);
        goto done;
    }

    res = mbedtls_ecp_check_privkey(&group, &num);
    if (res != 0)
    {
        OE_TRACE_ERROR("mbedtls_error = 0x%x", res);
        goto done;
    }

    is_valid = true;

done:
    mbedtls_ecp_group_free(&group);
    mbedtls_mpi_free(&num);
    return is_valid;
}
