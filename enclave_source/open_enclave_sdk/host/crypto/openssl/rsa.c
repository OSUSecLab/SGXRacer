// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/raise.h>
#include <openenclave/internal/rsa.h>
#include <openenclave/internal/utils.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "../magic.h"
#include "../rsa.h"
#include "init.h"
#include "key.h"
#include "rsa.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L
/* Needed for compatibility with ssl1.1 */

static void RSA_get0_key(
    const RSA* r,
    const BIGNUM** n,
    const BIGNUM** e,
    const BIGNUM** d)
{
    if (n != NULL)
        *n = r->n;
    if (e != NULL)
        *e = r->e;
    if (d != NULL)
        *d = r->d;
}

static int RSA_set0_key(RSA* r, BIGNUM* n, BIGNUM* e, BIGNUM* d)
{
    /* If the fields n and e in r are NULL, the corresponding input
     * parameters MUST be non-NULL for n and e.  d may be
     * left NULL (in case only the public key is used).
     */
    if ((r->n == NULL && n == NULL) || (r->e == NULL && e == NULL))
        return 0;

    if (n != NULL)
    {
        BN_free(r->n);
        r->n = n;
    }
    if (e != NULL)
    {
        BN_free(r->e);
        r->e = e;
    }
    if (d != NULL)
    {
        BN_free(r->d);
        r->d = d;
    }

    return 1;
}

#endif

OE_STATIC_ASSERT(sizeof(oe_public_key_t) <= sizeof(oe_rsa_public_key_t));
OE_STATIC_ASSERT(sizeof(oe_private_key_t) <= sizeof(oe_rsa_private_key_t));

static oe_result_t _private_key_write_pem_callback(BIO* bio, EVP_PKEY* pkey)
{
    oe_result_t result = OE_UNEXPECTED;
    RSA* rsa = NULL;

    if (!(rsa = EVP_PKEY_get1_RSA(pkey)))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, 0, NULL))
        OE_RAISE(OE_CRYPTO_ERROR);

    result = OE_OK;

done:

    if (rsa)
        RSA_free(rsa);

    return result;
}

static oe_result_t _get_public_key_get_modulus_or_exponent(
    const oe_public_key_t* public_key,
    uint8_t* buffer,
    size_t* buffer_size,
    bool get_modulus)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t required_size;
    const BIGNUM* bn;
    RSA* rsa = NULL;

    /* Check for invalid parameters */
    if (!public_key || !buffer_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then buffer_size must be zero */
    if (!buffer && *buffer_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get RSA key */
    if (!(rsa = EVP_PKEY_get1_RSA(public_key->pkey)))
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Select modulus or exponent */
    const BIGNUM* e;
    const BIGNUM* n;
    RSA_get0_key(rsa, &n, &e, NULL);
    bn = get_modulus ? n : e;

    /* Determine the required size in bytes */
    {
        int n = BN_num_bytes(bn);

        if (n <= 0)
            OE_RAISE(OE_CRYPTO_ERROR);

        /* Add one leading byte for the leading zero byte */
        required_size = (size_t)n;
    }

    /* If buffer is null or not big enough */
    if (!buffer || (*buffer_size < required_size))
    {
        *buffer_size = required_size;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /* Copy key bytes to the caller's buffer */
    if (!BN_bn2bin(bn, buffer))
        OE_RAISE(OE_CRYPTO_ERROR);

    *buffer_size = required_size;

    result = OE_OK;

done:

    if (rsa)
        RSA_free(rsa);

    return result;
}

static oe_result_t _public_key_get_modulus(
    const oe_public_key_t* public_key,
    uint8_t* buffer,
    size_t* buffer_size)
{
    return _get_public_key_get_modulus_or_exponent(
        public_key, buffer, buffer_size, true);
}

static oe_result_t _public_key_get_exponent(
    const oe_public_key_t* public_key,
    uint8_t* buffer,
    size_t* buffer_size)
{
    return _get_public_key_get_modulus_or_exponent(
        public_key, buffer, buffer_size, false);
}

static oe_result_t _public_key_equal(
    const oe_public_key_t* public_key1,
    const oe_public_key_t* public_key2,
    bool* equal)
{
    oe_result_t result = OE_UNEXPECTED;
    RSA* rsa1 = NULL;
    RSA* rsa2 = NULL;

    if (equal)
        *equal = false;

    /* Reject bad parameters */
    if (!oe_public_key_is_valid(public_key1, OE_RSA_PUBLIC_KEY_MAGIC) ||
        !oe_public_key_is_valid(public_key2, OE_RSA_PUBLIC_KEY_MAGIC) || !equal)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!(rsa1 = EVP_PKEY_get1_RSA(public_key1->pkey)))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!(rsa2 = EVP_PKEY_get1_RSA(public_key2->pkey)))
        OE_RAISE(OE_INVALID_PARAMETER);

    const BIGNUM* e1;
    const BIGNUM* e2;
    const BIGNUM* n1;
    const BIGNUM* n2;
    RSA_get0_key(rsa1, &n1, &e1, NULL);
    RSA_get0_key(rsa2, &n2, &e2, NULL);

    /* Compare modulus and exponent */
    if (BN_cmp(n1, n2) == 0 && BN_cmp(e1, e2) == 0)
        *equal = true;

    result = OE_OK;

done:

    if (rsa1)
        RSA_free(rsa1);

    if (rsa2)
        RSA_free(rsa2);

    return result;
}

void oe_rsa_public_key_init(oe_rsa_public_key_t* public_key, EVP_PKEY* pkey)
{
    oe_public_key_init(
        (oe_public_key_t*)public_key, pkey, OE_RSA_PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_private_key_read_pem(
    oe_rsa_private_key_t* private_key,
    const uint8_t* pem_data,
    size_t pem_size)
{
    return oe_private_key_read_pem(
        pem_data,
        pem_size,
        (oe_private_key_t*)private_key,
        EVP_PKEY_RSA,
        OE_RSA_PRIVATE_KEY_MAGIC);
}

oe_result_t oe_rsa_private_key_write_pem(
    const oe_rsa_private_key_t* private_key,
    uint8_t* pem_data,
    size_t* pem_size)
{
    return oe_private_key_write_pem(
        (const oe_private_key_t*)private_key,
        pem_data,
        pem_size,
        _private_key_write_pem_callback,
        OE_RSA_PRIVATE_KEY_MAGIC);
}

oe_result_t oe_rsa_public_key_read_pem(
    oe_rsa_public_key_t* public_key,
    const uint8_t* pem_data,
    size_t pem_size)
{
    return oe_public_key_read_pem(
        pem_data,
        pem_size,
        (oe_public_key_t*)public_key,
        EVP_PKEY_RSA,
        OE_RSA_PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_public_key_write_pem(
    const oe_rsa_public_key_t* public_key,
    uint8_t* pem_data,
    size_t* pem_size)
{
    return oe_public_key_write_pem(
        (const oe_public_key_t*)public_key,
        pem_data,
        pem_size,
        OE_RSA_PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_private_key_free(oe_rsa_private_key_t* private_key)
{
    return oe_private_key_free(
        (oe_private_key_t*)private_key, OE_RSA_PRIVATE_KEY_MAGIC);
}

oe_result_t oe_rsa_public_key_free(oe_rsa_public_key_t* public_key)
{
    return oe_public_key_free(
        (oe_public_key_t*)public_key, OE_RSA_PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_private_key_sign(
    const oe_rsa_private_key_t* private_key,
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
        OE_RSA_PRIVATE_KEY_MAGIC);
}

oe_result_t oe_rsa_public_key_verify(
    const oe_rsa_public_key_t* public_key,
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
        OE_RSA_PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_public_key_get_modulus(
    const oe_rsa_public_key_t* public_key,
    uint8_t* buffer,
    size_t* buffer_size)
{
    return _public_key_get_modulus(
        (oe_public_key_t*)public_key, buffer, buffer_size);
}

oe_result_t oe_rsa_public_key_get_exponent(
    const oe_rsa_public_key_t* public_key,
    uint8_t* buffer,
    size_t* buffer_size)
{
    return _public_key_get_exponent(
        (oe_public_key_t*)public_key, buffer, buffer_size);
}

oe_result_t oe_rsa_public_key_equal(
    const oe_rsa_public_key_t* public_key1,
    const oe_rsa_public_key_t* public_key2,
    bool* equal)
{
    return _public_key_equal(
        (oe_public_key_t*)public_key1, (oe_public_key_t*)public_key2, equal);
}

oe_result_t oe_rsa_get_public_key_from_private(
    const oe_rsa_private_key_t* private_key,
    oe_rsa_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_private_key_t* private_key_temp = (oe_private_key_t*)private_key;
    RSA* rsa_private = NULL;
    RSA* rsa_public = NULL;
    EVP_PKEY* rsa_public_pkey = NULL;
    const BIGNUM* private_e = NULL;
    const BIGNUM* private_n = NULL;
    const BIGNUM* public_e = NULL;
    const BIGNUM* public_n = NULL;

    /* Check for invalid parameters */
    if (!private_key || !public_key)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get RSA private key */
    if (!(rsa_private = EVP_PKEY_get1_RSA(private_key_temp->pkey)))
        OE_RAISE(OE_CRYPTO_ERROR);

    RSA_get0_key(rsa_private, &private_e, &private_n, NULL);

    /* Check if it's possible to get the public key. */
    if (!private_e || !private_n)
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Create RSA public key. */
    if (!(rsa_public = RSA_new()))
        OE_RAISE(OE_CRYPTO_ERROR);

    RSA_get0_key(rsa_private, &public_e, &public_n, NULL);

    if (!public_e)
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!public_n)
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!RSA_set0_key(rsa_public, BN_dup(public_e), BN_dup(public_n), NULL))
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Init the OE public key type. */
    if (!(rsa_public_pkey = EVP_PKEY_new()))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (EVP_PKEY_set1_RSA(rsa_public_pkey, rsa_public) == 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    oe_rsa_public_key_init(public_key, rsa_public_pkey);

    result = OE_OK;
    rsa_public_pkey = NULL;

done:
    if (rsa_public_pkey)
        EVP_PKEY_free(rsa_public_pkey);

    if (rsa_public)
        RSA_free(rsa_public);

    if (rsa_private)
        RSA_free(rsa_private);

    return result;
}
