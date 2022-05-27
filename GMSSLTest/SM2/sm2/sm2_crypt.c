/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "sm2.h"
//#include "sm2err.h"
#include "ec_int.h" /* ecdh_KDF_X9_63() */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <string.h>


typedef struct SM2_Ciphertext_st SM2_Ciphertext;
DECLARE_ASN1_FUNCTIONS(SM2_Ciphertext)

struct SM2_Ciphertext_st {
    BIGNUM *C1x;
    BIGNUM *C1y;
    ASN1_OCTET_STRING *C3;
    ASN1_OCTET_STRING *C2;
};

ASN1_SEQUENCE(SM2_Ciphertext) = {
    ASN1_SIMPLE(SM2_Ciphertext, C1x, BIGNUM),
    ASN1_SIMPLE(SM2_Ciphertext, C1y, BIGNUM),
    ASN1_SIMPLE(SM2_Ciphertext, C3, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SM2_Ciphertext, C2, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(SM2_Ciphertext)

IMPLEMENT_ASN1_FUNCTIONS(SM2_Ciphertext)

static size_t ec_field_size(const EC_GROUP *group)
{
    /* Is there some simpler way to do this? */
    BIGNUM *p = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    size_t field_size = 0;

    if (p == NULL || a == NULL || b == NULL)
       goto done;
    
    if (!EC_GROUP_get_curve_GF2m(group, p, a, b, NULL)) {
        goto done;
    }
    
    
    if (!EC_GROUP_get_curve_GFp(group, p, a, b, NULL)) {
        goto done;
    }
    
//
//    if (!EC_GROUP_get_curve(group, p, a, b, NULL))
//        goto done;
    field_size = (BN_num_bits(p) + 7) / 8;

 done:
    BN_free(p);
    BN_free(a);
    BN_free(b);

    return field_size;
}

int sm2_plaintext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len,
                       size_t *pt_size)
{
    const size_t field_size = ec_field_size(EC_KEY_get0_group(key));
    const int md_size = EVP_MD_size(digest);
    size_t overhead;

    if (md_size < 0) {
        SM2err(SM2_F_SM2_PLAINTEXT_SIZE, SM2_R_INVALID_DIGEST);
        return 0;
    }
    if (field_size == 0) {
        SM2err(SM2_F_SM2_PLAINTEXT_SIZE, SM2_R_INVALID_FIELD);
        return 0;
    }

    overhead = 10 + 2 * field_size + (size_t)md_size;
    if (msg_len <= overhead) {
        SM2err(SM2_F_SM2_PLAINTEXT_SIZE, SM2_R_INVALID_ENCODING);
        return 0;
    }

    *pt_size = msg_len - overhead;
    return 1;
}

int sm2_ciphertext_size_yy(const EC_KEY *key, const EVP_MD *digest, size_t msg_len,
                        size_t *ct_size)
{
    const size_t field_size = ec_field_size(EC_KEY_get0_group(key));
    const int md_size = EVP_MD_size(digest);
    size_t sz;

    if (field_size == 0 || md_size < 0)
        return 0;

    /* Integer and string are simple type; set constructed = 0, means primitive and definite length encoding. */
    sz = 2 * ASN1_object_size(0, field_size + 1, V_ASN1_INTEGER)
         + ASN1_object_size(0, md_size, V_ASN1_OCTET_STRING)
         + ASN1_object_size(0, msg_len, V_ASN1_OCTET_STRING);
    /* Sequence is structured type; set constructed = 1, means constructed and definite length encoding. */
    *ct_size = ASN1_object_size(1, sz, V_ASN1_SEQUENCE);

    return 1;
}

