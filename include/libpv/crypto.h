/*
 * General cryptography helper functions and definitions
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#pragma once

#include "libpv/common.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

typedef struct pv_cipher_parms {
	const EVP_CIPHER *cipher;
	size_t tag_size;
	GBytes *key;
	union {
		GBytes *iv;
		GBytes *tweak;
	};
} PvCipherParms;

typedef union {
	struct {
		uint8_t x[80];
		uint8_t y[80];
	};
	uint8_t data[160];
} PvEcdhPubKey;
G_STATIC_ASSERT(sizeof(PvEcdhPubKey) == 160);

typedef GSList PvEvpKeyList;

enum PvCryptoMode {
	PV_ENCRYPT,
	PV_DECRYPT,
	PV_NO_OP,
};

/**
 * pv_generate_rand_data:
 * @size: number of generated random bytes using a crypographically secure pseudo random generator
 * @error: return location for a #GError
 *
 * Creates a new #GBytes with @size random bytes using a cryptographically
 * secure pseudo random generator.
 *
 * Returns: (nullable) (transfer full): a new #GBytes, or %NULL in case of an error
 */
GBytes *pv_generate_rand_data(guint size, GError **error) PV_NONNULL(2);

/**
 * pv_generate_key:
 * @cipher: specifies the OpenSSL cipher for which a cryptographically secure key should be generated
 * @error: return location for a #GError
 *
 * Creates a random key for @cipher using a cryptographically secure pseudo
 * random generator.
 *
 * Returns: (nullable) (transfer full): a new #GBytes, or %NULL in case of an error
 */
GBytes *pv_generate_key(const EVP_CIPHER *cipher, GError **error)
	PV_NONNULL(1, 2);

/**
 * pv_generate_iv:
 * @cipher: specifies the OpenSSL cipher for which a cryptographically secure IV should be generated
 * @error: return location for a #GError
 *
 * Creates a random IV for @cipher using a cryptographically secure pseudo
 * random generator.
 *
 * Returns: (nullable) (transfer full): a new #GBytes, or %NULL in case of an error
 */
GBytes *pv_generate_iv(const EVP_CIPHER *cipher, GError **error)
	PV_NONNULL(1, 2);

/* Symmetric en/decryption functions */

/**
 * pv_gcm_encrypt:
 * @plain: data to encrypt
 * @aad: (optional): additional data that should be authenticated with the key
 * @parms:
 * @cipher: (out): location to store the ciphertext
 * @tag: (out): location to store the generated GCM tag
 * @error: return location for a #GError
 *
 * Encrypts the @plain data and authenticates @aad data.
 *
 * Returns: number of bytes, or -1 in case of an error
 */
int64_t pv_gcm_encrypt(GBytes *plain, GBytes *aad, const PvCipherParms *parms,
		       GBytes **cipher, GBytes **tag, GError **error)
	PV_NONNULL(1, 3, 4, 5, 6);

/**
 * pv_gcm_decrypt:
 * @cipher: ciphertext to decrypt
 * @aad: (optional): additional date to authenticate
 * @tag: the GCM tag
 * @parms:
 * @plain: (out): location to store the decrypted data
 * @error: return location for a #GError
 *
 * Decrypts the @cipher data and authenticates the @aad data.
 *
 * Returns: number of bytes, or -1 in case of an error
 */
int64_t pv_gcm_decrypt(GBytes *cipher, GBytes *aad, GBytes *tag,
		       const PvCipherParms *parms, GBytes **plain,
		       GError **error) PV_NONNULL(1, 3, 4, 5, 6);

/** pv_encrypt_file:
 * @parms:
 * @path_in: plain input file path
 * @path_out: decrypted output file path
 * @in_size: (out): location to store the input file size
 * @out_size: (out): location to store the output file size
 * @error: return location for a #GError
 *
 * Encrypts the content of @path_in and stores it in @path_out.
 *
 * Returns: 0 in case of success or -1 otherwise
 */
int pv_encrypt_file(const PvCipherParms *parms, const char *path_in,
		    const char *path_out, size_t *in_size, size_t *out_size,
		    GError **error) PV_NONNULL(1, 2, 3, 4, 5, 6);

/** pv_decrypt_file:
 * @parms:
 * @path_in: decrypted input file path
 * @path_out: plain output file path
 * @in_size: (out): location to store the input file size
 * @out_size: (out): location to store the output file size
 * @error: return location for a #GError
 *
 * Decrypts the content of @path_in and stores it in @path_out.
 *
 * Returns: 0 in case of success or -1 otherwise
 */
int pv_decrypt_file(const PvCipherParms *parms, const char *path_in,
		    const char *path_out, size_t *in_size, size_t *out_size,
		    GError **error) PV_NONNULL(1, 2, 3, 4, 5, 6);

/** pv_encrypt_buf:
 * @parms:
 * @in: plain input buffer
 * @error: return location for a #GError
 *
 * Encrypts the content of @in and returns it.
 *
 * Returns: (nullable) (transfer full): Encrypted data from @in or NULL in case of error.
 */
GBytes *pv_encrypt_buf(const PvCipherParms *parms, GBytes *in, GError **error)
	PV_NONNULL(1, 2, 3);

/** pv_decrypt_buf:
 * @parms:
 * @in: decrypted input buffer
 * @error: return location for a #GError
 *
 * Decrypts the content of @in and returns it.
 *
 * Returns: (nullable) (transfer full): Decrypted data from @in or NULL in case of error.
 */
GBytes *pv_decrypt_buf(const PvCipherParms *parms, GBytes *in, GError **error)
	PV_NONNULL(1, 2, 3);

/**
 * pv_read_data:
 * @input: Input
 * @output: Output
 * @len: Read @len bytes
 *
 * Read data from @input and write it to @output.
 *
 * Returns: The number of bytes read for success, -1 if an error occurred
 */
int pv_read_data(BIO *input, BIO *output, int len) PV_NONNULL(1, 2);

/** pv_hkdf_extract_and_expand:
 * @derived_key_len: size of the output key
 * @key: input key
 * @salt: salt for the extraction
 * @info: infor for the expansion
 * @md: EVP mode of operation
 * @error: return location for a #GError
 *
 * Performs a RFC 5869 HKDF.
 *
 * Returns: (nullable) (transfer full): Result of RFC 5869 HKDF
 *
 */
GBytes *pv_hkdf_extract_and_expand(size_t derived_key_len, GBytes *key,
				   GBytes *salt, GBytes *info, const EVP_MD *md,
				   GError **error) PV_NONNULL(2, 3, 4, 5);

/** pv_generate_ec_key:
 *
 * @nid: Numerical identifier of the curve
 * @error: return location for a #GError
 *
 * Returns: (nullable) (transfer full): new random key based on the given curve
 */
EVP_PKEY *pv_generate_ec_key(int nid, GError **error) PV_NONNULL(2);

/** pv_evp_pkey_to_ecdh_pub_key:
 *
 * @key: input key in EVP_PKEY format
 * @error: return location for a #GError
 *
 * Returns: the public part of the input @key in ECDH format.
 */
PvEcdhPubKey *pv_evp_pkey_to_ecdh_pub_key(const EVP_PKEY *key, GError **error)
	PV_NONNULL(1, 2);

/** pv_compute_exchange_key:
 * @cust: Customer Key
 * @host: Host key
 * @error: return location for a #GError
 *
 * Returns: (nullable) (transfer full): Shared Secret of @cust and @host
 */
GBytes *pv_compute_exchange_key(const EVP_PKEY *cust, const EVP_PKEY *host,
				GError **error) PV_NONNULL(1, 2, 3);

GQuark pv_crypto_error_quark(void);
#define PV_CRYPTO_ERROR pv_crypto_error_quark()
typedef enum {
	PV_CRYPTO_ERROR_DERIVE,
	PV_CRYPTO_ERROR_HKDF_FAIL,
	PV_CRYPTO_ERROR_INTERNAL,
	PV_CRYPTO_ERROR_INVALID_KEY_SIZE,
	PV_CRYPTO_ERROR_KEYGENERATION,
	PV_CRYPTO_ERROR_RANDOMIZATION,
	PV_CRYPTO_ERROR_READ_FILE,
	PV_CRYPTO_ERROR_NO_IBM_Z_SIGNING_KEY,
	PV_CRYPTO_ERROR_NO_MATCH_TAG,
} PvCryptoErrors;

WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(ASN1_INTEGER, ASN1_INTEGER_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(ASN1_OCTET_STRING, ASN1_OCTET_STRING_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(BIO, BIO_free_all)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(BIGNUM, BN_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(BN_CTX, BN_CTX_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(EC_GROUP, EC_GROUP_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(EC_KEY, EC_KEY_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(EC_POINT, EC_POINT_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_CIPHER_CTX, EVP_CIPHER_CTX_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_PKEY, EVP_PKEY_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_PKEY_CTX, EVP_PKEY_CTX_free)

/* --- */

typedef struct _pv_crypto_ctx PvCryptoCtx;
/** pv_crypto_ctx_new:
 *
 * @cipher: Cipher to use in the context
 * @key: crypto key to use in the context
 * @mode: en- or decryption
 * @input: first Input
 *
 * Returns: (nullable) (transfer full): nex Crypto context
 */
PvCryptoCtx *pv_crypto_ctx_new(const EVP_CIPHER *cipher, GBytes *key,
			       enum PvCryptoMode mode, BIO *input)
	PV_NONNULL(1, 2);

void pv_crypto_ctx_free(PvCryptoCtx *ctx);

gboolean pv_crypto_ctx_set_input(PvCryptoCtx *ctx, BIO *input) PV_NONNULL(1, 2);

BIO *pv_crypto_ctx_rm_input(PvCryptoCtx *ctx) PV_NONNULL(1);

WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(PvCryptoCtx, pv_crypto_ctx_free)
