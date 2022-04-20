/*
 * Cryptography functions
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include "config.h"

#include <openssl/bio.h>

#include <openssl/rand.h>

#include <openssl/crypto.h>
#include <stdbool.h>
#include <stdarg.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>

#include "lib/zt_common.h"

#include "libpv/crypto.h"
#include "libpv/glib-helper.h"
#include "libpv/hash.h"

#include "cdef.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

GBytes *pv_generate_rand_data(guint size, GError **error)
{
	g_autofree unsigned char *data = NULL;

	if (size > INT_MAX) {
		g_set_error_literal(
			error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_RANDOMIZATION,
			"Too many random data requested. Split it up.");
		OPENSSL_clear_free(data, size);
		return NULL;
	}

	/* OPENSSL_secure_free is not available?!?!? */
	data = g_malloc(size);
	if (RAND_bytes(data, (int)size) != 1) {
		g_set_error_literal(
			error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_RANDOMIZATION,
			"The required amount of random data is not available");
		return NULL;
	}

	return pv_sec_gbytes_new_take(g_steal_pointer(&data), size);
}

GBytes *pv_generate_key(const EVP_CIPHER *cipher, GError **error)
{
	int size;

	size = EVP_CIPHER_key_length(cipher);
	if (size <= 0) {
		g_set_error(error, PV_CRYPTO_ERROR,
			    PV_CRYPTO_ERROR_KEYGENERATION, "Unknown cipher.");
		return NULL;
	}

	return pv_generate_rand_data((guint)size, error);
}

GBytes *pv_generate_iv(const EVP_CIPHER *cipher, GError **error)
{
	int size;

	size = EVP_CIPHER_iv_length(cipher);
	if (size <= 0) {
		g_set_error(error, PV_CRYPTO_ERROR,
			    PV_CRYPTO_ERROR_KEYGENERATION, "Unknown cipher.");
		return NULL;
	}

	return pv_generate_rand_data((guint)size, error);
}

static int64_t pv_gcm_encrypt_decrypt(GBytes *input, GBytes *aad,
				      const PvCipherParms *parms,
				      GBytes **output, GBytes **tagp,
				      enum PvCryptoMode mode, GError **error)
{
	g_autoptr(EVP_CIPHER_CTX) ctx = NULL;
	const EVP_CIPHER *cipher = parms->cipher;
	bool encrypt = mode == PV_ENCRYPT;
	const GBytes *key = parms->key;
	const GBytes *iv = parms->iv;
	const size_t tag_size = parms->tag_size;
	int64_t ret = -1;
	int len = -1;
	GBytes *tag = *tagp;
	const uint8_t *in_data, *aad_data = NULL, *iv_data, *key_data;
	size_t in_size, aad_size = 0, iv_size, key_size, out_size;
	g_autofree uint8_t *out_data = NULL;
	g_autofree uint8_t *tag_data = NULL;
	int cipher_block_size;

	g_assert(cipher);
	g_assert(key);
	g_assert(iv);

	in_data = g_bytes_get_data((GBytes *)input, &in_size);
	if (aad)
		aad_data = g_bytes_get_data((GBytes *)aad, &aad_size);
	iv_data = g_bytes_get_data((GBytes *)iv, &iv_size);
	key_data = g_bytes_get_data((GBytes *)key, &key_size);
	out_size = in_size;
	cipher_block_size = EVP_CIPHER_block_size(cipher);

	/* Checks for later casts */
	g_assert(aad_size <= INT_MAX);
	g_assert(in_size <= INT_MAX);
	g_assert(iv_size <= INT_MAX);
	g_assert(cipher_block_size > 0);

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		g_abort();

	if (tag_size == 0 || (tag_size % (size_t)cipher_block_size != 0)) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    "Passed tag size is incorrect");
		return -1;
	}

	/* Has the passed key the correct size? */
	if (EVP_CIPHER_key_length(cipher) != (int)key_size) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    "Passed key has incorrect size");
		return -1;
	}

	/* First, set the cipher algorithm so we can verify our key/IV lengths
	 */
	if (EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, encrypt) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    "EVP_CIPHER_CTX_new failed");
		return -1;
	}

	/* Set IV length */
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_size,
				NULL) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    "EVP_CIPHER_CTX_ex failed");
		return -1;
	}

	/* Initialise key and IV */
	if (EVP_CipherInit_ex(ctx, NULL, NULL, key_data, iv_data, encrypt) !=
	    1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    "EVP_CipherInit_ex failed");
		return -1;
	}

	/* Allocate output data */
	out_data = g_malloc0(out_size);
	if (encrypt)
		tag_data = g_malloc0(tag_size);

	if (aad_size > 0) {
		/* Provide any AAD data */
		if (EVP_CipherUpdate(ctx, NULL, &len, aad_data,
				     (int)aad_size) != 1) {
			g_set_error(error, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    "EVP_CipherUpdate failed");
			return -1;
		}
		g_assert(len == (int)aad_size);
	}

	/* Provide data to be en/decrypted */
	if (EVP_CipherUpdate(ctx, out_data, &len, in_data, (int)in_size) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    "EVP_CipherUpdate failed");
		return -1;
	}
	ret = len;

	if (!encrypt) {
		const uint8_t *tmp_tag_data = NULL;
		size_t tmp_tag_size = 0;

		if (tag)
			tmp_tag_data = g_bytes_get_data(tag, &tmp_tag_size);
		if (tag_size != tmp_tag_size) {
			g_set_error(error, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    "Getting the GCM tag failed");
			return -1;
		}

		/* Set expected tag value */
		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
					(int)tmp_tag_size,
					(uint8_t *)tmp_tag_data) != 1) {
			g_set_error(error, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    "Setting the GCM tag failed");
			return -1;
		}
	}

	/* Finalize the en/decryption */
	if (EVP_CipherFinal_ex(ctx, (unsigned char *)out_data + len, &len) !=
	    1) {
		if (encrypt)
			g_set_error(error, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    "Encrypting failed (EVP_CipherFinal_ex)");
		else
			g_set_error(error, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_NO_MATCH_TAG,
				    "Verifying the GCM tag failed.");
		return -1;
	}
	ret += len;

	if (encrypt) {
		/* Get the tag */
		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
					(int)tag_size, tag_data) != 1) {
			g_set_error(error, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    "Getting the GCM tag failed");
			return -1;
		}

		g_assert(!*tagp);
		*tagp = g_bytes_new_take(g_steal_pointer(&tag_data), tag_size);
	}
	g_assert(ret == (int)out_size);
	g_assert(out_size == in_size);

	g_assert(!*output);
	*output = pv_sec_gbytes_new_take(g_steal_pointer(&out_data), out_size);
	return ret;
}

int64_t pv_gcm_encrypt(GBytes *plain, GBytes *aad, const PvCipherParms *parms,
		       GBytes **cipher, GBytes **tag, GError **error)
{
	return pv_gcm_encrypt_decrypt(plain, aad, parms, cipher, tag,
				      PV_ENCRYPT, error);
}

int64_t pv_gcm_decrypt(GBytes *cipher, GBytes *aad, GBytes *tag,
		       const PvCipherParms *parms, GBytes **plain,
		       GError **error)
{
	return pv_gcm_encrypt_decrypt(cipher, aad, parms, plain, &tag,
				      PV_DECRYPT, error);
}

static int __encrypt_decrypt_bio(const PvCipherParms *parms, BIO *b_in,
				 BIO *b_out, size_t *size_in, size_t *size_out,
				 gboolean encrypt, GError **error)
{
	int num_bytes_read, num_bytes_written;
	g_autoptr(EVP_CIPHER_CTX) ctx = NULL;
	g_autoptr(BIGNUM) tweak_num = NULL;
	const EVP_CIPHER *cipher = parms->cipher;
	int cipher_block_size = EVP_CIPHER_block_size(cipher);
	uint8_t in_buf[PAGE_SIZE],
		out_buf[PAGE_SIZE + (guint)cipher_block_size];
	const GBytes *key = parms->key;
	const GBytes *tweak = parms->tweak;
	g_autofree uint8_t *tmp_tweak = NULL;
	int out_len;
	size_t tweak_size;
	gconstpointer key_data;
	size_t tmp_size_in = 0, tmp_size_out = 0, key_size;

	g_assert(cipher_block_size > 0);
	g_assert(key);
	g_assert(tweak);
	g_assert(g_bytes_get_size((GBytes *)tweak) <= INT_MAX);

	key_data = g_bytes_get_data((GBytes *)key, &key_size);

	/* copy the value for leaving the original value untouched */
	tweak_size = g_bytes_get_size((GBytes *)tweak);
	tmp_tweak = g_malloc0(tweak_size);
	memcpy(tmp_tweak, g_bytes_get_data((GBytes *)tweak, NULL), tweak_size);
	tweak_num = BN_bin2bn(tmp_tweak, (int)tweak_size, NULL);
	if (!tweak_num) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("BN_bin2bn failed"));
		return -1;
	}

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		g_abort();

	/* don't set the key or tweak right away as we want to check
	 * lengths before
	 */
	if (EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, encrypt) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("EVP_CipherInit_ex failed"));
		return -1;
	}

	/* Now we can set the key and tweak */
	if (EVP_CipherInit_ex(ctx, NULL, NULL, key_data, tmp_tweak, encrypt) !=
	    1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("EVP_CipherInit_ex failed"));
		return -1;
	}

	do {
		memset(in_buf, 0, sizeof(in_buf));
		/* Read in data in 4096 bytes blocks. Update the ciphering
		 * with each read.
		 */
		num_bytes_read = BIO_read(b_in, in_buf, (int)PAGE_SIZE);
		if (num_bytes_read < 0) {
			g_set_error(error, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    _("Failed to read"));
			return -1;
		}
		tmp_size_in += (guint)num_bytes_read;

		/* in case we reached the end and it's not the special
		 * case of an empty component we can break here
		 */
		if (num_bytes_read == 0 && tmp_size_in != 0)
			break;

		if (EVP_CipherUpdate(ctx, out_buf, &out_len, in_buf,
				     num_bytes_read) != 1) {
			g_set_error(error, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    _("EVP_CipherUpdate failed"));
			return -1;
		}
		g_assert(out_len >= 0);

		num_bytes_written = BIO_write(b_out, out_buf, out_len);
		if (num_bytes_written < 0) {
			g_set_error(error, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    _("Failed to write"));
			return -1;
		}
		g_assert(num_bytes_written == out_len);

		tmp_size_out += (guint)num_bytes_written;

		/* Set new tweak value. Please keep in mind that the
		 * tweaks are stored in big-endian form. Therefore we
		 * must use the correct OpenSSL functions
		 */
		if (BN_add_word(tweak_num, PAGE_SIZE) != 1) {
			g_set_error(error, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    _("BN_add_word failed"));
			return -1;
		}
		g_assert(BN_num_bytes(tweak_num) > 0);
		g_assert(BN_num_bytes(tweak_num) <= (int)tweak_size);

		if (BN_bn2binpad(tweak_num, tmp_tweak, (int)tweak_size) < 0) {
			g_set_error(error, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    _("BN_bn2binpad failed"));
			return -1;
		};

		/* set new tweak */
		if (EVP_CipherInit_ex(ctx, NULL, NULL, NULL, tmp_tweak,
				      encrypt) != 1) {
			g_set_error(error, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    _("EVP_CipherInit_ex failed"));
			return -1;
		}
	} while (num_bytes_read == PAGE_SIZE);

	/* Now cipher the final block and write it out to file */
	if (EVP_CipherFinal_ex(ctx, out_buf, &out_len) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("EVP_CipherFinal_ex failed"));
		return -1;
	}
	g_assert(out_len >= 0);

	num_bytes_written = BIO_write(b_out, out_buf, out_len);
	if (num_bytes_written < 0) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Failed to write"));
		return -1;
	}
	g_assert(out_len == num_bytes_written);
	tmp_size_out += (guint)out_len;

	if (BIO_flush(b_out) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Failed to flush"));
		return -1;
	}

	*size_in = tmp_size_in;
	*size_out = tmp_size_out;
	return 0;
}

static int __encrypt_decrypt_file(const PvCipherParms *parms,
				  const char *path_in, const char *path_out,
				  size_t *size_in, size_t *size_out,
				  gboolean encrypt, GError **error)
{
	g_autoptr(BIO) b_out = NULL;
	g_autoptr(BIO) b_in = NULL;

	b_in = BIO_new_file(path_in, "rb");
	if (!b_in) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_READ_FILE,
			    _("Failed to read file '%s'"), path_in);
		return -1;
	}

	b_out = BIO_new_file(path_out, "wb");
	if (!b_out) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_READ_FILE,
			    _("Failed to write file '%s'"), path_out);
		return -1;
	}

	if (__encrypt_decrypt_bio(parms, b_in, b_out, size_in, size_out,
				  encrypt, error) < 0)
		return -1;

	return 0;
}

int pv_encrypt_file(const PvCipherParms *parms, const char *path_in,
		    const char *path_out, size_t *in_size, size_t *out_size,
		    GError **error)
{
	return __encrypt_decrypt_file(parms, path_in, path_out, in_size,
				      out_size, TRUE, error);
}

int pv_decrypt_file(const PvCipherParms *parms, const char *path_in,
		    const char *path_out, size_t *in_size, size_t *out_size,
		    GError **error)
{
	return __encrypt_decrypt_file(parms, path_in, path_out, in_size,
				      out_size, FALSE, error);
}

static GBytes *__encrypt_decrypt_buffer(const PvCipherParms *parms, GBytes *in,
					gboolean encrypt, GError **error)
{
	g_autoptr(BIO) b_out = NULL;
	g_autoptr(BIO) b_in = NULL;
	size_t in_size, out_size;
	gconstpointer in_data;
	char *data = NULL;
	long data_size;

	in_data = g_bytes_get_data(in, &in_size);

	g_assert(in_size <= INT_MAX);

	b_in = BIO_new_mem_buf(in_data, (int)in_size);
	if (!b_in)
		g_abort();

	b_out = BIO_new(BIO_s_mem());
	if (!b_out)
		g_abort();

	if (__encrypt_decrypt_bio(parms, b_in, b_out, &in_size, &out_size,
				  encrypt, error) < 0)
		return NULL;

	data_size = BIO_get_mem_data(b_out, &data);
	if (data_size < 0) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Could not read buffer"));
		return NULL;
	}

	return g_bytes_new(data, (size_t)data_size);
}

GBytes *pv_encrypt_buf(const PvCipherParms *parms, GBytes *in, GError **error)
{
	return __encrypt_decrypt_buffer(parms, in, TRUE, error);
}

GBytes *pv_decrypt_buf(const PvCipherParms *parms, GBytes *in, GError **error)
{
	return __encrypt_decrypt_buffer(parms, in, FALSE, error);
}

static BIO *pv_bio_cipher_new(const EVP_CIPHER *cipher, GBytes *key,
			      enum PvCryptoMode mode)
{
	g_autoptr(BIO) ret = NULL;
	const unsigned char *key_data;
	size_t key_len;
	/* TODO should we be able to select the engine used? */
	ENGINE *engine = NULL;
	/* TODO use of g_autoptr */
	EVP_CIPHER_CTX *ctx = NULL;
	bool encrypt = mode == PV_ENCRYPT;

	ret = BIO_new(BIO_f_cipher());
	if (!ret) {
		/* TODO set error */
		return NULL;
	}

	if (BIO_get_cipher_ctx(ret, &ctx) != 1) {
		/* TODO set error */
		return NULL;
	}
	g_assert(ctx);

	if (EVP_CipherInit_ex(ctx, cipher, engine, NULL, NULL, encrypt) != 1) {
		/* BIO_printf(bio_error, "Error setting cipher %s\n", */
		/*            EVP_CIPHER_get0_name(cipher)); */
		/* ERR_print_errors(bio_error); */
		/* TODO set error */
		return NULL;
	}

	/* Check key length */
	key_data = g_bytes_get_data(key, &key_len);
	if (key_len > INT_MAX) {
		/* TODO error handling */
		return NULL;
	}
	if (EVP_CIPHER_CTX_key_length(ctx) != (int)key_len) {
		/* TODO set error */
		return NULL;
	}

	/* Set key */
	if (EVP_CipherInit_ex(ctx, NULL, NULL, key_data, NULL, -1) != 1) {
		/* TODO set error */
		return NULL;
	}
	return g_steal_pointer(&ret);
}

int pv_read_data(BIO *input, BIO *output, int len)
{
	char data[4096];
	int rc;

	if (len != (int)G_N_ELEMENTS(data)) {
		return -1;
	}

	rc = BIO_read(input, data, (int)G_N_ELEMENTS(data));
	if (rc != len) {
		/* TODO Add BIO_should_retry */
		// TODO error.
		/* g_set_error(error, 12, 12, "placeholder error"); */
		return -1;
	}

	rc = BIO_write(output, data, G_N_ELEMENTS(data));
	if (rc != G_N_ELEMENTS(data)) {
		/* TODO Add BIO_should_retry */
		// TODO error.
		/* g_set_error(error, 12, 12, "placeholder error"); */
		return -1;
	}
	return rc;
}

GBytes *pv_hkdf_extract_and_expand(size_t derived_key_len, GBytes *key,
				   GBytes *salt, GBytes *info, const EVP_MD *md,
				   G_GNUC_UNUSED GError **error)
{
	const unsigned char *salt_data, *key_data, *info_data;
	g_autoptr(EVP_PKEY_CTX) ctx = NULL;
	size_t salt_len, key_len, info_len;
	g_autofree unsigned char *derived_key = NULL;

	g_assert(derived_key_len > 0);

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (!ctx)
		g_abort();

	if (EVP_PKEY_derive_init(ctx) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_HKDF_FAIL,
			    "FAILED to derive key via HKDF");
		return NULL;
	}

	if (EVP_PKEY_CTX_hkdf_mode(
		    ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_HKDF_FAIL,
			    "FAILED to derive key via HKDF");
		return NULL;
	}

	if (EVP_PKEY_CTX_set_hkdf_md(ctx, md) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_HKDF_FAIL,
			    "FAILED to derive key via HKDF");
		return NULL;
	}

	salt_data = g_bytes_get_data(salt, &salt_len);
	if (salt_len > INT_MAX) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_HKDF_FAIL,
			    "FAILED to derive key via HKDF");
		return NULL;
	}

	if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt_data, (int)salt_len) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_HKDF_FAIL,
			    "FAILED to derive key via HKDF");
		return NULL;
	}

	key_data = g_bytes_get_data(key, &key_len);
	if (key_len > INT_MAX) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_HKDF_FAIL,
			    "FAILED to derive key via HKDF");
		return NULL;
	}

	if (EVP_PKEY_CTX_set1_hkdf_key(ctx, key_data, (int)key_len) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_HKDF_FAIL,
			    "FAILED to derive key via HKDF");
		return NULL;
	}

	info_data = g_bytes_get_data(info, &info_len);
	if (info_len > INT_MAX) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_HKDF_FAIL,
			    "FAILED to derive key via HKDF");
		return NULL;
	}

	if (EVP_PKEY_CTX_add1_hkdf_info(ctx, (unsigned char *)info_data,
					(int)info_len) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_HKDF_FAIL,
			    "FAILED to derive key via HKDF");
		return NULL;
	}

	derived_key = g_malloc0(derived_key_len);
	if (EVP_PKEY_derive(ctx, derived_key, &derived_key_len) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_HKDF_FAIL,
			    "FAILED to derive key via HKDF");
		printf("%s\n", get_openssl_error());
		return NULL;
	}

	return pv_sec_gbytes_new_take(g_steal_pointer(&derived_key),
				      derived_key_len);
}

EVP_PKEY *pv_generate_ec_key(int nid, GError **error)
{
	g_autoptr(EVP_PKEY_CTX) ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	g_autoptr(EVP_PKEY) ret = NULL;

	if (!ctx)
		g_abort();

	if (EVP_PKEY_keygen_init(ctx) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR,
			    PV_CRYPTO_ERROR_KEYGENERATION,
			    _("EC key could not be auto-generated"));
		return NULL;
	}

	if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR,
			    PV_CRYPTO_ERROR_KEYGENERATION,
			    _("EC key could not be auto-generated"));
		return NULL;
	}

	if (EVP_PKEY_keygen(ctx, &ret) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR,
			    PV_CRYPTO_ERROR_KEYGENERATION,
			    _("EC key could not be auto-generated"));
		return NULL;
	}

	return g_steal_pointer(&ret);
}

/* Convert a EVP_PKEY to the key format used in the PV header */
PvEcdhPubKey *pv_evp_pkey_to_ecdh_pub_key(const EVP_PKEY *key, GError **error)
{
	g_autofree PvEcdhPubKey *ret = g_new0(PvEcdhPubKey, 1);
	g_autoptr(BIGNUM) pub_x_big = NULL;
	g_autoptr(BIGNUM) pub_y_big = NULL;
	const EC_POINT *pub_key;
	g_autoptr(EC_KEY) ec_key = NULL;
	const EC_GROUP *grp;

	/* g_assert(key); */

	/* TODO cast correct?! */
	ec_key = EVP_PKEY_get1_EC_KEY((EVP_PKEY *)key);
	if (!ec_key) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Key has the wrong type"));
		return NULL;
	}

	pub_key = EC_KEY_get0_public_key(ec_key);
	if (!pub_key) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Failed to get public key"));
		return NULL;
	}

	grp = EC_KEY_get0_group(ec_key);
	if (!grp) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Failed to get EC group"));
		return NULL;
	}

	pub_x_big = BN_new();
	if (!pub_x_big)
		g_abort();

	pub_y_big = BN_new();
	if (!pub_y_big)
		g_abort();

	if (EC_POINT_get_affine_coordinates_GFp(grp, pub_key, pub_x_big,
						pub_y_big, NULL) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Cannot convert key to internal format"));
		return NULL;
	}

	if (BN_bn2binpad(pub_x_big, ret->x, sizeof(ret->x)) < 0) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Cannot convert key to internal format"));
		return NULL;
	}

	if (BN_bn2binpad(pub_y_big, ret->y, sizeof(ret->y)) < 0) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Cannot convert key to internal format"));
		return NULL;
	}

	return g_steal_pointer(&ret);
}

static GBytes *derive_key(const EVP_PKEY *key1, const EVP_PKEY *key2,
			  GError **error)
{
	g_autoptr(EVP_PKEY_CTX) ctx = NULL;
	uint8_t *data = NULL;
	size_t data_size, key_size;

	/* TODO cast okay?! */
	ctx = EVP_PKEY_CTX_new((EVP_PKEY *)key1, NULL);
	if (!ctx)
		g_abort();

	if (EVP_PKEY_derive_init(ctx) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Key derivation failed"));
		return NULL;
	}

	/* TODO cast okay?! */
	if (EVP_PKEY_derive_set_peer(ctx, (EVP_PKEY *)key2) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Key derivation failed"));
		return NULL;
	}

	/* Determine buffer length */
	if (EVP_PKEY_derive(ctx, NULL, &key_size) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_DERIVE,
			    _("Key derivation failed"));
		return NULL;
	}

	data_size = key_size;
	data = OPENSSL_malloc(data_size);
	if (!data)
		g_abort();
	if (EVP_PKEY_derive(ctx, data, &data_size) != 1) {
		OPENSSL_clear_free(data, data_size);
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_DERIVE,
			    _("Key derivation failed"));
		return NULL;
	}

	g_assert(data_size == key_size);
	return pv_sec_gbytes_new_take(g_steal_pointer(&data), data_size);
}

GBytes *pv_compute_exchange_key(const EVP_PKEY *cust, const EVP_PKEY *host,
				GError **error)
{
	const guint8 append[] = { 0x00, 0x00, 0x00, 0x01 };
	g_autoptr(GBytes) derived_key = NULL, ret = NULL;
	g_autoptr(GByteArray) der_key_ga = NULL;
	g_autofree uint8_t *raw = NULL;
	size_t raw_len;

	derived_key = derive_key(cust, host, error);
	if (!derived_key)
		return NULL;

	der_key_ga = g_bytes_unref_to_array(g_steal_pointer(&derived_key));
	/* ANSI X.9.63-2011: 66 bytes x with leading 7 bits and
	 * concatenate 32 bit int '1'
	 */
	der_key_ga = g_byte_array_append(der_key_ga, append, sizeof(append));
	/* free GBytesArray and get underlying data */
	raw_len = der_key_ga->len;
	raw = g_byte_array_free(g_steal_pointer(&der_key_ga), FALSE);

	ret = pv_sha256_hash(raw, raw_len, error);
	OPENSSL_cleanse(raw, raw_len);
	return g_steal_pointer(&ret);
}

GQuark pv_crypto_error_quark(void)
{
	return g_quark_from_static_string("pv-crypto-error-quark");
}

/* Alloc with openssl and clear+free */
struct _pv_crypto_ctx {
	EVP_CIPHER_CTX *cipher_ctx;
	BIO *input;
	BIO *filter;
};

PvCryptoCtx *pv_crypto_ctx_new(const EVP_CIPHER *cipher, GBytes *key,
			       enum PvCryptoMode mode, BIO *input)
{
	g_autoptr(PvCryptoCtx) ret = NULL;
	g_autoptr(BIO) filter = NULL;

	g_assert(input);

	ret = g_new0(PvCryptoCtx, 1);
	filter = pv_bio_cipher_new(cipher, key, mode);
	if (!filter) {
		/* TODO set error */
		return NULL;
	}

	if (input && !pv_crypto_ctx_set_input(ret, input)) {
		/* TODO set error */
		return NULL;
	}

	if (BIO_get_cipher_ctx(filter, &ret->cipher_ctx) != 1) {
		/* TODO set error */
		return NULL;
	}
	g_assert(ret->cipher_ctx);

	ret->filter = filter;
	return g_steal_pointer(&ret);
}

void pv_crypto_ctx_free(PvCryptoCtx *ctx)
{
	if (!ctx)
		return;
	/* TODO should we do this? is it worth it? */
	BIO_flush(ctx->filter);
	BIO_flush(ctx->input);

	BIO_vfree(ctx->input);
	BIO_vfree(ctx->filter);
	/* g_clear_pointer(ctx->output, BIO_vfree); */
	ctx->cipher_ctx = NULL;
	g_free(ctx);
}

gboolean pv_crypto_ctx_set_input(PvCryptoCtx *ctx, BIO *input)
{
	ctx->filter = BIO_push(ctx->filter, input);
	g_assert(ctx->filter);
	if (BIO_up_ref(input) != 1)
		return FALSE;
	ctx->input = input;
	return TRUE;
}

BIO *pv_crypto_ctx_rm_input(PvCryptoCtx *ctx)
{
	BIO *ret = ctx->input;
	if (!ret)
		return NULL;
	g_assert(BIO_pop(ctx->input) == NULL);
	BIO_vfree(ctx->input);
	ctx->input = NULL;
	return ret;
}
