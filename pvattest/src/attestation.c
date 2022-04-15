/*
 * Attestation related functions
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include "config.h"

#include "libpv/hash.h"
#include "libpv/se-hdr.h"

#include "attestation.h"

/*
 * All optional arguments may be NULL
 * user_data is up to 256 bytes long, or NULL.
 * nonce is 16 bytes long or NULL.
 * additional_data is up to 32768 bytes long or NULL.
 */
GBytes *att_gen_measurement_hmac_sha512(att_meas_ctx_t *meas_hdr,
					GBytes *measurement_key,
					GBytes *optional_user_data,
					GBytes *optional_nonce,
					GBytes *optional_additional_data,
					GError **error)
{
	g_autoptr(HMAC_CTX) hmac_ctx = NULL;
	size_t user_data_size, additional_data_size, nonce_size;

	user_data_size = gbytes_get_size0(optional_user_data);
	additional_data_size = gbytes_get_size0(optional_additional_data);
	nonce_size = gbytes_get_size0(optional_nonce);

	g_assert(user_data_size <= 256);
	g_assert(additional_data_size <= 0x8000);
	g_assert(nonce_size == 0 || nonce_size == ARCB_V1_NONCE_SIZE);

	hmac_ctx = pv_hmac_ctx_new(measurement_key, EVP_sha512(), error);
	if (!hmac_ctx)
		return NULL;

	meas_hdr->user_data_len = GUINT16_TO_BE((uint16_t)user_data_size);
	meas_hdr->zeros = 0;
	meas_hdr->additional_data_len =
		GUINT32_TO_BE((uint32_t)additional_data_size);

	if (0 != pv_hmac_ctx_update_raw(hmac_ctx, meas_hdr, sizeof(*meas_hdr),
					error))
		return NULL;

	/* update optional data. if NULL passed (or size = 0) nothing will happen to the HMAC_CTX */
	if (0 != pv_hmac_ctx_update(hmac_ctx, optional_user_data, error))
		return NULL;
	if (0 != pv_hmac_ctx_update(hmac_ctx, optional_nonce, error))
		return NULL;
	if (0 != pv_hmac_ctx_update(hmac_ctx, optional_additional_data, error))
		return NULL;
	return pv_hamc_ctx_finalize(hmac_ctx, error);
}

att_meas_ctx_t *att_extract_from_hdr(GBytes *se_hdr, GError **error)
{
	g_autofree att_meas_ctx_t *meas = NULL;
	size_t se_hdr_size;
	const struct pv_hdr_head *hdr = g_bytes_get_data(se_hdr, &se_hdr_size);
	off_t se_hdr_tag_offset =
		GUINT32_FROM_BE(hdr->phs) - AES_256_GCM_TAG_SIZE;
	uint8_t *hdr_u8 = (uint8_t *)hdr;

	if (GUINT32_FROM_BE(hdr->phs) != se_hdr_size ||
	    GUINT64_FROM_BE(hdr->magic) != PV_MAGIC_NUMBER) {
		g_set_error(
			error, ATT_ERROR, ATT_ERR_INVALID_HDR,
			"Invalid SE-header provided. Size mismatch or wrong magic.");
		return NULL;
	}
	meas = g_malloc0(sizeof(*meas));

	memcpy(meas->pld, hdr->pld, SHA512_DIGEST_LENGTH);
	memcpy(meas->ald, hdr->ald, SHA512_DIGEST_LENGTH);
	memcpy(meas->tld, hdr->tld, SHA512_DIGEST_LENGTH);
	memcpy(meas->tag, hdr_u8 + se_hdr_tag_offset, AES_256_GCM_TAG_SIZE);

	return g_steal_pointer(&meas);
}

void att_add_uid(att_meas_ctx_t *m_hdr, GBytes *config_uid)
{
	g_assert(g_bytes_get_size(config_uid) == ATT_CONFIG_UID_SIZE);
	memcpy(m_hdr->config_uid, g_bytes_get_data(config_uid, NULL),
	       ATT_CONFIG_UID_SIZE);
}

gboolean att_verify_measurement(GBytes *calculated_measurement,
				GBytes *uvio_measurement, GError **error)
{
	if (g_bytes_compare(calculated_measurement, uvio_measurement) != 0) {
		g_set_error(
			error, ATT_ERROR,
			ATT_ERR_MEASUREMENT_VERIFICATION_FAILED,
			"Calculated and received attestation measurement are not the same.");
		return FALSE;
	}
	return TRUE;
}

PvX509WithPath *att_get_host_key_by_hash(PvCertWithPathList **host_keys,
					 GBytes *additional_data, size_t offset,
					 int nid, GError **error)
{
	PvX509WithPath *host_key = NULL;
	size_t add_data_size;
	uint8_t *phkh =
		((uint8_t *)g_bytes_get_data(additional_data, &add_data_size)) +
		offset;

	g_assert(*host_keys);

	if (offset + ARCB_V1_PHKH_SIZE > add_data_size) {
		g_set_error(
			error, ATT_ERROR, ATT_ERR_PHKH_NO_FIT_IN_USER_DATA,
			"The given user data is to small to hold the required PHKH.");
		return NULL;
	}

	for (GSList *iter = *host_keys; iter;
	     iter = iter->next, host_key = NULL) {
		host_key = iter->data;
		g_autoptr(EVP_PKEY) evp_host;
		g_autoptr(GBytes) phkh_host = NULL;
		g_autofree PvEcdhPubKey *ecdh_host = NULL;

		evp_host = pv_read_ec_pubkey_cert(host_key->cert, nid, error);
		if (!evp_host)
			return NULL;
		ecdh_host = pv_evp_pkey_to_ecdh_pub_key(evp_host, error);
		if (!ecdh_host)
			return NULL;
		phkh_host = pv_sha256_hash(ecdh_host->data,
					   sizeof(ecdh_host->data), error);
		if (!phkh_host)
			return NULL;

		if (memcmp(phkh, g_bytes_get_data(phkh_host, NULL),
			   ARCB_V1_PHKH_SIZE) == 0) {
			*host_keys = g_slist_delete_link(*host_keys, iter);
			break;
		}
	}

	if (!host_key)
		g_set_error(
			error, ATT_ERROR, ATT_ERR_PHKH_NO_MATCH,
			"No hash of the given host-keys match to the one attestation returned.");
	return host_key;
}
