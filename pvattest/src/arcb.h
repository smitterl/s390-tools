/*
 * Attestation Request Control Block related functions
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#pragma once
#include "libpv/glib-helper.h"

#include "lib/zt_common.h"
#include "libpv/crypto.h"

#include "types.h"

#define MAI_HMAC_RESERVED_INVALID 0
#define MAI_HMAC_SHA512 0x1

#define HMAC_SHA512_KEY_SIZE 64
#define ARCB_V1_ATTEST_PROT_KEY_SIZE 32
#define ARCB_V1_NONCE_SIZE 16
#define ARCB_V1_TAG_SIZE 16
#define ARCB_V1_IV_SIZE 12
#define ARCB_V1_PHKH_SIZE 32

#define BIT(bit) ((uint64_t)1 << (63 - bit))
/* Optional nonce in ARCB */
#define ARCB_V1_PAF_NONCE BIT(1)
/* public host key hash used to unseal SE
* header added to additional data
* to be measured */
#define ARCB_V1_PAF_AAD_PHKH_HEADER BIT(2)
/* public host key hash used to unseal
* this attestation added to additional data
* to be measured */
#define ARCB_V1_PAF_AAD_PHKH_ATTEST BIT(3)
/* Temporary backup-host-key use allowed */
#define ARCB_V1_PAF_TMP_BACKUP_ALLOWED BIT(62)

/* Global not-host-specific key allowed */
#define ARCB_V1_PAF_GLOBAL_NHS_KEY_ALLOWED BIT(63)

#define ARCB_V1_PAF_ALL                                                        \
	(ARCB_V1_PAF_NONCE | ARCB_V1_PAF_AAD_PHKH_HEADER |                     \
	 ARCB_V1_PAF_AAD_PHKH_ATTEST | ARCB_V1_PAF_TMP_BACKUP_ALLOWED |        \
	 ARCB_V1_PAF_GLOBAL_NHS_KEY_ALLOWED)

typedef struct arcb_v1 arcb_v1_t;

/** arcb_v1_new() - create a new Attestation Request Control Block
 *
 * @arpk: Attestation Request Protection key. AES-GCM-256 key to
 *        protect Measurement Key and Nonce.
 *        Must be ´ARCB_V1_ATTEST_PROT_KEY_SIZE´ bytes long.
 * @iv: IV for protecting Measuremt Key and Nonce.
 *      Should be random for each new ARPK.
 *      Must be ´ARCB_V1_IV_SIZE´ bytes long.
 * @mai:  Measurement Algorithm Identifier for the attestation measurement.
 *       See ´enum mai´
 * @evp_cpk: Customer key in EVP_PKEY format. Must contain private and public key pair.
 * @mkey: Measurement key to calculate the Measurement.
 *        Must be ´HMAC_SHA512_KEY_SIZE´ bytes long.
 * @paf: Plaintext Attestation Flags. See ´enum plaintext_attestattion_flags´.
 *       ´ARCB_V1_PAF_NONCE´ must not be set.
 * @error: GError. *error will != NULL if error occours.
 *
 * arpk, mkey, and iv must me correct size
 * If not this is considered as a programming error (No warning;
 * Results in Assertion or undefined behavior).
 *
 * GBytes will be ref'ed.
 *
 * All numbers must be in system byte order and will be converted to big endian
 * if needed.
 *
 * Return: new ARCB context.
 */
arcb_v1_t *arcb_v1_new(GBytes *arpk, GBytes *iv, uint32_t mai,
		       EVP_PKEY *evp_cpk, GBytes *mkey, uint64_t paf,
		       GError **error) PV_NONNULL(1, 2, 4, 5, 7);
void arcb_v1_clear_free(arcb_v1_t *arcb);
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(arcb_v1_t, arcb_v1_clear_free)

/** arcb_v1_add_key_slot() - add a Host key to the ARCB.
 *
 * @arcb: ARCB context.
 * @evp_host: Host public key.
 * @error: GError. *error will != NULL if error occours.
 *
 * Builds a key slot. Calculates exchange key, wraps ARPK with the exchange key.
 * Calculates the public host key hash. Calculates the key slot tag.
 * Adds it to the ARCB.
 */
void arcb_v1_add_key_slot(arcb_v1_t *arcb, EVP_PKEY *evp_host, GError **error)
	PV_NONNULL(1, 2, 3);
void arcb_v1_set_nonce(arcb_v1_t *arcb, GBytes *nonce) PV_NONNULL(1, 2);
void arcb_v1_rm_nonce(arcb_v1_t *arcb) PV_NONNULL(1);

/** arcb_v1_serialize() - WRITE out ARCB such that it can be read by UV.
 *
 * @arcb: ARCB context.
 * @error: GError. *error will != NULL if error occurs.
 *
 * Will create a valid ARCB for the UV. Including encrypting confidential data.
 * At least one key_slot must be added beforehand.
 *
 * Return: The serialized ARCB which can be added to the
 *         Retrieve Attestation Measurement UVC as GBytes.
 */
GBytes *arcb_v1_serialize(arcb_v1_t *arcb, GError **error) PV_NONNULL(1, 2);

uint32_t arcb_v1_get_required_measurement_size(arcb_v1_t *arcb, GError **error)
	PV_NONNULL(1, 2);
uint32_t arcb_v1_get_required_additional_size(arcb_v1_t *arcb) PV_NONNULL(1);
gboolean arcb_v1_use_nonce(arcb_v1_t *arcb) PV_NONNULL(1);
gboolean arcb_v1_additional_has_phkh_image(arcb_v1_t *arcb) PV_NONNULL(1);
gboolean arcb_v1_additional_has_phkh_attest(arcb_v1_t *arcb) PV_NONNULL(1);

GBytes *arcb_v1_get_measurement_key(arcb_v1_t *arcb) PV_NONNULL(1);
GBytes *arcb_v1_get_nonce(arcb_v1_t *arcb) PV_NONNULL(1);
GBytes *arcb_v1_get_arp_key(arcb_v1_t *arcb) PV_NONNULL(1);

/** arcb_v1_verify_serialized_arcb() - Verifies if a given serialized ARCB is valid.
 *
 * @serialized_arcb: binary ARCB in UV readable format.
 * @arpk: Attestation Request Protection key that was used to create serialized_arpk
 * @measurement_key: Output parameter: decrypted measurement key if no error.
 *                   May be NULL if not interested for this output.
 * @optional_nonce: Output parameter: decrypted nonce if no error.
 *                  May be NULL if not interested for this output.
 * @error: GError. *error will != NULL if error occurs.
 *
 *
 * Checks if sizes are sound and flags are known by this implementation.
 * Decrypts Measurement key and nonce (if given) and verifies ARCB tag.
 *
 * Return: TRUE if ARCB is valid, including matching ARCB tag. Otherwise FALSE.
 *
 */
gboolean arcb_v1_verify_serialized_arcb(GBytes *serialized_arcb, GBytes *arpk,
					GBytes **measurement_key,
					GBytes **optional_nonce, GError **error)
	PV_NONNULL(1, 2, 5);

#define ARCB_ERROR g_quark_from_static_string("pv-arcb_error-quark")
typedef enum arcb_error {
	ARCB_ERR_INVALID_ARCB,
	ARCB_ERR_INVALID_PAF,
	ARCB_ERR_INVALID_MAI,
	ARCB_ERR_UNABLE_ENCR_ARPK,
} arcb_error_e;
