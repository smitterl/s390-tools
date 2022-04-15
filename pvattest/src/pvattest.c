/*
 * Entry point for the pvattest tool.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include "config.h"

#include <stdio.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "libpv/crypto.h"
#include "libpv/cert.h"

#include "uvio.h"
#define UV_PATH "/dev/uv"

#include "common.h"
#include "attestation.h"
#include "arcb.h"
#include "parse.h"
#include "exchange_format.h"
#include "log.h"

#define NID NID_secp521r1

#define EXIT_MEASURE_NOT_VERIFIED 2

#define __PVATTEST_ERROR_MESSAGE_STRING                                        \
	"Error: " //redefine this error message for more detailed output

static arcb_v1_t *create_arcb(char **host_key_paths, gboolean use_nonce,
			      gboolean phkh_img, gboolean phkh_att,
			      uint64_t user_paf, GError **error)
{
	g_autoptr(arcb_v1_t) arcb = NULL;
	g_autoptr(GBytes) arpk = NULL, meas_key = NULL, nonce = NULL, iv = NULL;
	g_autoptr(EVP_PKEY) evp_cpk = NULL;
	g_autoslist(PvX509WithPath) host_keys_with_path = NULL;
	g_autoslist(EVP_PKEY) evp_host_keys = NULL;

	uint32_t mai = MAI_HMAC_SHA512;
	uint64_t paf = user_paf;

	g_assert(host_key_paths);

	arpk = pv_generate_key(EVP_aes_256_gcm(), error);
	if (!arpk)
		return NULL;
	iv = pv_generate_iv(EVP_aes_256_gcm(), error);
	if (!iv)
		return NULL;
	evp_cpk = pv_generate_ec_key(NID, error);
	if (!evp_cpk)
		return NULL;

	meas_key = pv_generate_rand_data(HMAC_SHA512_KEY_SIZE, error);
	if (!meas_key)
		return NULL;
	if (phkh_img)
		paf |= ARCB_V1_PAF_AAD_PHKH_HEADER;
	if (phkh_att)
		paf |= ARCB_V1_PAF_AAD_PHKH_ATTEST;

	arcb = arcb_v1_new(arpk, iv, mai, evp_cpk, meas_key, paf, error);
	if (!arcb)
		return NULL;
	if (use_nonce) {
		nonce = pv_generate_rand_data(ARCB_V1_NONCE_SIZE, error);
		arcb_v1_set_nonce(arcb, nonce);
	}

	host_keys_with_path = pv_load_certificates(
		(const char *const *)host_key_paths, error);
	if (!host_keys_with_path)
		return NULL;

	/*
	 * Load host keys and verify that they use the correct hostkeys
	 */
	evp_host_keys = pv_get_evp_pubkeys(host_keys_with_path, NID, error);
	if (!evp_host_keys)
		return NULL;
	for (GSList *iter = evp_host_keys; iter; iter = iter->next) {
		EVP_PKEY *host_key = iter->data;
		arcb_v1_add_key_slot(arcb, host_key, error);
		if (*error)
			return NULL;
	}
	return g_steal_pointer(&arcb);
}

#undef __PVATTEST_ERROR_MESSAGE_STRING
#define __PVATTEST_ERROR_MESSAGE_STRING                                        \
	"Creating the attestation request failed"
static int do_create(pvattest_create_config_t *create_config)
{
	g_autoptr(GError) error = NULL;
	g_autoptr(GBytes) serialized_arcb = NULL;
	g_autoptr(arcb_v1_t) arcb = NULL;
	g_autoptr(exchange_format_ctx_t) output_ctx = NULL;
	g_autoptr(GBytes) arpk = NULL;
	uint32_t measurement_size, additional_data_size;
	int hkd_verified = 0;

	if (!create_config->no_verify)
		hkd_verified = pv_verify_host_key_doc_by_path(
			(const char *const *)
				create_config->host_key_document_paths,
			create_config->root_ca_path,
			(const char *const *)create_config->crl_paths,
			(const char *const *)create_config->certificate_paths,
			create_config->online, &error);
	if (hkd_verified) {
		pvattest_log_GError(__PVATTEST_ERROR_MESSAGE_STRING, error);
		return EXIT_FAILURE;
	}
	pvattest_log_debug("Verification passed or skipped.");

	/* build attestation request */
	arcb = create_arcb(create_config->host_key_document_paths,
			   create_config->nonce, create_config->phkh_img,
			   create_config->phkh_att, create_config->paf, &error);
	if (!arcb) {
		pvattest_log_GError(__PVATTEST_ERROR_MESSAGE_STRING, error);
		return EXIT_FAILURE;
	}

	if (!create_config->nonce)
		pvattest_log_warning("No nonce used. (Discouraged setting)");

	additional_data_size = arcb_v1_get_required_additional_size(arcb);
	measurement_size = arcb_v1_get_required_measurement_size(arcb, &error);
	if (error) {
		pvattest_log_GError(__PVATTEST_ERROR_MESSAGE_STRING, error);
		return EXIT_FAILURE;
	}

	serialized_arcb = arcb_v1_serialize(arcb, &error);
	if (!serialized_arcb) {
		pvattest_log_GError(__PVATTEST_ERROR_MESSAGE_STRING, error);
		return EXIT_FAILURE;
	}

	/* write attestation request data to file */
	output_ctx = exchange_ctx_new(PVATTEST_EXCHANGE_VERSION_1_00);
	exchange_set_serialized_arcb(output_ctx, serialized_arcb);
	exchange_write_to_file(output_ctx, create_config->output_path,
			       measurement_size, additional_data_size, &error);
	if (error) {
		pvattest_log_GError(__PVATTEST_ERROR_MESSAGE_STRING, error);
		return EXIT_FAILURE;
	}
	pvattest_log_debug("ARCB written to file.");

	/* write attestation request protection key to file */
	arpk = arcb_v1_get_arp_key(arcb);
	wrapped_g_file_set_content(create_config->arp_key_out_path, arpk, 0600,
				   &error);
	if (error) {
		pvattest_log_GError(__PVATTEST_ERROR_MESSAGE_STRING, error);
		return EXIT_FAILURE;
	}
	pvattest_log_debug("ARPK written to file.");

	if (create_config->no_verify)
		pvattest_log_warning(
			"Host-key document verification is disabled.\n"
			"The attestation result could be compromised!");
	return EXIT_SUCCESS;
}

#ifdef PVATTEST_COMPILE_MEASURE
#undef __PVATTEST_ERROR_MESSAGE_STRING
#define __PVATTEST_ERROR_MESSAGE_STRING                                        \
	"Creating the attestation measurement failed"
static int do_measure(pvattest_measure_config_t *measure_config)
{
	g_autoptr(GError) error = NULL;
	g_autoptr(exchange_format_ctx_t) exchange_ctx = NULL;
	g_autoptr(GBytes) serialized_arcb = NULL, user_data = NULL,
			  measurement = NULL, additional_data = NULL,
			  config_uid = NULL;
	g_autoptr(uvio_attest_t) uvio_attest = NULL;
	uint32_t measurement_size, additional_data_size;
	be16_t uv_rc;
	int uv_fd;

	exchange_ctx =
		exchange_ctx_from_file(measure_config->input_path, &error);
	if (!exchange_ctx) {
		pvattest_log_GError(__PVATTEST_ERROR_MESSAGE_STRING, error);
		return EXIT_FAILURE;
	}

	serialized_arcb = exchange_get_serialized_arcb(exchange_ctx);
	if (!serialized_arcb) {
		pvattest_log_GError(__PVATTEST_ERROR_MESSAGE_STRING, error);
		return EXIT_FAILURE;
	}
	measurement_size =
		exchange_get_requested_measurement_size(exchange_ctx);
	additional_data_size =
		exchange_get_requested_additional_data_size(exchange_ctx);

	pvattest_log_debug("Input data loaded.");

	//TODO user data; user data generated here ore before at some point: next version
	uvio_attest = build_attestation_v1_ioctl(serialized_arcb, user_data,
						 measurement_size,
						 additional_data_size, &error);
	if (!uvio_attest) {
		pvattest_log_GError(__PVATTEST_ERROR_MESSAGE_STRING, error);
		return EXIT_FAILURE;
	}

	pvattest_log_debug("attestation context generated.");

	/* execute attestation */
	uv_fd = uvio_access_uv(UV_PATH, &error);
	if (uv_fd < 0) {
		pvattest_log_GError(__PVATTEST_ERROR_MESSAGE_STRING, error);
		return EXIT_FAILURE;
	};

	uv_rc = uvio_ioctl_attest(uv_fd, uvio_attest, &error);
	close(uv_fd);
	if (uv_rc != UVC_EXECUTED) {
		pvattest_log_GError(__PVATTEST_ERROR_MESSAGE_STRING, error);
		return EXIT_FAILURE;
	}
	pvattest_log_debug("attestation measurement successful. rc = %#x",
			   uv_rc);

	/* save to file */
	measurement = uvio_get_measurement(uvio_attest);
	additional_data = uvio_get_additional_data(uvio_attest);
	config_uid = uvio_get_config_uid(uvio_attest);

	exchange_set_measurement(exchange_ctx, measurement);
	exchange_set_additional_data(exchange_ctx, additional_data);
	exchange_set_config_uid(exchange_ctx, config_uid);

	exchange_write_to_file(exchange_ctx, measure_config->output_path, 0, 0,
			       &error);

	pvattest_log_debug("Output written to file.");

	return EXIT_SUCCESS;
}
#endif /* PVATTEST_COMPILE_MEASURE */

#undef __PVATTEST_ERROR_MESSAGE_STRING
#define __PVATTEST_ERROR_MESSAGE_STRING                                        \
	"Attestation measurement verification failed"
static int do_verify(pvattest_verify_config_t *verify_config)
{
	g_autoptr(GError) error = NULL;
	g_autoptr(exchange_format_ctx_t) input_ctx = NULL;
	g_autoptr(GBytes) user_data = NULL, uv_measurement = NULL,
			  additional_data = NULL, image_hdr = NULL,
			  calc_measurement = NULL, config_uid = NULL,
			  meas_key = NULL, arp_key = NULL, nonce = NULL,
			  serialized_arcb = NULL;
	g_autofree att_meas_ctx_t *measurement_hdr = NULL;
	gboolean rc;

	image_hdr = pv_file_to_g_bytes(verify_config->hdr_path, &error);
	if (!image_hdr) {
		pvattest_log_GError(__PVATTEST_ERROR_MESSAGE_STRING, error);
		return EXIT_FAILURE;
	}

	measurement_hdr = att_extract_from_hdr(image_hdr, &error);
	if (!measurement_hdr) {
		pvattest_log_GError(__PVATTEST_ERROR_MESSAGE_STRING, error);
		return EXIT_FAILURE;
	}

	pvattest_log_debug("Image header loaded.");

	input_ctx = exchange_ctx_from_file(verify_config->input_path, &error);
	if (!input_ctx) {
		pvattest_log_GError(__PVATTEST_ERROR_MESSAGE_STRING, error);
		return EXIT_FAILURE;
	}

	config_uid = exchange_get_config_uid(input_ctx);
	uv_measurement = exchange_get_measurement(input_ctx);
	user_data = exchange_get_user_data(input_ctx);
	additional_data = exchange_get_additional_data(input_ctx);
	serialized_arcb = exchange_get_serialized_arcb(input_ctx);

	if (!uv_measurement || !serialized_arcb) {
		g_set_error(&error, PVATTEST_ERROR, PVATTEST_SUBC_INVALID,
			    "Input data has no measurement");
		pvattest_log_GError(__PVATTEST_ERROR_MESSAGE_STRING, error);
		return EXIT_FAILURE;
	}
	pvattest_log_debug("Input data loaded.");

	att_add_uid(measurement_hdr, config_uid);

	arp_key = pv_file_to_g_bytes(verify_config->arp_key_in_path, &error);
	if (!arp_key) {
		pvattest_log_GError(__PVATTEST_ERROR_MESSAGE_STRING, error);
		return EXIT_FAILURE;
	}

	pvattest_log_debug("ARPK loaded.");

	rc = arcb_v1_verify_serialized_arcb(serialized_arcb, arp_key, &meas_key,
					    &nonce, &error);
	if (!rc) {
		pvattest_log_GError(__PVATTEST_ERROR_MESSAGE_STRING, error);
		return EXIT_FAILURE;
	}

	pvattest_log_debug("Input ARCB verified.");

	calc_measurement =
		att_gen_measurement_hmac_sha512(measurement_hdr, meas_key,
						user_data, nonce,
						additional_data, &error);
	if (!calc_measurement) {
		pvattest_log_GError(__PVATTEST_ERROR_MESSAGE_STRING, error);
		return EXIT_FAILURE;
	}
	pvattest_log_debug("Measurement calculated");

	if (!att_verify_measurement(calc_measurement, uv_measurement, &error)) {
		pvattest_log_GError(__PVATTEST_ERROR_MESSAGE_STRING, error);
		return EXIT_MEASURE_NOT_VERIFIED;
	}

	pvattest_log_debug("Measurement verified.");
	pvattest_log_debug("MEASUREMENT VALUES");
	gbhexdump(uv_measurement);
	gbhexdump(calc_measurement);

	return EXIT_SUCCESS;
}

/*
 * Will not free the config structs, but the nested char* etc.
 * that's what we need to do as we will receive a statically allocated config_t
 * Not defined in the parse header as someone might incorrectly assume
 * that the config pointers will be freed.
 */
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(pvattest_config_t,
				      pvattest_parse_clear_config)
int main(int argc, char *argv[])
{
	enum pvattest_command command;
	g_autoptr(GError) error = NULL;
	g_autoptr(pvattest_config_t) config = NULL;
	int rc;
	int appl_log_lvl = PVATTEST_LOG_LVL_DEFAULT;

	/* setting up the default log handler to filter messages based on the log level specified by the user */
	g_log_set_handler(NULL,
			  G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL |
				  G_LOG_FLAG_RECURSION,
			  &pvattest_log_default_logger, &appl_log_lvl);
	/* setting up the log handler for hexdumps (no prefix and  '\n' at end of message)to filter messages
	 * based on the log level specified by the user */
	g_log_set_handler(PVATTEST_HEXDUMP_LOG_DOMAIN,
			  G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL |
				  G_LOG_FLAG_RECURSION,
			  &pvattest_log_plain_logger, &appl_log_lvl);

	command = pvattest_parse(&argc, &argv, &config, &error);
	if (command == PVATTEST_SUBC_INVALID) {
		pvattest_log_error(error->message);
		exit(EXIT_FAILURE);
	}
	g_assert(config != NULL);
	appl_log_lvl = config->general.log_level;

	pv_init();

	switch (command) {
	case PVATTEST_SUBC_CREATE:
		rc = do_create(&config->create);
		break;
#ifdef PVATTEST_COMPILE_MEASURE
	case PVATTEST_SUBC_MEASURE:
		rc = do_measure(&config->measure);
		break;
#endif /* PVATTEST_COMPILE_MEASURE */
	case PVATTEST_SUBC_VERIFY:
		rc = do_verify(&config->verify);
		break;
	default:
		g_return_val_if_reached(EXIT_FAILURE);
	}

	pv_cleanup();

	return rc;
}
