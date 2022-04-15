/*
 * Definitions used for parsing arguments.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef PVATTEST_PARSE_H
#define PVATTEST_PARSE_H
#include "libpv/glib-helper.h"

#include <stdint.h>

#include "libpv/macros.h"

#define PVATTEST_SUBC_STR_CREATE "create"
#define PVATTEST_SUBC_STR_MEASURE "measure"
#define PVATTEST_SUBC_STR_VERIFY "verify"

enum pvattest_command {
	PVATTEST_SUBC_INVALID,
	PVATTEST_SUBC_CREATE,
	PVATTEST_SUBC_MEASURE,
	PVATTEST_SUBC_VERIFY,
};

typedef struct {
	int log_level;
} pvattest_general_config_t;

typedef struct {
	char **host_key_document_paths;
	char **certificate_paths;
	char **crl_paths;
	char *root_ca_path;

	char *arp_key_out_path;
	char *output_path;

	gboolean phkh_img;
	gboolean phkh_att;
	gboolean no_verify;
	gboolean online;

	/* experimental flags */
	gboolean nonce; /* default TRUE */
	uint64_t paf; /* default NULL */
} pvattest_create_config_t;

typedef struct {
	char *output_path;
	char *input_path;
} pvattest_measure_config_t;

typedef struct {
	char *input_path;
	char *hdr_path;
	char *arp_key_in_path;
} pvattest_verify_config_t;

typedef struct {
	pvattest_general_config_t general;
	pvattest_create_config_t create;
	pvattest_measure_config_t measure;
	pvattest_verify_config_t verify;
} pvattest_config_t;

/** pvattest_parse_clear_config() - clears pvattest config
 *
 * @config: struct to be cleared
 *
 * clears but not frees all config.
 * all non config members such like char* will be freed.
 */
void pvattest_parse_clear_config(pvattest_config_t *config);

/**  pvattest_parse() - parse CLI args
 *
 * @argc: ptr to argument count
 * @argv: ptr to argument vector
 * @config: output: ptr to parsed config. Target is statically allocated.
 *          You are responsible for freeing all non config ptrs.
 *
 * Will not return if verbose or help parsed.
 */
enum pvattest_command pvattest_parse(gint *argc, char **argvp[],
				     pvattest_config_t **config, GError **error)
	PV_NONNULL(1, 2, 3, 4);

#define PVATTEST_ERROR g_quark_from_static_string("pv-pvattest_error-quark")
typedef enum {
	PVATTEST_ERR_INV_ARGV,
	PVATTEST_ERR_INV_ARG,
} pv_pvattest_error_e;

#endif /* PVATTEST_PARSE_H */
