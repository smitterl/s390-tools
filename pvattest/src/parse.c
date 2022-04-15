/*
 * Definitions used for parsing arguments.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include "config.h"

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include "parse.h"
#include "log.h"
#include "common.h"

#define DEFAULT_OUTPUT_FILE_NAME "attest.bin"
#define DEFAULT_OPTION_PHKH_IMG FALSE
#define DEFAULT_OPTION_PHKH_ATT FALSE
#define DEFAULT_OPTION_NO_VERIFY FALSE
#define DEFAULT_OPTION_ONLINE TRUE
#define DEFAULT_OPTION_NONCE TRUE

static pvattest_config_t pvattest_config = {
	.general = {
		.log_level = PVATTEST_LOG_LVL_DEFAULT,
	},
	.create = {
		.output_path = NULL,
		.host_key_document_paths = NULL,
		.crl_paths = NULL,
		.root_ca_path = NULL,
		.certificate_paths = NULL,
		.arp_key_out_path = NULL,
		.phkh_img = DEFAULT_OPTION_PHKH_IMG,
		.phkh_att = DEFAULT_OPTION_PHKH_ATT,
		.online = DEFAULT_OPTION_ONLINE,
		.nonce = DEFAULT_OPTION_NONCE,
		.paf = 0,
	},
	.measure = {
		.output_path = NULL,
		.input_path = NULL,
	},
	.verify = {
		.input_path = NULL,
		.hdr_path = NULL,
		.arp_key_in_path = NULL,
	},
};
typedef gboolean (*verify_options_fn_t)(GError **);

static gboolean check_for_non_null(const void *ptr, const char *msg,
				   GError **error)
{
	if (ptr == NULL) {
		g_set_error(error, PVATTEST_ERROR, PVATTEST_ERR_INV_ARG, "%s",
			    msg);
		return FALSE;
	}
	return TRUE;
}

static gboolean _check_for_invalid_path(const char *path, gboolean must_exist,
					GError **error)
{
	int cached_errno = 0;
	g_assert(path);

	if (must_exist) {
		if (access(path, F_OK | R_OK) != 0)
			cached_errno = errno;
	}
	if (cached_errno) {
		g_set_error(error, PVATTEST_ERROR, PVATTEST_ERR_INV_ARG,
			    "Cannot access '%s': %s", path,
			    g_strerror(cached_errno));
		return FALSE;
	}
	return TRUE;
}

static gboolean check_for_optional_invalid_path(const char *path,
						gboolean must_exist,
						GError **error)
{
	if (!path)
		return TRUE;
	return _check_for_invalid_path(path, must_exist, error);
}

static gboolean check_for_invalid_path(const char *path, gboolean must_exist,
				       const char *null_msg, GError **error)
{
	if (!check_for_non_null(path, null_msg, error))
		return FALSE;
	return _check_for_invalid_path(path, must_exist, error);
}

static gboolean _check_file_list(char **path_list, gboolean must_exist,
				 GError **error)
{
	char *path = NULL;
	for (char **path_it = path_list; path_it != NULL && *path_it != NULL;
	     path_it++) {
		path = *path_it;
		if (!_check_for_invalid_path(path, must_exist, error))
			return FALSE;
	}
	return TRUE;
}

static gboolean check_optional_file_list(char **path_list, gboolean must_exist,
					 GError **error)
{
	if (!path_list)
		return TRUE;
	return _check_file_list(path_list, must_exist, error);
}

static gboolean check_file_list(char **path_list, gboolean must_exist,
				const char *null_msg, GError **error)
{
	if (!check_for_non_null(path_list, null_msg, error))
		return FALSE;
	return _check_file_list(path_list, must_exist, error);
}

static gboolean hex_str_toull(const char *nptr, uint64_t *dst, GError **err)
{
	uint64_t value;
	gchar *end;

	g_assert(dst);

	if (!g_str_is_ascii(nptr)) {
		g_set_error(
			err, PVATTEST_ERROR, PVATTEST_ERR_INV_ARG,
			_("Invalid value: '%s'. A hexadecimal value is required, for example '0xcfe'"),
			nptr);
		return FALSE;
	}

	value = g_ascii_strtoull(nptr, &end, 16);
	if ((value == G_MAXUINT64 && errno == ERANGE) ||
	    (end && *end != '\0')) {
		g_set_error(
			err, PVATTEST_ERROR, PVATTEST_ERR_INV_ARG,
			_("Invalid value: '%s'. A hexadecimal value is required, for example '0xcfe'"),
			nptr);
		return FALSE;
	}
	*dst = value;
	return TRUE;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

/************************* SHARED OPTIONS *************************************/
/* NOTE REQUIRED */
#define _entry_host_key_document(__arg_data, __indent)                                \
	{                                                                             \
		.long_name = "host-key-document", .short_name = 'k',                  \
		.flags = G_OPTION_FLAG_NONE,                                          \
		.arg = G_OPTION_ARG_FILENAME_ARRAY, .arg_data = __arg_data,           \
		.description =                                                        \
			"Specify the host key document. At least one is required.\n", \
		.arg_description = "FILE",                                            \
	}
/* NOTE REQUIRED */
#define _entry_certs(__arg_data, __indent)                                                            \
	{                                                                                             \
		.long_name = "cert", .short_name = 'C',                                               \
		.flags = G_OPTION_FLAG_NONE,                                                          \
		.arg = G_OPTION_ARG_FILENAME_ARRAY, .arg_data = __arg_data,                           \
		.description =                                                                        \
			"Specifies  the  certificate that is used to establish a chain\n" __indent    \
			"of trust for the verification of the host-key documents. Specify\n" __indent \
			"this option twice to specify the IBM Z signing key and the\n" __indent       \
			"intermediate CA certificate (signed by the root CA). Required.\n" __indent   \
			"Ignored when --no-verify is selected.\n",                                    \
		.arg_description = "FILE",                                                            \
	}
/* NOTE REQUIRED */
#define _entry_crls(__arg_data, __indent)                                        \
	{                                                                        \
		.long_name = "crl", .short_name = 0,                             \
		.flags = G_OPTION_FLAG_NONE,                                     \
		.arg = G_OPTION_ARG_FILENAME_ARRAY, .arg_data = __arg_data,      \
		.description =                                                   \
			"FILE contains a certificate revocation list\n" __indent \
			"(optional).",                                           \
		.arg_description = "FILE",                                       \
	}
/* NOTE REQUIRED */
#define _entry_root_ca(__arg_data, __indent)                                           \
	{                                                                              \
		.long_name = "root-ca", .short_name = 0,                               \
		.flags = G_OPTION_FLAG_NONE,                                           \
		.arg = G_OPTION_ARG_FILENAME_ARRAY, .arg_data = __arg_data,            \
		.description =                                                         \
			"Set FILE as the trusted root CA and don't use the\n" __indent \
			"root CAs that are installed on the system (optional).",       \
		.arg_description = "FILE",                                             \
	}
/* NOTE REQUIRED */
#define _entry_guest_hdr(__arg_data, __indent)                                               \
	{                                                                                    \
		.long_name = "hdr", .short_name = 0,                                         \
		.flags = G_OPTION_FLAG_NONE, .arg = G_OPTION_ARG_FILENAME,                   \
		.arg_data = __arg_data,                                                      \
		.description =                                                               \
			"Specify the header of the guest image. Exactly one is required.\n", \
		.arg_description = "FILE",                                                   \
	}
/* NOTE REQUIRED */
#define _entry_input(__arg_data, __additional_text, __indent)                                  \
	{                                                                                      \
		.long_name = "input", .short_name = 'i',                                       \
		.flags = G_OPTION_FLAG_NONE, .arg = G_OPTION_ARG_FILENAME,                     \
		.arg_data = __arg_data,                                                        \
		.description =                                                                 \
			"Use FILE to specify the encrypted attestation input file.\n" __indent \
				__additional_text "\n",                                        \
		.arg_description = "FILE",                                                     \
	}
/* NOTE REQUIRED */
#define _entry_output(__arg_data, __additional_text, __indent)                                  \
	{                                                                                       \
		.long_name = "output", .short_name = 'o',                                       \
		.flags = G_OPTION_FLAG_NONE, .arg = G_OPTION_ARG_FILENAME,                      \
		.arg_data = __arg_data,                                                         \
		.description =                                                                  \
			"Use FILE to specify the encrypted attestation output file.\n" __indent \
				__additional_text "\n",                                         \
		.arg_description = "FILE",                                                      \
	}
/* NOTE REQUIRED */
#define _entry_att_prot_key_save(__arg_data, __indent)                               \
	{                                                                            \
		.long_name = "arpk", .short_name = 'a',                              \
		.flags = G_OPTION_FLAG_NONE, .arg = G_OPTION_ARG_FILENAME,           \
		.arg_data = __arg_data,                                              \
		.description =                                                       \
			"Save FILE as GCM-AES256 key for protecting the \n" __indent \
			"attestation request. Do not publish this key,\n" __indent   \
			"otherwise your attestation might be tampered.\n",           \
		.arg_description = "FILE",                                           \
	}
/* NOTE REQUIRED */
#define _entry_att_prot_key_load(__arg_data, __indent)                                 \
	{                                                                              \
		.long_name = "arpk", .short_name = 'a',                                \
		.flags = G_OPTION_FLAG_NONE, .arg = G_OPTION_ARG_FILENAME,             \
		.arg_data = __arg_data,                                                \
		.description =                                                         \
			"GCM-AES256 key to unwrap the attestation request.\n" __indent \
			"Delete this key after verification.\n",                       \
		.arg_description = "FILE",                                             \
	}
#define _entry_phkh_img(__arg_data, __indent)                                                     \
	{                                                                                         \
		.long_name = "phkh-img", .short_name = 0,                                         \
		.flags = G_OPTION_FLAG_NONE, .arg = G_OPTION_ARG_NONE,                            \
		.arg_data = __arg_data,                                                           \
		.description =                                                                    \
			"add the public host key hash of the image hdr used to unseal\n" __indent \
			"the secure guest to the measurement. (optional)\n"                       \
	}
#define _entry_phkh_att(__arg_data, __indent)                                      \
	{                                                                          \
		.long_name = "phkh-att", .short_name = 0,                          \
		.flags = G_OPTION_FLAG_NONE, .arg = G_OPTION_ARG_NONE,             \
		.arg_data = __arg_data,                                            \
		.description =                                                     \
			"add the public host key hash of the \n" __indent          \
			"attestation hdr used to unseal\n" __indent                \
			"the attestation request to the measurement. (optional)\n" \
	}
#define _entry_no_verify(__arg_data, __indent)                                     \
	{                                                                          \
		.long_name = "no-verify", .short_name = 0,                         \
		.flags = G_OPTION_FLAG_NONE, .arg = G_OPTION_ARG_NONE,             \
		.arg_data = __arg_data,                                            \
		.description =                                                     \
			"Disable the host-key-document verification. (optional)\n" \
	}
#define _entry_offline_maps_to_online(__arg_data, __indent)                    \
	{                                                                      \
		.long_name = "offline", .short_name = 0,                       \
		.flags = G_OPTION_FLAG_REVERSE, .arg = G_OPTION_ARG_NONE,      \
		.arg_data = __arg_data,                                        \
		.description = "Don't download CRLs (optional).\n",            \
	}

#define _entry_verbose(__indent)                                               \
	{                                                                      \
		.long_name = "verbose", .short_name = 'V',                     \
		.flags = G_OPTION_FLAG_NO_ARG, .arg = G_OPTION_ARG_CALLBACK,   \
		.arg_data = &increase_log_lvl,                                 \
		.description = "Provide more detailed output (optional)\n",    \
		.arg_description = NULL,                                       \
	}
#define _entry_x_paf(__arg_data, __indent)                                      \
	{                                                                       \
		.long_name = "x-paf", .short_name = 0,                          \
		.flags = G_OPTION_FLAG_NONE, .arg = G_OPTION_ARG_CALLBACK,      \
		.arg_data = __arg_data,                                         \
		.description =                                                  \
			"Specify the Plaintext Attestation Flags\n" __indent    \
			"as a hexadecimal value. Flags that change\n" __indent  \
			"the paf (--phkh-*) take precedence over\n" __indent    \
			"this flag.\n" __indent                                 \
			"Setting the nonce paf is not allowed here.\n" __indent \
			"(optional, default 0x0)\n",                            \
		.arg_description = "FILE",                                      \
	}
#define _entry_x_no_nonce(__arg_data, __indent)                                \
	{                                                                      \
		.long_name = "x-no-nonce", .short_name = 0,                    \
		.flags = G_OPTION_FLAG_REVERSE, .arg = G_OPTION_ARG_NONE,      \
		.arg_data = __arg_data,                                        \
		.description = "Do not use a nonce in the request.\n" __indent \
			       "(optional, not suggested)\n"                   \
	}
static gboolean increase_log_lvl(G_GNUC_UNUSED const char *option_name,
				 G_GNUC_UNUSED const char *value,
				 G_GNUC_UNUSED gpointer data,
				 G_GNUC_UNUSED GError **error)
{
	pvattest_log_increase_log_lvl(&pvattest_config.general.log_level);
	return TRUE;
}

static gboolean create_set_paf(G_GNUC_UNUSED const char *option_name,
			       const char *value, G_GNUC_UNUSED gpointer data,
			       G_GNUC_UNUSED GError **error)
{
	return hex_str_toull(value, &pvattest_config.create.paf, error);
}
/***************************** GENERAL OPTIONS ********************************/
static gboolean print_version = FALSE;

GOptionEntry general_options[] = {
	{
		.long_name = "version",
		.short_name = 'v',
		.flags = G_OPTION_FLAG_NONE,
		.arg = G_OPTION_ARG_NONE,
		.arg_data = &print_version,
		.description = "Print the version and exit.\n",
		.arg_description = NULL,
	},
	_entry_verbose(""),
	{ NULL },
};
/************************* CREATE ATTESTATION OPTIONS *************************/
#define create_indent "                                   "
GOptionEntry create_options[] = {
	_entry_host_key_document(
		&pvattest_config.create.host_key_document_paths, create_indent),
	_entry_certs(&pvattest_config.create.certificate_paths, create_indent),
	_entry_crls(&pvattest_config.create.crl_paths, create_indent),
	_entry_root_ca(&pvattest_config.create.root_ca_path, create_indent),
	_entry_output(&pvattest_config.create.output_path,
		      "Contains the attestation request control block.",
		      create_indent),
	_entry_att_prot_key_save(&pvattest_config.create.arp_key_out_path,
				 create_indent),

	_entry_phkh_img(&pvattest_config.create.phkh_img, create_indent),
	_entry_phkh_att(&pvattest_config.create.phkh_att, create_indent),
	_entry_no_verify(&pvattest_config.create.no_verify, create_indent),
	_entry_offline_maps_to_online(&pvattest_config.create.online,
				      create_indent),
	_entry_verbose(create_indent),
	{ NULL }
};
GOptionEntry experimental_create_options[] = {
	_entry_x_no_nonce(&pvattest_config.create.nonce, create_indent),
	_entry_x_paf(&create_set_paf, create_indent),
	{ NULL }
};

static gboolean verify_create(GError **error)
{
	if (!check_file_list(
		    pvattest_config.create.host_key_document_paths, TRUE,
		    "Please specify --host-key-document at least once.", error))
		return FALSE;
	if (!pvattest_config.create.no_verify) {
		if (!check_file_list(
			    pvattest_config.create.certificate_paths, TRUE,
			    "Either specify the IBM Z signing key and"
			    " intermediate CA certificate\nby using the '--cert' option, or"
			    " use the '--no-verify' flag to disable the\nhost-key document"
			    " verification completely (at your own risk).",
			    error))
			return FALSE;
	}
	if (!check_for_invalid_path(pvattest_config.create.arp_key_out_path,
				    FALSE, "Missing argument for --arpk.",
				    error))
		return FALSE;
	if (!check_for_invalid_path(pvattest_config.create.output_path, FALSE,
				    "Missing argument for --output.", error))
		return FALSE;
	if (!check_optional_file_list(pvattest_config.create.crl_paths, TRUE,
				      error))
		return FALSE;
	if (!check_for_optional_invalid_path(
		    pvattest_config.create.root_ca_path, TRUE, error))
		return FALSE;
	return TRUE;
};
/************************* MEASUREMENT OPTIONS ********************************/
#ifdef PVATTEST_COMPILE_MEASURE
#define measure_indent "                        "
GOptionEntry measure_options[] = {
	_entry_input(&pvattest_config.measure.input_path,
		     "Contains the attestation request control block.",
		     measure_indent),
	_entry_output(
		&pvattest_config.measure.output_path,
		"Contains the attestation request control block, measurement, and additional data.",
		measure_indent),
	_entry_verbose(measure_indent),
	{ NULL },
};
static gboolean verify_measure(GError **error)
{
	if (!check_for_invalid_path(pvattest_config.measure.input_path, TRUE,
				    "Missing argument for --input.", error))
		return FALSE;
	if (!check_for_invalid_path(pvattest_config.measure.output_path, FALSE,
				    "Missing argument for --output.", error))
		return FALSE;
	return TRUE;
}
#endif /* PVATTEST_COMPILE_MEASURE */
/************************* VERIFY OPTIONS ************************************/
#define verify_indent "                       "
GOptionEntry verify_options[] = {
	_entry_input(
		&pvattest_config.verify.input_path,
		"Contains the attestation request control block,\n" verify_indent
		" measurement, and additional data.",
		verify_indent),
	_entry_guest_hdr(&pvattest_config.verify.hdr_path, verify_indent),
	_entry_att_prot_key_load(&pvattest_config.verify.arp_key_in_path,
				 verify_indent),
	_entry_verbose(verify_indent),
	{ NULL },
};
static gboolean verify_verify(GError **error)
{
	if (!check_for_invalid_path(pvattest_config.verify.input_path, TRUE,
				    "Missing argument for --input.", error))
		return FALSE;
	if (!check_for_invalid_path(pvattest_config.verify.hdr_path, TRUE,
				    "Missing argument for --hdr.", error))
		return FALSE;
	if (!check_for_invalid_path(pvattest_config.verify.arp_key_in_path,
				    TRUE, "Missing argument for --arpk.",
				    error))
		return FALSE;
	return TRUE;
}
/************************** OPTIONS END ***************************************/
#pragma GCC diagnostic pop

/*
 * If the next line is in the same paragraph add a blank just before the \n.
 * We generate man pages using these help messages. " \n" is used to identify
 * newlines that needs to be removed to generate nicer man pages.
 * In the --help output these spaces won't hurt.
 */
static char summary[] =
	"\n"
	"Commands:\n"
	"  " GETTEXT_PACKAGE " create [OPTIONS]\n"
#ifdef PVATTEST_COMPILE_MEASURE
	"  " GETTEXT_PACKAGE " measure [OPTIONS]\n"
#endif /* PVATTEST_COMPILE_MEASURE */
	"  " GETTEXT_PACKAGE " verify [OPTIONS]\n"
	"\n"
	"Description:\n"
	"  With " GETTEXT_PACKAGE
	" one can create attestation requests in a trusted environment \n"
	"  to attest an IBM Secure Execution guest to verify that a secure \n"
	"  configuration is the one you think it is and was actually started in a secure manner.\n"
	"\n"
	"  create    creates such request in a trusted environment.\n"
	"  measure   sends the attestation request to the Ultravisor \n"
	"            and receives the answer.\n"
	"  verify    checks if the answer from the Ultravisor is the one you expect. \n"
	"            If they differ, the Secure Execution guest might not be the one \n"
	"            you think it is or the guest is not secure at all.\n"
	"\n"
	"  In order to get credible results, 'create' and 'verify' must be run in a \n"
	"  trusted environment, like your workstation or a previously attested \n"
	"  IBM Secure Execution guest. Otherwise, the attestation might be tampered. \n"
	"  For all certificates, revocation lists, and host-key documents, both \n"
	"  the PEM and DER input formats are supported. \n"
	"  If you run this program on a non S390 System, 'measure' might not be available.\n"
	"\n"
	"  Use '" GETTEXT_PACKAGE " [COMMAND] -h' to get detailed help\n";
static char create_summary[] =
	"Description:\n"
	"  Create attestation measurement requests to attest an \n"
	"  IBM Secure Execution guest. Only create attestation requests on a machine \n"
	"  you TRUST e.g. your Workstation. \n"
	"  In order to avoid compromising the attestation do not publish the \n"
	" Attest Request Protection Key and delete it after verification. \n"
	" Every 'create' will generate a new, random ARP-key.\n"
	"Example:\n"
	"  " GETTEXT_PACKAGE
	" create -k hkd.crt --arpk arp.key -o arcb.bin --no_verify\n"
	"  \n"
	"  " GETTEXT_PACKAGE
	" create -k hkd.crt --arpk arp.key -o arcb.bin --cert DigiCertCA.crt --cert IbmSigningKey.crt\n"
	"  \n"
	"  " GETTEXT_PACKAGE
	" create -k hkd.crt --arpk arp.key -o arcb.bin --cert DigiCertCA.crt --cert IbmSigningKey.crt --offline --crl DigiCertCA.crl --crl IbmSigningKey.crl --crl rootCA.crl";
#ifdef PVATTEST_COMPILE_MEASURE
static char measure_summary[] =
	"Description:\n"
	"  Run a measurement of this system using '/dev/uv'. \n"
	"  System must support this functionality. \n"
	"  Input must contain an Attestation Request Control Block (ARCB). \n"
	"  Output will contain the original ARCB, the measurement, the configuration UID, \n"
	"  if requested in the ARCB Additional Data, and if provided User Data.\n"
	"Example:\n"
	"  " GETTEXT_PACKAGE
	" measure --input arcb.bin --output measurement.bin\n";
#endif /* PVATTEST_COMPILE_MEASURE */
static char verify_summary[] =
	"Description:\n"
	"  Verify that a previously generated attestation measurement of an \n"
	"  IBM Secure Execution guest is as expected. Verify only on a machine \n"
	"  you TRUST e.g. your Workstation. \n"
	"  Input must contain the original ARCB, the measurement, the configuration UID, \n"
	"  and if requested in the ARCB Additional Data. \n"
	"  The ARP-key must be the one that was used to create the ARCB. Please delete it \n"
	"  after verification.\n"
	"Example:\n"
	"  " GETTEXT_PACKAGE
	" verify --input measurement.bin --arpk arp.key --hdr se_guest.hdr";

static void print_version_and_exit(void)
{
	printf("%s version %s\n", GETTEXT_PACKAGE, RELEASE_STRING);
	printf("%s\n", COPYRIGHT_NOTICE);
	exit(EXIT_SUCCESS);
}

static GOptionContext *create_ctx(GOptionEntry *options,
				  GOptionEntry *experimental_options,
				  const char *param_name,
				  const char *opt_summary)
{
	GOptionContext *ret = g_option_context_new(param_name);
	GOptionGroup *x_group = NULL;
	g_option_context_add_main_entries(ret, options, NULL);
	g_option_context_set_summary(ret, opt_summary);
	if (experimental_options) {
		x_group = g_option_group_new("experimental",
					     "Experimental Options",
					     "Show experimental options", NULL,
					     NULL);
		g_option_group_add_entries(x_group, experimental_options);
		g_option_context_add_group(ret, x_group);
	}
	return ret;
}

enum pvattest_command pvattest_parse(gint *argc, char **argvp[],
				     pvattest_config_t **config, GError **error)
{
	g_autoptr(GOptionContext) main_context = NULL, subc_context = NULL;
	char **argv = *argvp;
	enum pvattest_command subc = PVATTEST_SUBC_INVALID;
	verify_options_fn_t verify_options_fn = NULL;

	/*
 	 * First parse until the first non dash argument. This must be one of the commands.
	 * (strict POSIX parsing)
 	 */
	main_context = g_option_context_new(
		"COMMAND [OPTIONS] - create, do, and verify attestation measurements");
	g_option_context_set_strict_posix(main_context, TRUE);
	g_option_context_add_main_entries(main_context, general_options, NULL);
	g_option_context_set_summary(main_context, summary);

	if (!g_option_context_parse(main_context, argc, argvp, error))
		return PVATTEST_SUBC_INVALID;
	if (print_version)
		print_version_and_exit();

	/*
	 *Parse depending on the specified command
	 */
	else if (g_strcmp0(argv[1], PVATTEST_SUBC_STR_CREATE) == 0) {
		subc_context = create_ctx(
			create_options, experimental_create_options,
			"create [OPTIONS] - create an attestation measurement request",
			create_summary);
		subc = PVATTEST_SUBC_CREATE;
		verify_options_fn = &verify_create;
	}
#ifdef PVATTEST_COMPILE_MEASURE
	else if (g_strcmp0(argv[1], PVATTEST_SUBC_STR_MEASURE) == 0) {
		subc_context = create_ctx(
			measure_options, NULL,
			"measure [OPTIONS] - execute an attestation measurement request",
			measure_summary);
		subc = PVATTEST_SUBC_MEASURE;
		verify_options_fn = &verify_measure;
	}
#endif /* PVATTEST_COMPILE_MEASURE */
	else if (g_strcmp0(argv[1], PVATTEST_SUBC_STR_VERIFY) == 0) {
		subc_context = create_ctx(
			verify_options, NULL,
			"verify [OPTIONS] - verify an attestation measurement",
			verify_summary);
		subc = PVATTEST_SUBC_VERIFY;
		verify_options_fn = &verify_verify;
	} else {
		if (argv[1])
			g_set_error(error, PVATTEST_ERROR,
				    PVATTEST_ERR_INV_ARGV,
				    "Invalid command specified: %s.", argv[1]);
		else
			g_set_error(error, PVATTEST_ERROR,
				    PVATTEST_ERR_INV_ARGV,
				    "No command specified.");
		return PVATTEST_SUBC_INVALID;
	}
	g_assert(verify_options_fn);

	if (!g_option_context_parse(subc_context, argc, argvp, error))
		return PVATTEST_SUBC_INVALID;

	if (!verify_options_fn(error))
		return PVATTEST_SUBC_INVALID;

	*config = &pvattest_config;
	return subc;
}

static void pvattest_parse_clear_create_config(pvattest_create_config_t *config)
{
	if (!config)
		return;
	g_strfreev(config->host_key_document_paths);
	g_strfreev(config->certificate_paths);
	g_free(config->arp_key_out_path);
	g_free(config->output_path);
}

static void
pvattest_parse_clear_measure_config(pvattest_measure_config_t *config)
{
	if (!config)
		return;
	g_free(config->input_path);
	g_free(config->output_path);
}

static void pvattest_parse_clear_verify_config(pvattest_verify_config_t *config)
{
	if (!config)
		return;
	g_free(config->input_path);
	g_free(config->hdr_path);
	g_free(config->arp_key_in_path);
}

void pvattest_parse_clear_config(pvattest_config_t *config)
{
	if (!config)
		return;
	pvattest_parse_clear_create_config(&config->create);
	pvattest_parse_clear_measure_config(&config->measure);
	pvattest_parse_clear_verify_config(&config->verify);
}
