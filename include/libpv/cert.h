/*
 * Certificate functions and definitions.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#pragma once

#include "libpv/common.h"

#include <openssl/asn1.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>

#define PV_IBM_Z_SUBJECT_COMMON_NAME                                           \
	"International Business Machines Corporation"
#define PV_IBM_Z_SUBJECT_COUNTRY_NAME "US"
#define PV_IBM_Z_SUBJECT_LOCALITY_NAME "Poughkeepsie"
#define PV_IBM_Z_SUBJECT_ORGANIZATIONONAL_UNIT_NAME_SUFFIX "Key Signing Service"
#define PV_IBM_Z_SUBJECT_ORGANIZATION_NAME                                     \
	"International Business Machines Corporation"
#define PV_IBM_Z_SUBJECT_STATE "New York"
#define PV_IMB_Z_SUBJECT_ENTRY_COUNT 6

/* Minimum security level for the keys/certificates used to establish a chain of
 * trust (see https://www.openssl.org/docs/man1.1.1/man3/X509_VERIFY_PARAM_set_auth_level.html
 * for details).
 */
#define PV_CERTS_SECURITY_LEVEL 2

/** pv_cert_init() - initialize certificate handling.
 *
 * Should not be called by user.
 * Use pv_init() instead which
 * calls this function during creation.
 *
 * Sets up data structures for caching CRLs.
 */
void pv_cert_init(void);

/** pv_cert_cleanup() - cleanup certificate handling.
 *
 * Should not be called by user.
 * Use pv_cleanup() instead which
 * calls this function during creation.
 *
 * Cleans up data structures for caching CRLs.
 */
void pv_cert_cleanup(void);

#define PV_CERT_ERROR g_quark_from_static_string("pv-cert-error-quark")
typedef enum {
	PV_CERT_ERROR_CERT_REVOKED,
	PV_CERT_ERROR_CERT_SIGNATURE_INVALID,
	PV_CERT_ERROR_CERT_SUBJECT_ISSUER_MISMATCH,
	PV_CERT_ERROR_CRL_DOWNLOAD_FAILED,
	PV_CERT_ERROR_CRL_SIGNATURE_INVALID,
	PV_CERT_ERROR_CRL_SUBJECT_ISSUER_MISMATCH,
	PV_CERT_ERROR_CURL_INIT_FAILED,
	PV_CERT_ERROR_DOWNLOAD_FAILED,
	PV_CERT_ERROR_FAILED_DOWNLOAD_CRL,
	PV_CERT_ERROR_INTERNAL,
	PV_CERT_ERROR_INVALID_PARM,
	PV_CERT_ERROR_INVALID_SIGNATURE_ALGORITHM,
	PV_CERT_ERROR_INVALID_VALIDITY_PERIOD,
	PV_CERT_ERROR_LOAD_CRL,
	PV_CERT_ERROR_LOAD_DEFAULT_CA,
	PV_CERT_ERROR_LOAD_ROOT_CA,
	PV_CERT_ERROR_MALFORMED_CERTIFICATE,
	PV_CERT_ERROR_MALFORMED_ROOT_CA,
	PV_CERT_ERROR_NO_CRL,
	PV_CERT_ERROR_NO_CRLDP,
	PV_CERT_ERROR_NO_ISSUER_IBM_Z_FOUND,
	PV_CERT_ERROR_NO_PUBLIC_KEY,
	PV_CERT_ERROR_READ_CERTIFICATE,
	PV_CERT_ERROR_SIGNATURE_ALGORITHM_MISMATCH,
	PV_CERT_ERROR_SKID_AKID_MISMATCH,
	PV_CERT_ERROR_VERIFICATION_FAILED,
	PV_CERT_ERROR_WRONG_CA_USED,
} PvCertErrors;

/** PvX509WithPath - X509 certificate associated with a path.
 *
 */
typedef struct {
	X509 *cert;
	const char *path;
} PvX509WithPath;

/** pv_x509_with_path_new() - create a new PvX509WithPath
 *
 *  @cert: X509 certificate
 *  @path: Path of that X509 certificate
 */
PvX509WithPath *pv_x509_with_path_new(X509 *cert, const char *path);

/** pv_x509_with_path_free() - free a PvX509WithPath
 *
 * frees the path and the PvX509WithPath; Decreases the refcount of the X509
 */
void pv_x509_with_path_free(PvX509WithPath *cert);

typedef STACK_OF(DIST_POINT) STACK_OF_DIST_POINT;
typedef STACK_OF(X509) STACK_OF_X509;
typedef STACK_OF(X509_CRL) STACK_OF_X509_CRL;
typedef GSList PvCertWithPathList;

typedef struct {
	X509 *cert;
	STACK_OF_X509_CRL *crls;
} PvX509Pair;

/** pv_x509_pair_new_take() - take X509 + CRLs and build a pair
 * @cert: ptr to X509
 * @crls: ptr to CRLs
 *
 * Takes a X509 and the associated CRLs and builds a pair.
 * Both, *cert and *crls will be NULL afterwards, and owned by the pair.
 *
 * Return:
 * 	New PvX509Pair
 */
PvX509Pair *pv_x509_pair_new_take(X509 **cert, STACK_OF_X509_CRL **crls);

/** pv_x509_pair_free() - free a PvX509Pair
 *
 * Decreases the refcount of the X509 and crls.
 * Frees the PvX509Pair.
 */
void pv_x509_pair_free(PvX509Pair *pair);

void STACK_OF_DIST_POINT_free(STACK_OF_DIST_POINT *stack);
void STACK_OF_X509_free(STACK_OF_X509 *stack);
void STACK_OF_X509_CRL_free(STACK_OF_X509_CRL *stack);

/** pv_x509_from_pem_der_data() - create X509 from PEM
 *
 * @data: GBytes containing the cert in PEM format
 * @error: return location for a #GError
 *
 * return:
 * 	X509 cert
 * 	NULL on error
 */
X509 *pv_x509_from_pem_der_data(GBytes *data, GError **error);

/** pv_read_ec_pubkey_cert() - get public key from X509
 *
 * @cert: X509 to extract pubkey from
 * @nid: numerical identifier of the expected curve
 * @error: return location for a #GError
 *
 * Return:
 * 	corresponding pupkey for the given certificate
 * 	NULL on error
 */
EVP_PKEY *pv_read_ec_pubkey_cert(X509 *cert, int nid, GError **error);

typedef GSList PvEvpPkeyList;

/** pv_get_evp_pubkeys() - get EVP_PKEY for each cert
 *
 * @certs_with_path: List of PvX509WithPath
 * @nid: numerical identifier of the expected curve
 * @error: return location for a #GError
 *
 * Return:
 * 	List of corresponding pupkeys for the given certificate
 * 	NULL on error
 */
PvEvpPkeyList *pv_get_evp_pubkeys(PvCertWithPathList *certs_with_path, int nid,
				  GError **error);

/* pv_load_certificates() - load certificates from the given paths
 *
 * @cert_paths: list of cert paths.
 * @error: return location for a #GError
 *
 * Return:
 * 	List of PvX509WithPath corresponding to the given paths
 * 	NULL on error
 *
 * @cert_paths must contain at least one element, otherwise an error is
 * reported.
 */
PvCertWithPathList *pv_load_certificates(const char *const *cert_paths,
					 GError **error);

/* pv_load_first_cert_from_file() - Load the first certificate in the given path
 *
 * @path: location of the x509
 * @error: return location for a #GError
 *
 * Return:
 * 	PvX509WithPath corresponding to the given path
 * 	NULL on error
 *
 * This function reads in only the first certificate and ignores all other. This
 * is only relevant for the PEM file format. For the host-key document and the
 * root CA this behavior is expected.
 */
X509 *pv_load_first_cert_from_file(const char *path, GError **error);

/* pv_load_first_crl_from_file() - Load the first CRL in the given path
 *
 * @path: location of the x509 CRL
 * @error: return location for a #GError
 *
 * Return:
 * 	X509_CRL corresponding to the given path
 * 	NULL on error
 *
 * This function reads in only the first CRL and ignores all other. This
 * is only relevant for the PEM file format.
 */
X509_CRL *pv_load_first_crl_from_file(const char *path, GError **error);

/** pv_store_setup_crl_download() - prepare the X509_Store for downloading CRLs
 *
 * @st: X509_STORE
 */
void pv_store_setup_crl_download(X509_STORE *st);

/** pv_load_first_crl_by_cert() loads first CRL from the location specified in the given X509
 * @cert: X509 to specify the download location.
 * @error: return location for a #GError
 *
 * Return:
 * 	x509 CRL corresponding to the given X509
 * 	NULL on error
 *
 * This function returns the first X509_CRL found from the CRL distribution
 * points specified in @cert.
 */
X509_CRL *pv_load_first_crl_by_cert(X509 *cert, GError **error);

/** pv_try_load_crls_by_certs() - load CRLs corresponding to the given X509s
 *
 * @certs_with_path: List of PvX509WithPath
 *
 * Returns:
 * 	Stack of CRLs corresponding to the given X509
 * 	NULL on error
 */
STACK_OF_X509_CRL *
pv_try_load_crls_by_certs(PvCertWithPathList *certs_with_path);

/** pv_store_setup() - setup a X509_SOTRE for later verrification
 *
 *
 * @root_ca_path: Location of the rootCA or NULL if SystemRoot CA shall be used
 * @crl_paths: List of CRL paths or NULL
 * @cert_with_crl_paths: List of (untrusted) X509 paths
 * @error: return location for a #GError
 *
 * Return:
 * 	X509_store with given input data.
 * 	NULL on error
 *
 * The untrusted certs need to be verified before actually verifying a Host Key Document.
 *
 */
X509_STORE *pv_store_setup(const char *root_ca_path,
			   const char *const *crl_paths,
			   const char *const *cert_with_crl_paths,
			   GError **error);

/** pv_get_x509_stack() - convert a PvCertWithPathList to a STACK_OF_X509
 *
 * x509_with_path_list: list of PvX509WithPath
 *
 * Return:
 * 	Stack of X509 corresponding to the given x509 with path
 */
STACK_OF_X509 *pv_get_x509_stack(const GSList *x509_with_path_list);

/** pv_init_store_ctx() - Initializes the Store CTX
 *
 * @ctx: a uninitialized Store CTX
 * @trusted: X509_STORE with a trusted rootCA
 * @chain: untrusted X509s
 * @error: return location for a #GError
 *
 * Return:
 * 	0 on success
 * 	-1 in failure
 *
 * Can be called multiple times on the same context if X509_STORE_CTX_cleanup(ctx)
 * was called before.
 */
int pv_init_store_ctx(X509_STORE_CTX *ctx, X509_STORE *trusted,
		      STACK_OF_X509 *chain, GError **error) PV_NONNULL(1, 2, 3);

/** pv_init_store_ctx() - Creates the Store CTX
 *
 * @trusted: X509_STORE with a trusted rootCA
 * @chain: untrusted X509s
 * @error: return location for a #GError
 *
 * Return:
 * 	X509_STORE_CTX setup with the input data
 * 	NULL on error
 */
X509_STORE_CTX *pv_create_store_ctx(X509_STORE *trusted, STACK_OF_X509 *chain,
				    GError **error) PV_NONNULL(1, 2);
/** pv_remove_ibm_signing_certs() - extract all IBM signing keys
 *
 * @certs: Stack of X509s
 *
 * Return:
 * 	List of all IBM Z signing key certificates in @certs and remove them
 * 		from the chain.
 * 	Empty stack if no IBM Z signing key is found.
 */
STACK_OF_X509 *pv_remove_ibm_signing_certs(STACK_OF_X509 *certs);

/** pv_c2b_name() - workaround for issuer name and subject name mismatch
 *
 * Workaround to fix the mismatch between issuer name of the
 * IBM Z signing CRLs and the IBM Z signing key subject name.
 *
 * In RFC 5280 the attributes of a (subject/issuer) name is not mandatory
 * ordered. The problem is that our certificates are not consistent in the order
 * (see https://tools.ietf.org/html/rfc5280#section-4.1.2.4 for details).
 *
 * This function tries to reorder the name attributes such that
 * further OpenSSL calls can work with it.  The caller is
 * responsible to free the returned value.
 */
X509_NAME *pv_c2b_name(const X509_NAME *name);

/** pv_verify_host_key() - verify a Host key with given IBM signing keys
 *
 * @host_key: X509 to be verified
 * @issuer_pairs: IBM signing key X509+CRLs Pairs used for verification
 * @level: Security level. see PV_CERTS_SECURITY_LEVEL
 * @error: return location for a #GError
 *
 * Return:
 * 	0 if Host key could be verified with one of the IBM signing keys
 * 	-1 if no IBM signing key could verify the authenticity of the given host key
 *
 */
int pv_verify_host_key(X509 *host_key, GSList *issuer_pairs, int verify_flags,
		       int level, GError **error);

/** pv_verify_cert() - verify the given cert with the given X509_SORE_CTX
 *
 * @cert: X509 to be verified
 * @ctx: trusted store ctx used for verification
 * @error: return location for a #GError
 *
 * Return:
 * 	0 if @cert could be verified
 * 	-1 if @cert could not be verified
 *
 * Cannot be used to verify host keys with IBM signing keys, as IBM signing
 * keys are no intermediate CAs. Use pv_verify_host_key() instead.
 */
int pv_verify_cert(X509 *cert, X509_STORE_CTX *ctx, GError **error)
	PV_NONNULL(1, 2);

/** pv_check_crl_valid_for_cert() - verify that the given CRL is valid
 *
 * @crl: CRL to be verified
 * @cert: Cert that probably issued the given CRL
 * @verify_flags: X509 Verification flags (X509_V_FLAG_<TYPE>)
 * @error: return location for a #GError
 *
 * Return:
 * 	 0 if @crl is valid and issued by @cert
 * 	 -1 otherwise
 *
 * Verify whether a revocation list @crl is valid and is issued by @cert. For
 * this multiple steps must be done:
 *
 * 1. verify issuer of the CRL matches with the suject name of @cert
 * 2. verify the validity period of the CRL
 * 3. verify the signature of the CRL
 *
 * Important: This function does not verify whether @cert is allowed to issue a
 * CRL. */
int pv_check_crl_valid_for_cert(X509_CRL *crl, X509 *cert, int verify_flags,
				GError **error);

/** pv_check_chain_parameters() - verify that the given chain is valid
 *
 * @chain: chain of trust to be validated
 * @error: return location for a #GError
 *
 * Return:
 * 	 0 @chain is valid
 * 	 -1 otherwise
 *
 * Verifies that chain has at least a RootCA ans intermediate CA
 * and logs the used ROD CA subject
 */
int pv_check_chain_parameters(const STACK_OF_X509 *chain, GError **error);

/** pv_store_set_verify_param() - set X509_STORE verify parameters
 *
 * @store: X509_STORE to set parameters
 * @error: return location for a #GError
 *
 * Return:
 * 	0 on success
 * 	-1 on failure
 */
int pv_store_set_verify_param(X509_STORE *store, GError **error);

/** pv_store_ctx_find_valid_crls() - find CRLs in X509_STORE
 *
 * @ctx: STORE_CTX for searching CRLs
 * @cert: X509 to match CRLs aggainst
 * @error: return location for a #GError
 *
 * Return:
 * 	STACK of CRLs related to given @crl fin @ctx
 * 	NULL if no CRL found
 */
STACK_OF_X509_CRL *pv_store_ctx_find_valid_crls(X509_STORE_CTX *ctx, X509 *cert,
						GError **error)
	PV_NONNULL(1, 2);

/** pv_verify_host_key_doc() - verify if the given host key documents are valid
 *
 * @host_key_certs_with_path: X509s to be verified
 * @trusted. X509_STORE with a rusted RootCA
 * @untrusted_certs: STACK OF untrusted X509s
 * @online: true if CRLs shall be downloaded
 * @error: return location for a #GError
 *
 * Return:
 * 	0 if all given HKDs could be verfied using the chain of trust.
 * 	-1 otherwise
 */
int pv_verify_host_key_doc(PvCertWithPathList *host_key_certs_with_path,
			   X509_STORE *trusted, STACK_OF_X509 *untrusted_certs,
			   gboolean online, GError **error) PV_NONNULL(1, 2, 3);

/** pv_verify_host_key_doc_by_path() - verify if the given host key documents are valid
 *
 * @host_key_paths: locations of X509 to be verified
 * @optional_root_ca_path: rootCA location or NULL if Default shall be used
 * @optional_crl_paths: locations of CRLs or NULL
 * @untrusted_cert_paths: locations of IntermediateCAs including the IBM signing key
 * @online: true if CRLs shall be downloaded
 * @error: return location for a #GError
 *
 * Return:
 * 	0 if all given HKDs could be verfied using the chain of trust.
 * 	-1 otherwise
 */
int pv_verify_host_key_doc_by_path(const char *const *host_key_paths,
				   const char *optional_root_ca_path,
				   const char *const *optional_crl_paths,
				   const char *const *untrusted_cert_paths,
				   gboolean online, GError **error)
	PV_NONNULL(1, 4);

WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(AUTHORITY_KEYID, AUTHORITY_KEYID_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(PvX509WithPath, pv_x509_with_path_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(STACK_OF_DIST_POINT,
				      STACK_OF_DIST_POINT_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(STACK_OF_X509, STACK_OF_X509_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(STACK_OF_X509_CRL, STACK_OF_X509_CRL_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509, X509_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509_CRL, X509_CRL_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509_LOOKUP, X509_LOOKUP_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509_NAME, X509_NAME_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509_VERIFY_PARAM, X509_VERIFY_PARAM_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(PvX509Pair, pv_x509_pair_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509_STORE, X509_STORE_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509_STORE_CTX, X509_STORE_CTX_free)
