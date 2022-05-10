/*
 * OpenSSL compatibility utils
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#pragma once

#include <openssl/opensslv.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#define Pv_X509_STORE_CTX_get_current_cert(ctx)                                \
	X509_STORE_CTX_get_current_cert(ctx)
#define Pv_X509_STORE_CTX_get1_crls(ctx, nm)                                   \
	X509_STORE_CTX_get1_crls((ctx), (nm))
#define Pv_X509_STORE_set_lookup_crls(st, cb) X509_STORE_set_lookup_crls(st, cb)
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
#define Pv_X509_STORE_CTX_get_current_cert(ctx)                                \
	X509_STORE_CTX_get_current_cert((X509_STORE_CTX *)(ctx))
#define Pv_X509_STORE_CTX_get1_crls(ctx, nm)                                   \
	X509_STORE_CTX_get1_crls((X509_STORE_CTX *)(ctx), (X509_NAME *)(nm))
#define Pv_X509_STORE_set_lookup_crls(st, cb)                                  \
	X509_STORE_set_lookup_crls(st, (X509_STORE_CTX_lookup_crls_fn)(cb))
#endif
