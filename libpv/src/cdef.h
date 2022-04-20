/*
 * Internal common definitions.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#pragma once

#ifndef GETTEXT_PACKAGE
#define GETTEXT_PACKAGE "libpv"
#endif

#include <openssl/err.h>
static inline const char *get_openssl_error(void)
{
	const char *ret;
	BIO *bio;
	char *buf;
	long len;

	bio = BIO_new(BIO_s_mem());
	ERR_print_errors(bio);
	len = BIO_get_mem_data(bio, &buf);
	if (len < 0)
		ret = "Cannot receive OpenSSL error message.";
	else
		ret = g_strndup(buf, (size_t)len);
	BIO_free(bio);
	return ret;
}
