/*
 * Libcurl utils
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#pragma once

#include "libpv/common.h"

#include <curl/curl.h>

#define CRL_DOWNLOAD_TIMEOUT_MS 3000
#define CRL_DOWNLOAD_MAX_SIZE 0x100000

WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(CURL, curl_easy_cleanup)

/** curl_download() - download from URL
 * @url: URL to specify location of data
 * @timeout_ms: time to wait until fail
 * @max_size: Maximum size of the downloaded data
 * @error: return location for a GError
 *
 * Returns:
 * 	Downloaded data as #GByteArray, or NULL in case of error
 */
GByteArray *curl_download(const char *url, long timeout_ms, uint max_size,
			  GError **err);

/** pv_curl_init() - initialize libcurl handling.
 *
 * Should not be called by user.
 * Use pv_init() instead which
 * calls this function during creation.
 */
int pv_curl_init(void);

/** pv_curl_cleanup() - cleanup libcurl handling.
 *
 * Should not be called by user.
 * Use pv_cleanup() instead which
 * calls this function during creation.
 */
void pv_curl_cleanup(void);
