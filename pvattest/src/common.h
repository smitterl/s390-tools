/*
 * Common functions for pvattest.
 *
 *  IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#pragma once
#include "libpv/glib-helper.h"

#include <glib/gi18n-lib.h>
#include <stdio.h>

#include "libpv/macros.h"
#include "lib/zt_common.h"

#include "types.h"

#define COPYRIGHT_NOTICE "Copyright IBM Corp. 2022"

#define AES_256_GCM_TAG_SIZE 16
GBytes *pv_file_to_g_bytes(const char *filename, GError **error);

gboolean wrapped_g_file_set_content(const char *filename, GBytes *bytes,
				    int mode, GError **error);

gconstpointer gbytes_get_data0(GBytes *bytes, size_t *size);
size_t gbytes_get_size0(GBytes *bytes);
GBytes *gbytes_ref0(GBytes *bytes);
/**
 * just ref's up if one of them is NULL.
 * If both NULL returns NULL.
 * Otherwise returns lh ++ rh
 */
GBytes *secure_gbytes_concat(GBytes *lh, GBytes *rh);
