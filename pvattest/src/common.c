/*
 * Common functions for pvattest.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include "config.h"

#include <stdio.h>

#include "libpv/glib-helper.h"
#include <glib/gstdio.h>

#include "types.h"
#include "common.h"

GBytes *pv_file_to_g_bytes(const char *filename, GError **error)
{
	g_autofree char *data = NULL;
	size_t data_size;

	if (!g_file_get_contents(filename, &data, &data_size, error))
		return NULL;

	return g_bytes_new_take(g_steal_pointer(&data), data_size);
}

gboolean wrapped_g_file_set_content(const char *filename, GBytes *bytes,
				    int mode, GError **error)
{
	gconstpointer data;
	size_t size;
	gboolean rc;

	data = g_bytes_get_data(bytes, &size);
#if GLIB_CHECK_VERSION(2, 66, 0)
	rc = g_file_set_contents_full(filename, data, (gssize)size,
				      G_FILE_SET_CONTENTS_CONSISTENT |
					      G_FILE_SET_CONTENTS_ONLY_EXISTING,
				      mode, error);
#else
	rc = g_file_set_contents(filename, data, (ssize_t)size, error);
	if (rc && mode != 0666)
		g_chmod(filename, (uint)mode);
#endif
	return rc;
}

gconstpointer gbytes_get_data0(GBytes *bytes, size_t *size)
{
	if (!bytes) {
		if (size)
			*size = 0;
		return NULL;
	}
	return g_bytes_get_data(bytes, size);
}

size_t gbytes_get_size0(GBytes *bytes)
{
	if (!bytes)
		return 0;
	return g_bytes_get_size(bytes);
}

GBytes *gbytes_ref0(GBytes *bytes)
{
	if (!bytes)
		return NULL;
	return g_bytes_ref(bytes);
}

GBytes *secure_gbytes_concat(GBytes *lh, GBytes *rh)
{
	g_autoptr(GByteArray) lha = NULL;

	if (!lh && !rh)
		return NULL;
	if (!lh)
		return g_bytes_ref(rh);
	if (!rh)
		return g_bytes_ref(lh);
	lha = g_bytes_unref_to_array(g_bytes_ref(lh));
	g_byte_array_append(lha, g_bytes_get_data(rh, NULL),
			    (guint)g_bytes_get_size(rh));
	return pv_sec_gbytes_new(lha->data, lha->len);
}
