/*
 * Glib convenience functions
 * Shall be used instead of manually including glib.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#pragma once

#if defined(GLIB_VERSION_MIN_REQUIRED)
#if GLIB_VERSION_MIN_REQUIRED < GLIB_VERSION_2_56
#error "GLIB_VERSION must be at least 2.56"
#endif
#else
#define GLIB_VERSION_MIN_REQUIRED GLIB_VERSION_2_56
#endif

#include "libpv/openssl-compat.h"

#include <glib.h>
#include <gmodule.h>
#include <stdio.h>

#ifdef __clang__
#define WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(...)                             \
	DO_PRAGMA(clang diagnostic push)                                       \
	DO_PRAGMA(clang diagnostic ignored "-Wunused-function")                \
	G_DEFINE_AUTOPTR_CLEANUP_FUNC(__VA_ARGS__)                             \
	DO_PRAGMA(clang diagnostic pop)
#else
#define WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(...)                             \
	G_DEFINE_AUTOPTR_CLEANUP_FUNC(__VA_ARGS__)
#endif

/** pv_sec_gbytes_new_take() - #g_bytes_new_take() with secure cleanup
 */
GBytes *pv_sec_gbytes_new_take(void *data, size_t size);

/** pv_sec_gbytes_new() - #g_bytes_new() with secure cleanup
 */
GBytes *pv_sec_gbytes_new(const void *data, size_t size);

/** pv_get_content_as_secure_bytes() - read file and save as secure gbytes
 *
 * @filename: path to file for reading in
 *
 * Return:
 * 	Content of file as #GBytes with secure cleanup
 */
GBytes *pv_get_content_as_secure_bytes(const char *filename);

/** pv_file_seek() - fseek with error reporting
 */
int pv_file_seek(FILE *file, long offset, int whence, GError **error);

/** pv_file_write() - fwrite with error reporting
 */
size_t pv_file_write(FILE *file, const void *ptr, size_t size, GError **error);

/** pv_file_close() - fclose with error reporting
 */
long pv_file_close(FILE *file, GError **error);

/** pv_file_tell() - ftell with error reporting
 */
long pv_file_tell(FILE *file, GError **error);

/** pv_file_open() - fopen with error reporting
 */
FILE *pv_file_open(const char *filename, const char *mode, GError **error);

#define PV_GLIB_HELPER_ERROR                                                   \
	g_quark_from_static_string("pv-glib-helper_error-quark")
typedef enum {
	PV_GLIB_HELPER_FILE_ERROR,
} pv_glib_helper_error_e;
