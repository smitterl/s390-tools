/*
 * Functions for the pvattest exchange format to send attestation requests and responses between
 * machines .
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "libpv/glib-helper.h"

#include "exchange_format.h"
#include "log.h"

struct exchange_shared_hdr {
	be64_t magic;
	be32_t version;
	be32_t size;
} __packed;

struct entry {
	be32_t size;
	be32_t offset;
} __packed;
STATIC_ASSERT(sizeof(struct entry) == 8)
/*
 * If size == 0
 * 	offset ignored.
 * 	(part does not exist)
 * if offset >0 and <0x50 -> invalid format
 * if offset == 0 and size > 0 no data saved, however the request will need this amount of memory to
 * 	succeed.
 * 	Only makes sense for measurement and additional data. This however, is not enforced.
 */

struct _exchange_format_v1_hdr {
	be64_t magic;
	be32_t version;
	be32_t size;
	uint64_t reserved;
	struct entry serialized_arcb;
	struct entry measurement;
	struct entry additional_data;
	struct entry user_data;
	struct entry config_uid;
} __packed;
STATIC_ASSERT(sizeof(exchange_format_v1_hdr_t) == 0x40)

struct _exchange_format_ctx {
	uint32_t version;
	uint32_t req_meas_size;
	uint32_t req_add_size;
	GBytes *serialized_arcb;
	GBytes *measurement;
	GBytes *additional_data;
	GBytes *user_data;
	GBytes *config_uid;
};

/* Use a byte array to avoid any byteorder issues while checking */

#define PVATTEST_EXCHANGE_MAGIC 0x7076617474657374 // pvattest
static const uint8_t exchange_magic[] = { 0x70, 0x76, 0x61, 0x74,
					  0x74, 0x65, 0x73, 0x74 };

exchange_format_ctx_t *exchange_ctx_new(uint32_t version)
{
	exchange_format_ctx_t *ctx = NULL;

	if (version != PVATTEST_EXCHANGE_VERSION_1_00)
		return ctx;

	ctx = g_malloc0(sizeof(*ctx));
	ctx->version = version;
	return ctx;
}

static GBytes *get_content(GBytes *file_content, const struct entry *entry,
			   const size_t max_size, GError **error)
{
	uint64_t size = GUINT32_FROM_BE(entry->size);
	uint64_t offset = GUINT32_FROM_BE(entry->offset);
	size_t file_size = 0;
	const uint8_t *file_content_u8 =
		g_bytes_get_data(file_content, &file_size);

	if (size == 0 || offset == 0)
		return NULL;
	if ((size != 0 &&
	     (offset > 0 && offset < sizeof(exchange_format_v1_hdr_t))) ||
	    offset + size > file_size || size > max_size) {
		g_set_error(error, EXCHANGE_FORMAT_ERROR,
			    EXCHANGE_FORMAT_ERROR_INVALID_FORMAT,
			    "Input file is not in a valid format.");
		return NULL;
	}
	return g_bytes_new(file_content_u8 + offset, size);
}

static gboolean check_format(const struct exchange_shared_hdr *hdr)
{
	if (0 == memcmp(exchange_magic, &hdr->magic, sizeof(exchange_magic)))
		return TRUE;
	return FALSE;
}

exchange_format_ctx_t *exchange_ctx_from_file(const char *filename,
					      GError **error)
{
	g_autoptr(exchange_format_ctx_t) ctx = g_malloc0(sizeof(*ctx));
	g_autoptr(GBytes) file_content = NULL;
	size_t file_size;
	const struct exchange_shared_hdr *hdr = NULL;
	const exchange_format_v1_hdr_t *hdr_v1 = NULL;

	file_content = pv_file_to_g_bytes(filename, error);
	if (!file_content)
		return NULL;
	hdr = (const struct exchange_shared_hdr *)g_bytes_get_data(file_content,
								   &file_size);

	if (file_size < sizeof(*hdr) || !check_format(hdr)) {
		g_set_error(error, EXCHANGE_FORMAT_ERROR,
			    EXCHANGE_FORMAT_ERROR_INVALID_FORMAT,
			    "''%s' is not in a valid format.", filename);
		return NULL;
	}

	if (GUINT32_FROM_BE(hdr->version) != PVATTEST_EXCHANGE_VERSION_1_00) {
		g_set_error(error, EXCHANGE_FORMAT_ERROR,
			    EXCHANGE_FORMAT_ERROR_INVALID_FORMAT,
			    "The version (%#x) of '%s' is not supported",
			    GUINT32_FROM_BE(hdr->version), filename);
		return NULL;
	}

	/* get the header */
	if (file_size < sizeof(exchange_format_v1_hdr_t)) {
		g_set_error(error, EXCHANGE_FORMAT_ERROR,
			    EXCHANGE_FORMAT_ERROR_INVALID_FORMAT,
			    "''%s' is not in a valid format.", filename);
		return NULL;
	}
	hdr_v1 = (const exchange_format_v1_hdr_t *)hdr;

	/* get entries if present */
	ctx->serialized_arcb =
		get_content(file_content, &hdr_v1->serialized_arcb,
			    PVATTEST_ARCB_MAX_SIZE, error);
	if (*error)
		return NULL;
	ctx->measurement = get_content(file_content, &hdr_v1->measurement,
				       PVATTEST_MEASUREMENT_MAX_SIZE, error);
	if (*error)
		return NULL;
	ctx->additional_data =
		get_content(file_content, &hdr_v1->additional_data,
			    PVATTEST_ADDITIONAL_MAX_SIZE, error);
	if (*error)
		return NULL;
	ctx->user_data = get_content(file_content, &hdr_v1->user_data,
				     PVATTEST_USER_DATA_MAX_SIZE, error);
	if (*error)
		return NULL;
	ctx->config_uid = get_content(file_content, &hdr_v1->config_uid,
				      PVATTEST_UID_SIZE, error);
	if (*error)
		return NULL;
	if (gbytes_get_size0(ctx->user_data) > PVATTEST_USER_DATA_MAX_SIZE ||
	    (gbytes_get_size0(ctx->config_uid) != PVATTEST_UID_SIZE &&
	     gbytes_get_size0(ctx->config_uid) != 0)) {
		g_set_error(error, EXCHANGE_FORMAT_ERROR,
			    EXCHANGE_FORMAT_ERROR_INVALID_FORMAT,
			    "''%s' is not in a valid format.", filename);
		return NULL;
	}
	ctx->req_meas_size = GUINT32_FROM_BE(hdr_v1->measurement.size);
	ctx->req_add_size = GUINT32_FROM_BE(hdr_v1->additional_data.size);
	ctx->version = GUINT32_TO_BE(hdr->version);

	return g_steal_pointer(&ctx);
}

void clear_free_exchange_ctx(exchange_format_ctx_t *ctx)
{
	if (!ctx)
		return;

	if (ctx->serialized_arcb)
		g_bytes_unref(ctx->serialized_arcb);
	if (ctx->measurement)
		g_bytes_unref(ctx->measurement);
	if (ctx->additional_data)
		g_bytes_unref(ctx->additional_data);
	if (ctx->user_data)
		g_bytes_unref(ctx->user_data);
	if (ctx->config_uid)
		g_bytes_unref(ctx->config_uid);

	g_free(ctx);
}
void exchange_set_serialized_arcb(exchange_format_ctx_t *ctx,
				  GBytes *serialized_arcb)
{
	g_bytes_unref(ctx->serialized_arcb);
	ctx->serialized_arcb = g_bytes_ref(serialized_arcb);
}

void exchange_set_measurement(exchange_format_ctx_t *ctx, GBytes *measurement)
{
	g_bytes_unref(ctx->measurement);
	ctx->measurement = g_bytes_ref(measurement);
}

void exchange_set_additional_data(exchange_format_ctx_t *ctx,
				  GBytes *additional_data)
{
	g_bytes_unref(ctx->additional_data);
	ctx->additional_data = gbytes_ref0(additional_data);
}

void exchange_set_user_data(exchange_format_ctx_t *ctx, GBytes *user_data)
{
	g_bytes_unref(ctx->user_data);
	ctx->user_data = gbytes_ref0(user_data);
}

void exchange_set_config_uid(exchange_format_ctx_t *ctx, GBytes *config_uid)
{
	g_bytes_unref(ctx->config_uid);
	ctx->config_uid = g_bytes_ref(config_uid);
}

GBytes *exchange_get_serialized_arcb(exchange_format_ctx_t *ctx)
{
	return gbytes_ref0(ctx->serialized_arcb);
}

GBytes *exchange_get_measurement(exchange_format_ctx_t *ctx)
{
	return gbytes_ref0(ctx->measurement);
}

GBytes *exchange_get_additional_data(exchange_format_ctx_t *ctx)
{
	return gbytes_ref0(ctx->additional_data);
}

GBytes *exchange_get_user_data(exchange_format_ctx_t *ctx)
{
	return gbytes_ref0(ctx->user_data);
}

GBytes *exchange_get_config_uid(exchange_format_ctx_t *ctx)
{
	return gbytes_ref0(ctx->config_uid);
}

uint32_t exchange_get_requested_measurement_size(exchange_format_ctx_t *ctx)
{
	return ctx->req_meas_size;
}

uint32_t exchange_get_requested_additional_data_size(exchange_format_ctx_t *ctx)
{
	return ctx->req_add_size;
}

static struct entry add_g_bytes(GBytes *bytes, FILE *file, GError **error)
{
	struct entry result = {};
	long offset;
	size_t size;
	gconstpointer data = g_bytes_get_data(bytes, &size);

	g_assert(size <= G_MAXUINT32);

	offset = pv_file_tell(file, error);
	g_assert(offset <= G_MAXUINT32);
	if (offset < 0)
		return result;

	result.offset = GUINT32_TO_BE((uint32_t)offset);
	result.size = GUINT32_TO_BE((uint32_t)size);
	pv_file_write(file, data, size, error);
	return result;
}

static void auto_close_file(FILE *f)
{
	fclose(f);
}

WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(FILE, auto_close_file)

void exchange_write_to_file(exchange_format_ctx_t *ctx, const char *filename,
			    uint32_t req_measurement_size,
			    uint32_t req_additional_size, GError **error)
{
	g_autoptr(FILE) file = NULL;
	exchange_format_v1_hdr_t hdr = {
		.magic = GUINT64_TO_BE(PVATTEST_EXCHANGE_MAGIC),
		.version = GUINT32_TO_BE(ctx->version),
	};
	uint32_t file_size = sizeof(hdr);
	size_t tmp_size;

	file = pv_file_open(filename, "w", error);
	if (!file)
		return;
	if (pv_file_seek(file, sizeof(exchange_format_v1_hdr_t), SEEK_SET,
			 error))
		return;

	if (ctx->serialized_arcb) {
		hdr.serialized_arcb =
			add_g_bytes(ctx->serialized_arcb, file, error);
		if (*error)
			return;
		file_size += (uint32_t)g_bytes_get_size(ctx->serialized_arcb);
	}
	if (ctx->measurement) {
		hdr.measurement = add_g_bytes(ctx->measurement, file, error);
		if (*error)
			return;
		file_size += (uint32_t)g_bytes_get_size(ctx->measurement);
	} else {
		hdr.measurement.size = GUINT32_TO_BE(req_measurement_size);
	}

	if (ctx->additional_data) {
		hdr.additional_data =
			add_g_bytes(ctx->additional_data, file, error);
		if (*error)
			return;
		file_size += (uint32_t)g_bytes_get_size(ctx->additional_data);
	} else {
		hdr.additional_data.size = GUINT32_TO_BE(req_additional_size);
	}

	if (ctx->user_data) {
		tmp_size = g_bytes_get_size(ctx->user_data);
		g_assert(tmp_size <= PVATTEST_USER_DATA_MAX_SIZE);
		tmp_size =
			MIN(tmp_size,
			    PVATTEST_USER_DATA_MAX_SIZE); /* should be a noop */
		hdr.user_data = add_g_bytes(ctx->user_data, file, error);
		if (*error)
			return;
		file_size += (uint32_t)g_bytes_get_size(ctx->user_data);
	}
	if (ctx->config_uid) {
		tmp_size = g_bytes_get_size(ctx->config_uid);
		g_assert(tmp_size == PVATTEST_UID_SIZE);
		tmp_size =
			MIN(tmp_size, PVATTEST_UID_SIZE); /* should be a noop */
		hdr.config_uid = add_g_bytes(ctx->config_uid, file, error);
		if (*error)
			return;
		file_size += (uint32_t)g_bytes_get_size(ctx->config_uid);
	}
	hdr.size = GUINT32_TO_BE(file_size);
	if (0 != pv_file_seek(file, 0, SEEK_SET, error))
		return;
	if (sizeof(hdr) != pv_file_write(file, &hdr, sizeof(hdr), error))
		return;
	g_assert(pv_file_seek(file, 0, SEEK_END, error) == 0);
	g_assert(pv_file_tell(file, error) == file_size);
	pv_file_close(file, error);
	file = NULL;
}

static void print_entry(const char *name, GBytes *data, gboolean print_data,
			FILE *stream)
{
	if (!data)
		return;
	fprintf(stream, "%s (%#lx bytes)", name, g_bytes_get_size(data));
	if (print_data) {
		fprintf(stream, ":\n");
		printf_hexdump(g_bytes_get_data(data, NULL),
			       g_bytes_get_size(data), 16, "      ", stream);
	}
	fprintf(stream, "\n");
}

void exchange_info_print(exchange_format_ctx_t *ctx, gboolean print_data,
			 FILE *stream)
{
	fprintf(stream, "Version: %#x\n", ctx->version);
	fprintf(stream, "Sections: \n");
	print_entry("  ARCB", ctx->serialized_arcb, print_data, stream);
	print_entry("  Measurement", ctx->measurement, print_data, stream);
	print_entry("  Additional Data", ctx->additional_data, print_data,
		    stream);
	print_entry("  User Data", ctx->user_data, print_data, stream);
	print_entry("  Config UID", ctx->config_uid, print_data, stream);
	if (!ctx->measurement)
		fprintf(stream, "Required Measurement size: %#x\n",
			ctx->req_meas_size);
	if (!ctx->additional_data)
		fprintf(stream, "Required Additional Data size: %#x\n",
			ctx->req_add_size);
}
