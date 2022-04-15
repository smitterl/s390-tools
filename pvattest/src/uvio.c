/*
 * UV device (uvio) related functions and definitions.
 * uses s390 only (kernel) features.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include "config.h"

#ifdef PVATTEST_COMPILE_MEASURE
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/ioctl.h>
#include <unistd.h>

#include "attestation.h"
#include "uvio.h"
#include "common.h"
#include "log.h"

__u64 ptr_to_u64(void *ptr)
{
	return (uint64_t)ptr;
}

void *u64_to_ptr(__u64 v)
{
	return (void *)v;
}

uvio_attest_t *build_attestation_v1_ioctl(GBytes *serialized_arcb,
					  GBytes *user_data,
					  uint32_t measurement_size,
					  uint32_t add_data_size,
					  GError **error)
{
	g_autoptr(uvio_attest_t) uvio_attest = NULL;
	size_t arcb_size;
	g_bytes_ref(serialized_arcb);
	gpointer arcb = g_bytes_unref_to_data(serialized_arcb, &arcb_size);

	uvio_attest = g_malloc0(sizeof(*uvio_attest));
	uvio_attest->arcb_addr = ptr_to_u64(arcb);
	uvio_attest->arcb_len = GUINT32_TO_BE((uint32_t)arcb_size);
	//transferred the ownership of the arcb to uvio_attest; nullify pointer
	g_steal_pointer(&serialized_arcb);

	if (user_data) {
		if (g_bytes_get_size(user_data) >
		    sizeof(uvio_attest->user_data)) {
			g_set_error(error, ATT_ERROR, ATT_ERR_INVALID_USER_DATA,
				    "user_data larger than %li bytes",
				    sizeof(uvio_attest->user_data));
			return NULL;
		}
		uvio_attest->user_data_len =
			GUINT16_TO_BE((uint16_t)g_bytes_get_size(user_data));
		memcpy(uvio_attest->user_data,
		       g_bytes_get_data(user_data, NULL),
		       uvio_attest->user_data_len);
	}

	uvio_attest->meas_len = GUINT32_TO_BE(measurement_size);
	uvio_attest->meas_addr = ptr_to_u64(g_malloc0(uvio_attest->meas_len));

	uvio_attest->add_data_len = GUINT32_TO_BE(add_data_size);
	uvio_attest->add_data_addr =
		ptr_to_u64(g_malloc0(uvio_attest->add_data_len));

	return g_steal_pointer(&uvio_attest);
}

void uvio_attest_free(uvio_attest_t *attest)
{
	if (!attest)
		return;
	g_free(u64_to_ptr(attest->arcb_addr));
	g_free(u64_to_ptr(attest->meas_addr));
	g_free(u64_to_ptr(attest->add_data_addr));
	g_free(attest);
}

GBytes *uvio_get_measurement(uvio_attest_t *attest)
{
	if (attest->meas_addr == (__u64)0)
		return NULL;
	return g_bytes_new(u64_to_ptr(attest->meas_addr),
			   GUINT32_FROM_BE(attest->meas_len));
}

GBytes *uvio_get_additional_data(uvio_attest_t *attest)
{
	if (attest->add_data_addr == (__u64)0)
		return NULL;
	return g_bytes_new(u64_to_ptr(attest->add_data_addr),
			   GUINT32_FROM_BE(attest->add_data_len));
}

GBytes *uvio_get_config_uid(uvio_attest_t *attest)
{
	return g_bytes_new(attest->config_uid, UVIO_ATT_UID_LEN);
}

be16_t uvio_ioctl(int uv_fd, unsigned int cmd, uint32_t flags, void *argument,
		  uint32_t argument_size, GError **error)
{
	g_autofree struct uvio_ioctl_cb *uv_ioctl =
		g_malloc0(sizeof(*uv_ioctl));
	int rc, cached_errno;

	uv_ioctl->flags = flags;
	uv_ioctl->argument_addr = ptr_to_u64(argument);
	uv_ioctl->argument_len = argument_size;
	rc = ioctl(uv_fd, cmd, uv_ioctl);
	cached_errno = errno;

	if (rc < 0) {
		g_set_error(error, UVIO_ERROR, UVIO_ERR_UV_IOCTL,
			    "ioctl failed: %s ", g_strerror(cached_errno));
		return 0;
	}

	if (uv_ioctl->uv_rc != UVC_EXECUTED)
		g_set_error(error, UVIO_ERROR, UVIO_ERR_UV_NOT_OK,
			    "Ultravisor call returned 'NOT OK'. rc: %#x (%s)",
			    uv_ioctl->uv_rc, uvio_uv_rc_to_str(rc));
	return uv_ioctl->uv_rc;
}

be16_t uvio_ioctl_attest(int uv_fd, uvio_attest_t *attest, GError **error)
{
	return uvio_ioctl(uv_fd, UVIO_IOCTL_ATT, 0, attest, sizeof(*attest),
			  error);
}

int uvio_access_uv(const char *uv_path, GError **error)
{
	int uv_fd;
	int cached_errno;

	uv_fd = open(uv_path, O_RDWR);
	cached_errno = errno;
	if (uv_fd < 0)
		g_set_error(error, UVIO_ERROR, UVIO_ERR_UV_OPEN,
			    "Cannot open uv driver at %s: %s", uv_path,
			    g_strerror(cached_errno));
	return uv_fd;
}

const char *uvio_uv_rc_to_str(const int rc)
{
	switch (rc) {
	case 0x106:
		return "Unsupported attestation request version";
	case 0x108:
		return "Number of key slots is greater than the maximum number supported.";
	case 0x10a:
		return "Unsupported plaintext attestation flags";
	case 0x10c:
		return "Unable to unseal attestation request control block. No valid host-key was provided.";
	case 0x10d:
		return "Measurement data length is not large enough to store measurement";
	case 0x10e:
		return "Additional data length is not large enough to store measurement";
	default:
		return "Unknown code.";
	}
}

#endif /* PVATTEST_COMPILE_MEASURE */
