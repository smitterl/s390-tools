/*
 * UV device (uvio) related functions and definitions.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#pragma once

#ifdef PVATTEST_COMPILE_MEASURE
#include "libpv/glib-helper.h"

#include <sys/ioctl.h>

#include "arcb.h"
#include "common.h"

#include <asm/uvdevice.h>
#define UVC_EXECUTED 0x0001

typedef int uv_fd_t;

typedef struct uvio_attest uvio_attest_t;
STATIC_ASSERT(sizeof(uvio_attest_t) == 0x138);
STATIC_ASSERT(sizeof(struct uvio_ioctl_cb) == 0x40);

/* some helper functions */
__u64 ptr_to_u64(void *ptr);
void *u64_to_ptr(__u64 v);

/* serializes arcb; arcb can be drooped afterwards if not needed anymore */
uvio_attest_t *build_attestation_v1_ioctl(GBytes *serialized_arcb,
					  GBytes *user_data,
					  uint32_t measurement_size,
					  uint32_t add_data_size,
					  GError **error);
GBytes *uvio_get_measurement(uvio_attest_t *attest);
GBytes *uvio_get_additional_data(uvio_attest_t *attest);
GBytes *uvio_get_config_uid(uvio_attest_t *attest);
void uvio_attest_free(uvio_attest_t *attest);
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(uvio_attest_t, uvio_attest_free)

be16_t uvio_ioctl(int uv_fd, unsigned int cmd, uint32_t flags, void *argument,
		  uint32_t argument_size, GError **error);
be16_t uvio_ioctl_attest(int uv_fd, uvio_attest_t *attest, GError **error);
int uvio_access_uv(const char *uv_path, GError **error);
const char *uvio_uv_rc_to_str(const int rc);

#define UVIO_ERROR g_quark_from_static_string("pv-uvio_error-quark")
typedef enum {
	UVIO_ERR_UV_IOCTL,
	UVIO_ERR_UV_OPEN,
	UVIO_ERR_UV_NOT_OK,
} uvio_error_e;

#endif /* PVATTEST_COMPILE_MEASURE */
