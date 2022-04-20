/*
 * Libpv common definitions.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */
#pragma once

#include "libpv/glib-helper.h"

#include <glib/gi18n-lib.h>

#include "libpv/openssl-compat.h"
#include "libpv/macros.h"

#define DEFAULT_INITIAL_PSW_ADDR IMAGE_ENTRY
#define DEFAULT_INITIAL_PSW_MASK (PSW_MASK_EA | PSW_MASK_BA)

#define log_debug(fmt, ...)                                                    \
	util_log_print(UTIL_LOG_DEBUG, fmt "\n", ##__VA_ARGS__)
#define log_err(fmt, ...)                                                      \
	util_log_print(UTIL_LOG_ERROR, fmt "\n", ##__VA_ARGS__)
#define log_info(fmt, ...)                                                     \
	util_log_print(UTIL_LOG_INFO, fmt "\n", ##__VA_ARGS__)
#define log_warn(fmt, ...)                                                     \
	util_log_print(UTIL_LOG_WARN, fmt "\n", ##__VA_ARGS__)
#define log_u64(v) log_debug("%s: 0x%lx\n", #v, v)

#define pv_nonnull(...) __attribute__((nonnull(__VA_ARGS__)))

/** pv_init() - initialize libpv.
 *
 * Must be called before any libpv call.
 */
int pv_init(void);

/** pv_cleanup() cleanup libpv
 *
 * Must be called when done with using libpv.
 */
void pv_cleanup(void);
