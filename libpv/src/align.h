/*
 * Internal common definitions.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#pragma once

#define PV_ALIGN(x, a) PV_ALIGN_MASK(x, (typeof(x))(a)-1)
#define PV_ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))
