/*
 * Config file.
 * Must be include before any other header.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */
#pragma once
#define GETTEXT_PACKAGE "pvattest"

#ifdef __GNUC__
#ifdef __s390x__
#ifndef PVATTEST_NO_MEASURE
#define PVATTEST_COMPILE_MEASURE
#endif
#endif
#endif

#ifdef __clang__
#ifdef __zarch__
#ifndef PVATTEST_NO_MEASURE
#define PVATTEST_COMPILE_MEASURE
#endif
#endif
#endif
