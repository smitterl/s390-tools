#pragma once

#if (__GNUC__ == 3 && __GNUC_MINOR__ >= 3) || __GNUC__ > 3
#define PV_NONNULL(...) __attribute__((nonnull(__VA_ARGS__)))
#else
#define PV_NONNULL(...)
#endif

#define DO_PRAGMA(x) _Pragma(#x)
