// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_DEFS_H
#define _OE_INTERNAL_DEFS_H

#include <openenclave/bits/defs.h>

/* OE_WEAK_ALIAS */
#define OE_WEAK_ALIAS(OLD, NEW) \
    extern __typeof(OLD) NEW __attribute__((__weak__, alias(#OLD)))

/* OE_ZERO_SIZED_ARRAY */
#ifdef _WIN32
/* nonstandard extension used: zero-sized array in struct/union */
#define OE_ZERO_SIZED_ARRAY __pragma(warning(suppress : 4200))
#else
#define OE_ZERO_SIZED_ARRAY /* empty */
#endif

/*
 * Define packed types, such as:
 *     OE_PACK_BEGIN
 *     struct foo {int a,b};
 *     OE_PACK_END
 */
#if defined(__GNUC__)
#define OE_PACK_BEGIN _Pragma("pack(push, 1)")
#define OE_PACK_END _Pragma("pack(pop)")
#elif _MSC_VER
#define OE_PACK_BEGIN __pragma(pack(push, 1))
#define OE_PACK_END __pragma(pack(pop))
#else
#error "OE_PACK_BEGIN and OE_PACK_END not implemented"
#endif

/* OE_CHECK_SIZE */
#define OE_CHECK_SIZE(N, M)          \
    typedef unsigned char OE_CONCAT( \
        __OE_CHECK_SIZE, __LINE__)[((N) == (M)) ? 1 : -1] OE_UNUSED_ATTRIBUTE

/* OE_FIELD_SIZE */
#define OE_FIELD_SIZE(TYPE, FIELD) (sizeof(((TYPE*)0)->FIELD))

/* OE_CHECK_FIELD */
#define OE_CHECK_FIELD(T1, T2, F)                               \
    OE_STATIC_ASSERT(OE_OFFSETOF(T1, F) == OE_OFFSETOF(T2, F)); \
    OE_STATIC_ASSERT(sizeof(((T1*)0)->F) == sizeof(((T2*)0)->F));

/* OE_PAGE_SIZE */
#define OE_PAGE_SIZE 0x1000

/* OE_UNUSED_ATTRIBUTE */
#ifdef __GNUC__
#define OE_UNUSED_ATTRIBUTE __attribute__((unused))
#elif _MSC_VER
#define OE_UNUSED_ATTRIBUTE
#else
#error OE_UNUSED_ATTRIBUTE not implemented
#endif

/* OE_CONCAT */
#define __OE_CONCAT(X, Y) X##Y
#define OE_CONCAT(X, Y) __OE_CONCAT(X, Y)

/* OE_STATIC_ASSERT */
#define OE_STATIC_ASSERT(COND)       \
    typedef unsigned char OE_CONCAT( \
        __OE_STATIC_ASSERT, __LINE__)[(COND) ? 1 : -1] OE_UNUSED_ATTRIBUTE

/* OE_FIELD_SIZE */
#define OE_FIELD_SIZE(TYPE, FIELD) (sizeof(((TYPE*)0)->FIELD))

#endif /* _OE_INTERNAL_DEFS_H */
