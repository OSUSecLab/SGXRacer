// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <cstddef>

#include "../edltestutils.h"
#include "all_t.h"

int aliasing_a(const char* d, size_t c)
{
    OE_UNUSED(d);
    OE_UNUSED(c);
    return 0;
}

int aliasing_b(char** e, size_t* g, size_t f, char* h, size_t i, size_t* j)
{
    OE_UNUSED(e);
    OE_UNUSED(g);
    OE_UNUSED(f);
    OE_UNUSED(h);
    OE_UNUSED(i);
    OE_UNUSED(j);
    return 0;
}

int aliasing_c(char* a)
{
    OE_UNUSED(a);
    return 0;
}
