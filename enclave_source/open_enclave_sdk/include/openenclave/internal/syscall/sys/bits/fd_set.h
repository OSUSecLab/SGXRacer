// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

typedef struct
{
    uint64_t fds_bits[OE_FD_SETSIZE / 8 / sizeof(uint64_t)];
} __OE_FD_SET;
