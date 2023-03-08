// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <errno.h>
#include <openenclave/internal/time.h>
#include <time.h>
#include "../ocalls.h"

static const uint64_t _SEC_TO_MSEC = 1000UL;
static const uint64_t _MSEC_TO_NSEC = 1000000UL;

/* Return milliseconds elapsed since the Epoch. */
static uint64_t _time()
{
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return 0;

    return ((uint64_t)ts.tv_sec * _SEC_TO_MSEC) +
           ((uint64_t)ts.tv_nsec / _MSEC_TO_NSEC);
}

static void _sleep(uint64_t milliseconds)
{
    struct timespec ts;
    const struct timespec* req = &ts;
    struct timespec rem = {0, 0};

    ts.tv_sec = (time_t)(milliseconds / _SEC_TO_MSEC);
    ts.tv_nsec = (long)((milliseconds % _SEC_TO_MSEC) * _MSEC_TO_NSEC);

    while (nanosleep(req, &rem) != 0 && errno == EINTR)
    {
        req = &rem;
    }
}

void oe_handle_sleep(uint64_t arg_in)
{
    const uint64_t milliseconds = arg_in;
    _sleep(milliseconds);
}

void oe_handle_get_time(uint64_t arg_in, uint64_t* arg_out)
{
    OE_UNUSED(arg_in);

    if (arg_out)
        *arg_out = _time();
}
