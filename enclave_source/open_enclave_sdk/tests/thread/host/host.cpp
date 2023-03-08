// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>
#include "../../../host/sgx/enclave.h"
#include "thread_u.h"

const size_t NUM_THREADS = 8;

void* test_mutex_thread(oe_enclave_t* enclave)
{
    oe_result_t result = enc_test_mutex(enclave);
    OE_TEST(result == OE_OK);

    return NULL;
}

void test_mutex(oe_enclave_t* enclave)
{
    std::thread threads[NUM_THREADS];

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i] = std::thread(test_mutex_thread, enclave);
    }

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i].join();
    }

    size_t count1 = 0;
    size_t count2 = 0;
    OE_TEST(enc_test_mutex_counts(enclave, &count1, &count2) == OE_OK);

    OE_TEST(count1 == NUM_THREADS);
    OE_TEST(count2 == NUM_THREADS);
}

void* waiter_thread(oe_enclave_t* enclave)
{
    oe_result_t result = enc_wait(enclave, NUM_THREADS);
    OE_TEST(result == OE_OK);

    return NULL;
}

void test_cond(oe_enclave_t* enclave)
{
    std::thread threads[NUM_THREADS];

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i] = std::thread(waiter_thread, enclave);
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        OE_TEST(enc_signal(enclave) == OE_OK);
    }

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i].join();
    }
}

void* cb_test_waiter_thread(oe_enclave_t* enclave)
{
    OE_TEST(cb_test_waiter_thread_impl(enclave) == OE_OK);

    return NULL;
}

void* cb_test_signal_thread(oe_enclave_t* enclave)
{
    OE_TEST(cb_test_signal_thread_impl(enclave) == OE_OK);

    return NULL;
}

void test_cond_broadcast(oe_enclave_t* enclave)
{
    std::thread threads[NUM_THREADS];
    std::thread signal_thread;

    printf("test_cond_broadcast Starting\n");

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i] = std::thread(cb_test_waiter_thread, enclave);
    }

    signal_thread = std::thread(cb_test_signal_thread, enclave);

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i].join();
    }

    signal_thread.join();

    printf("test_cond_broadcast Complete\n");
}

void* exclusive_access_thread(oe_enclave_t* enclave)
{
    const size_t ITERS = 2;

    printf("exclusive_access_thread Starting\n");
    for (size_t i = 0; i < ITERS; i++)
    {
        OE_TEST(enc_wait_for_exclusive_access(enclave) == OE_OK);
        std::this_thread::sleep_for(std::chrono::microseconds(20 * 1000));

        OE_TEST(enc_relinquish_exclusive_access(enclave) == OE_OK);
        std::this_thread::sleep_for(std::chrono::microseconds(20 * 1000));
    }
    printf("exclusive_access_thread Ending\n");
    return NULL;
}

void test_thread_wake_wait(oe_enclave_t* enclave)
{
    std::thread threads[NUM_THREADS];

    printf("test_thread_wake_wait Starting\n");
    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i] = std::thread(exclusive_access_thread, enclave);
    }

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i].join();
    }

    // The oe_calls in this test should succeed without any segv/double free.
    printf("test_thread_wake_wait Complete\n");
}

void* lock_and_unlock_thread1(oe_enclave_t* enclave)
{
    const size_t ITERS = 20000;

    for (size_t i = 0; i < ITERS; ++i)
    {
        OE_TEST(enc_lock_and_unlock_mutexes(enclave, "ABC") == OE_OK);
        OE_TEST(enc_lock_and_unlock_mutexes(enclave, "AB") == OE_OK);
        OE_TEST(enc_lock_and_unlock_mutexes(enclave, "AC") == OE_OK);
        OE_TEST(enc_lock_and_unlock_mutexes(enclave, "BC") == OE_OK);
        OE_TEST(enc_lock_and_unlock_mutexes(enclave, "ABBC") == OE_OK);
        OE_TEST(enc_lock_and_unlock_mutexes(enclave, "ABAB") == OE_OK);
    }

    return NULL;
}

void* lock_and_unlock_thread2(oe_enclave_t* enclave)
{
    const size_t ITERS = 20000;

    for (size_t i = 0; i < ITERS; ++i)
    {
        OE_TEST(enc_lock_and_unlock_mutexes(enclave, "BC") == OE_OK);
        OE_TEST(enc_lock_and_unlock_mutexes(enclave, "ABC") == OE_OK);
        OE_TEST(enc_lock_and_unlock_mutexes(enclave, "BBCC") == OE_OK);
        OE_TEST(enc_lock_and_unlock_mutexes(enclave, "BBC") == OE_OK);
        OE_TEST(enc_lock_and_unlock_mutexes(enclave, "ABAB") == OE_OK);
        OE_TEST(enc_lock_and_unlock_mutexes(enclave, "ABAC") == OE_OK);
        OE_TEST(enc_lock_and_unlock_mutexes(enclave, "ABAB") == OE_OK);
    }

    return NULL;
}

// Launch multiple threads and try out various locking patterns on 3 mutexes.
// The locking patterns are chosen to not deadlock.
void test_thread_locking_patterns(oe_enclave_t* enclave)
{
    std::thread threads[NUM_THREADS];

    printf("test_thread_locking_patterns Starting\n");
    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i] = std::thread(
            (i & 1) ? lock_and_unlock_thread2 : lock_and_unlock_thread1,
            enclave);
    }

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i].join();
    }

    // The oe_calls in this test should succeed without any OE_TEST() failures.
    printf("test_thread_locking_patterns Complete\n");
}

void test_readers_writer_lock(oe_enclave_t* enclave);

// test_tcs_exhaustion
static std::atomic<size_t> g_tcs_out_thread_count(0);

// this is the test_tcs worker thread
void* tcs_thread(oe_enclave_t* enclave, size_t tcs_req_count)
{
    oe_result_t result = enc_test_tcs_exhaustion(enclave, tcs_req_count);
    if (result == OE_OUT_OF_THREADS)
    {
        // increment g_tcs_out_thread_count when thread exhaustion is reached
        ++g_tcs_out_thread_count;
    }
    else
    {
        OE_TEST(result == OE_OK);
    }

    return NULL;
}

// this test that calling an enclave fails with OE_OUT_OF_THREADS after reaching
// TCS exhaustion
// this test launches many threads which in turn make ecalls
//   - successful ecalls increment a counter (tcs_used_thread_count) and wait
//     for the total thread count to reach the test count (tcs_req_count)
//   - unsuccessful ecalls increment a counter (tcs_out_thread_count)
// tcs_used_thread_count is maintained in the enclave
// tcs_out_thread_count is maintained in the host
void test_tcs_exhaustion(oe_enclave_t* enclave)
{
    std::vector<std::thread> threads;
    // Set the test_tcs_count to a value greater than the enclave TCSCount
    const size_t test_tcs_req_count = enclave->num_bindings * 2;
    printf(
        "test_tcs_exhaustion - Number of TCS bindings in enclave=%zu\n",
        enclave->num_bindings);

    for (size_t i = 0; i < test_tcs_req_count; i++)
    {
        threads.push_back(std::thread(tcs_thread, enclave, test_tcs_req_count));
    }

    for (size_t i = 0; i < test_tcs_req_count; i++)
    {
        threads[i].join();
    }

    // the local tcs_used_thread_count is a local copy of a value maintained on
    // the enclave
    size_t tcs_used_thread_count = 0;
    // enc_tcs_used_thread_count retrieves the value from the enclave
    OE_TEST(
        enc_tcs_used_thread_count(enclave, &tcs_used_thread_count) == OE_OK);

    printf(
        "test_tcs_exhaustion: tcs_count=%zu; num_threads=%zu; "
        "num_out_threads=%zu\n",
        test_tcs_req_count,
        tcs_used_thread_count,
        g_tcs_out_thread_count.load());

    // Crux of the test is to get OE_OUT_OF_THREADS i.e. to exhaust the TCSes
    OE_TEST(g_tcs_out_thread_count > 0);
    // Verifying that everything adds up fine
    OE_TEST(
        tcs_used_thread_count + g_tcs_out_thread_count == test_tcs_req_count);
    // Sanity test that we are not reusing the bindings
    OE_TEST(tcs_used_thread_count <= enclave->num_bindings);
}

size_t host_tcs_out_thread_count()
{
    return g_tcs_out_thread_count;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();

    result = oe_create_thread_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        oe_put_err("oe_create_thread_enclave(): result=%u", result);
    }

    test_mutex(enclave);

    test_cond(enclave);

    test_cond_broadcast(enclave);

    test_thread_wake_wait(enclave);

    test_thread_locking_patterns(enclave);

    test_readers_writer_lock(enclave);

    test_tcs_exhaustion(enclave);

    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_put_err("oe_terminate_enclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
