# Switchless Calls Sample

This sample demonstrates how to make switchless calls to host from inside an enclave.
It has the following properties:

- Explain the concept of switchless calls
- Identify cases where switchless calls are appropriate
- Demonstrate how to mark a function as `transition_using_threads` in EDL, and use [`oeedger8r`](https://github.com/openenclave/openenclave/tree/master/docs/GettingStartedDocs/Edger8rGettingStarted.md) tool to compile it
- Demonstrate how to configure an enclave to enable switchless calls originated within it
- Recommend the number of host worker threads required for switchless calls in practice

Prerequisite: you may want to read [Common Sample Information](../README.md#common-sample-information) before going further.

## Switchless Calls

In an enclave application, the host makes **ECALL**s into functions exposed by the enclaves it created. Likewise,
the enclaves may make **OCALL**s into functions exposed by the host that created them. In either case, the
execution has to be transitioned from an untrusted environment to a trusted environment, or vice versa. Since the
transition is costly due to heavy security checks, it might be more performance advantageous to make the calls
**context-switchless**: the caller delegates the function call to a worker thread in the other environment, which
does the real job of calling the function and post the result to the caller. Both the calling thread and the
worker thread never leave their respective execution contexts during the perceived function call.

The calling thread and the worker thread need to exchange information twice during the call. When the switchless
call is initiated, the caller needs to pass the `job` (encapsulating information regarding the function call in a
 single object, for details see the next section) to the worker thread. And when the call finishes, the worker
thread needs to pass the result back to the caller. Both exchanges need to be synchronized.

While switchless calls save transition time, they require at least one additional thread to service the calls.
Currently, the worker threads that service the calls busy-wait for messages and therefore consume a lot of CPU.
Thus more worker threads typically means more competition for the CPU cores and more thread context switches,
hurting the performance. In order to determine whether to make a particular function switchless, one has to weigh
the associated costs and savings. In general, the good candidates for switchless calls are functions that are:
1) short, thus the transition takes relatively high percentage of the overall execution time of the call; and
2) called frequently, so the savings in transition time add up.

## How does Open Enclave support switchless OCALLs

Open Enclave only supports synchronous switchless OCALLs currently. When the caller within an enclave makes a
switchless OCALL, the trusted Open Enclave runtime creates a `job` out of the function call. The `job` object
includes information such as the function ID, the parameters marshaled into a buffer, and a buffer for holding the
return value(s). The job is posted to a shared memory region which both the enclave and the host can access.

A host worker thread checks and retrieves `job` from the shared memory region. It uses the untrusted Open Enclave
runtime to process the `job` by unmarshaling the parameters, then dispatching to the callee function, and finally
relaying the result back to the trusted Open Enclave runtime, which is further forwarded back to the caller.

If an enclave supports multiple simultaneous ECALLs, multiple simultaneous switchless OCALLs could be made from the
enclave. We use multi-threaded host workers in that scenario. Open Enclave
allows users to configure how many host worker threads are to be created for servicing switchless OCALLs. The
following example illustrates how to do that. A word of caution is that too many host worker threads might increase
competition of cores between threads and degrade the performance. Therefore, if a enclave has switchless calls
enabled, Open Enclave caps the number of host worker threads for it to the number of enclave threads specified.

With the current implementation, we recommend that users avoid using more host worker threads than the minimum of:

1. the number of simultaneously active enclave threads, and
2. the number of cores that are potentially available to host worker threads.

For example, on a 4-core machine, if the number of the simultaneously active enclave threads is 2, and there are no
host threads other than the two threads making ECALLs and the switchless worker threads, both 1) and 2) would be 2.
So we recommend setting the number of host worker threads to 2.

The exception to the above rule happens when 2) is zero or negative. For example, if the host starts two more
additional threads that are expected to be active along with the two enclave threads, the number of cores available
to the worker threads is actually 0, and the minimum of 1) and 2) would be 0. In this case, we recommend setting
the number of host worker threads to 1 nevertheless, to ensure switchless calls are serviced by at least one thread.

The above recommendation may change when we modify the behavior of worker threads in the future.

## About the EDL

In this sample, we pretend the enclave doesn't know addition. It relies on a host function to
increment a number by 1, and repeats  calling it `N` times to add `N` to a given number. Since the host function is
short and called frequently, it is appropriate to make it a switchless function.

We want to compare the performance of switchless calls vs. regular calls. To that end, we define two variants of
the host function: `host_increment_regular` which is a regular OCALL, and `host_increment_switchless`,
which is called switchlessly.

Additionally, We define two enclave functions `enclave_add_N_regular` and `enclave_add_N_switchless`, which call host function
`host_increment_regular` and `host_increment_switchless` respectively. Both enclave functions call its host function
in a loop repeatedly. The number of iterations is determined by parameter `n`.

The host functions and enclave functions are defined in an EDL file `switchless.edl` as below:

```edl
enclave {
    trusted {
        public void enclave_add_N_switchless([in, out] int* m, int n);
        public void enclave_add_N_regular([in, out] int* m, int n);
    };t

    untrusted {
        void host_increment_switchless([in, out] int* m) transition_using_threads;
        void host_increment_regular([in, out] int* m);
    };
};
```

Function `host_increment_switchless`'s declaration ends with keyword `transition_using_threads`, indicating it should be
called switchlessly at run time. However, this a best-effort directive. Open Enclave runtime may still choose
to fall back to a tradition OCALL if switchless call resources are unavailable, e.g., the enclave is not configured
as switchless-capable, or the host worker threads are busy servicing other switchless OCALLs. In this example,
`host_increment_switchless` is always called switchlessly because there are no simultaneous switchless OCALLs.

To generate the functions with the marshaling code, the `oeedger8r` tool is called in both the host and enclave
directories from their Makefiles. For example:

```bash
cd host
oeedger8r ../switchless.edl --untrusted
```

## About the host

The host first defines a structure specifically for configuring switchless calls. In this case, we specify the
first field `1` as the number of host worker threads for switchless OCALLs. In this example, 1) There is at most
1 enclave thread all the time, and 2) The number of cores available to the host worker threads is unknown, and
so we use 1 as explained above. The 2nd field specifies the number of enclave threads for switchless ECALLs.
Since switchless ECALL is not yet implemented, we require the 2nd field to be `0`.

```c
oe_enclave_setting_context_switchless_t switchless_setting = {1, 0};
```

The host then puts the structure address and the setting type in an array of settings for the enclave
to be created. Even though we only have one setting (for switchless) for the enclave, we'd like the
flexibility of adding more than one setting (with different types) for an enclave in the future.

```c
oe_enclave_setting_t settings[] = {{
        .setting_type = OE_ENCLAVE_SETTING_CONTEXT_SWITCHLESS,
        .u.context_switchless_setting = &setting,
    }};
```

To make the settings created above effective, we need to pass the array `settingss` into `oe_create_enclave`
in the following way:

```c
oe_create_switchless_enclave(
             argv[1],
             OE_ENCLAVE_TYPE_SGX,
             flags,
             settings,
             OE_COUNTOF(settings),
             &enclave);
```

The host then makes an ECALL of `enclave_add_N_regular` to transition into the enclave to compute the sum of
two integers `m` and `n`. After that, the host makes an ECALL of `enclave_add_N_switchless` to perform the same
computation except for using switchless OCALLs instead of regular OCALLs. We print out the time spent on both
ECALLs to highlight the performance advantage of switchless calls in this case.

## About the enclave

The enclave exposes two functions `enclave_add_N_switchless` and `enclave_add_N_regular`, both taking
two parameters `m` and `n`. The formal calls host function `host_increment_switchless`, while the latter
calls `host_increment_regular`. Both host functions are called in a loop of `n` iterations.

## Build and run

Note that there are two different build systems supported, one using GNU Make and
`pkg-config`, the other using CMake.

If the build and run succeed, output like the following is expected (the exact time spent on the enclave functions could vary):

```bash
host/switchlesshost ./enclave/switchlessenc.signed
enclave_add_N_switchless(): 1000000 + 1000000 = 2000000. Time spent: 923 ms
enclave_add_N_regular(): 1000000 + 1000000 = 2000000. Time spent: 19167 ms
```

We expect to see a speed up of the first ECALL over the 2nd one due to switchless calls.

### CMake

This uses the CMake package provided by the Open Enclave SDK.

```bash
cd switchless
mkdir build && cd build
cmake ..
make run
```

### GNU Make

```bash
cd switchless
make build
make run
```
#### Note

switchless sample can run under Open Enclave simulation mode.

To run the switchless sample in simulation mode from the command like, use the following:

```bash
# if built with cmake
./host/switchless_host ./enclave/switchless_enc.signed --simulate
# or, if built with GNU Make and pkg-config
make simulate
```
