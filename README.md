# SGXRacer

SGXRacer is detection tool for controlled data races in enclave code.


## Overview

SGXRacer systematically identifies possible shared (i.e., the racing) variables and explores both intended and unintended thread interleavings in enclave code to inspect whether there are proper synchronizations on shared variables. A data race is identified if there is a lack of synchronization primitives when TCSnum is configured to be more than one. The key idea is to assume that every ecall can run concurrently with another ecall (including itself), given a strong privileged attacker who can abuse enclave thread creation, ecall invocation, and fine-grained enclave code execution. At a high level, SGXRacer contains two phases of analysis: the variable analysis phase and the data race detection phase. The variable analysis phase recovers shared variables and lock variables from enclave code and generates locksets and lock acquisition histories. The data race detection phase considers each ecall to be possibly concurrent and performs a reentrancy-aware lockset-based data race detection.


## Research paper

```
@inproceedings {Chen:2023:SGXRacer,
author = {Sanchuan Chen and Zhiqiang Lin and Yinqian Zhang},
title = {{Controlled Data Races in Enclaves: Attacks and Detection}},
booktitle = {32st USENIX Security Symposium (USENIX Security 23)},
year = {2023},
publisher = {USENIX Association},
}
```

## Dataset

We evaluated SGXRacer on four well-known SGX SDKs: Intel SGX SDK, Microsoft Open Enclave SDK, Apache Teaclave Rust-SGX SDK, and Fortanix Rust EDP SDK.

The specific versions evaluated:

| SDK | Repository | Version |
| --- | --- | --- |
| Intel SGX SDK | https://github.com/intel/linux-sgx | 2.6 |
| Microsoft Open Enclave SDK | https://github.com/openenclave/openenclave | 0.7.0 |
| Apache Teaclave Rust-SGX SDK | https://github.com/apache/incubator-teaclave-sgx-sdk | 1.0.8 |
| Fortanix Rust EDP SDK | https://github.com/fortanix/rust-sgx | commit dbe1430367b3fde78ccb6209cfd49ed0fdc2d707 |


We also evaluated eight widely used SGX Applications: mbedtls-SGX, intel-sgx-ssl, TaLoS, LibSEAL, SGX_SQLite, stealthdb, SGXDeep, and hot-calls.

The specific versions evaluated:

| Application | Repository | Version |
| --- | --- | --- |
| mbedtls-SGX | https://github.com/bl4ck5un/mbedtls-SGX | commit eab8e36a1e670a2fa66105735143eafa51931bff |
| intel-sgx-ssl | https://github.com/intel/intel-sgx-ssl | commit 59f179cb3bf39949ef6bf68e0021092163db9e8c |
| TaLoS | https://github.com/lsds/TaLoS | commit bb0b61925347b5148fe44cd6400eb981bd0f5a36 |
| LibSEAL | https://github.com/lsds/LibSEAL | commit cc00f0fd12cb856079253489a90a887e48c5c9c5 |
| SGX_SQLite | https://github.com/yerzhan7/SGX_SQLite | commit c470f0a6afcbb2461a94faa6045df47450c3354b |
| stealthdb | https://github.com/cryptograph/stealthdb | commit 1ca645ae1613c146d59900ce50abc873dc8a6d01 |
| SGXDeep | https://github.com/landoxy/intel-sgx-deep-learning | commit 2a6c3b7502556b8fcf585f1a5704d8f20f8d82d8 |
| hot-calls | https://github.com/oweisse/hot-calls | commit 31ca115906c4a43cdf97f71fc6f836be433bd338 |


## Software dependencies

SGXRacer was originally developed and tested on Ubuntu 20.04. SGXRacer needs Python 3 environment, such as command line tool python3 and pip3. SGXRacer also needs Python 3 package angr.


## Installation

* Install pip3 for Python 3:
```python
sudo apt install python3-pip
```
* Install binary code analysis framework angr:
```python
sudo pip3 install angr
```
* Clone SGXRacer GitHub repository:
```python
git clone https://github.com/OSUSecLab/SGXRacer.git
```




## 1. To detect data races in SGX SDKs.

```python
python3 sgxrace.py -input ./enclave_binaries/intel_sgx_sdk/enclave.signed.so -output intel_sgx_sdk_results.txt -output1 intel_sgx_sdk_results1.txt > intel_sgx_sdk_stdout

python3 sgxrace.py -input ./enclave_binaries/open_enclave_sdk/enclave.signed -output open_enclave_sdk_results.txt -output1 open_enclave_sdk_results1.txt > open_enclave_sdk_stdout

python3 sgxrace.py -input ./enclave_binaries/rust_sgx_sdk/enclave.signed.so -output rust_sgx_sdk_results.txt -output1 rust_sgx_sdk_results1.txt > rust_sgx_sdk_stdout

python3 sgxrace.py -input ./enclave_binaries/rust_edp_sdk/enclave -output rust_edp_sdk_results.txt -output1 rust_edp_sdk_results1.txt > rust_edp_sdk_stdout
```



## 2. To detect data races in SGX applications.

```python
python3 sgxrace.py -app -fast -input ./enclave_binaries/sgx_apps/001_mbedtls-SGX/enclave.signed.so -output 001_mbedtls-SGX_results.txt -output1 001_mbedtls-SGX_results1.txt > 001_mbedtls-SGX_stdout

python3 sgxrace.py -app -fast -input ./enclave_binaries/sgx_apps/002_intel-sgx-ssl/enclave.signed.so -output 002_intel-sgx-ssl_results.txt -output1 002_intel-sgx-ssl_results1.txt > 002_intel-sgx-ssl_stdout

python3 sgxrace.py -app -fast -input ./enclave_binaries/sgx_apps/008_TaLoS/enclave.signed.so -output 008_TaLoS_results.txt -output1 008_TaLoS_results1.txt > 008_TaLoS_stdout

python3 sgxrace.py -app -fast -input ./enclave_binaries/sgx_apps/016_SGX_SQLite/enclave.signed.so -output 016_SGX_SQLite_results.txt -output1 016_SGX_SQLite_results1.txt > 016_SGX_SQLite_stdout

python3 sgxrace.py -app -fast -input ./enclave_binaries/sgx_apps/026_LibSEAL/enclave.signed.so -output 026_LibSEAL_results.txt -output1 026_LibSEAL_results1.txt > 026_LibSEAL_stdout

python3 sgxrace.py -app -fast -input ./enclave_binaries/sgx_apps/028_stealthdb/enclave.signed.so -output 028_stealthdb_results.txt -output1 028_stealthdb_results1.txt > 028_stealthdb_stdout

python3 sgxrace.py -app -fast -input ./enclave_binaries/sgx_apps/065_hot-calls/enclave.signed.so -output 065_hot-calls_results.txt -output1 065_hot-calls_results1.txt > 065_hot-calls_stdout

python3 sgxrace.py -app -fast -input ./enclave_binaries/sgx_apps/087_intel-sgx-deep-learning/enclave.signed.so -output 087_intel-sgx-deep-learning_results.txt -output1 087_intel-sgx-deep-learning_results1.txt > 087_intel-sgx-deep-learning_stdout
```




