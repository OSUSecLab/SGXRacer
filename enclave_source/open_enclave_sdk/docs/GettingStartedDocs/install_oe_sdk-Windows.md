# Install the Open Enclave SDK NuGet Package

## Platform requirements

- A system with support for SGX1 with Flexible Launch Control (FLC).
Note: To check if your system has support for SGX1 with or without FLC, please look [here](./SGXSupportLevel.md).

- Windows Server 2016

## Software Prerequisites

### Microsoft Visual Studio Build Tools 2019

Install [Visual Studio Build Tools 2019](https://aka.ms/vs/16/release/vs_buildtools.exe). Choose the "C++ build tools" workload. Visual Studio Build Tools 2019 has support for CMake Version 3.15 (CMake ver 3.12 or above is required for building Open Enclave SDK). For more information about CMake support, look [here](https://blogs.msdn.microsoft.com/vcblog/2016/10/05/cmake-support-in-visual-studio/).

### Git for Windows 64-bit

Download [Git for Windows 64-bit](https://git-scm.com/download/win).

Install Git and add Git Bash to the PATH environment variable.
Typically, Git Bash is located in `C:\Program Files\Git\bin`.
Currently the Open Enclave SDK build system uses bash scripts to configure
and build Linux-based 3rd-party libraries.

Open a command prompt and ensure that Git Bash is added to PATH.

```cmd
C:\>where bash
C:\Program Files\Git\bin\bash.exe
```

Tools available in the Git bash environment are also used for test and sample
builds. For example, OpenSSL is used to generate test certificates, so it is
also useful to have the `Git\mingw64\bin` folder added to PATH. This can be checked
from the command prompt as well:

```cmd
C:\>where openssl
C:\Program Files\Git\mingw64\bin\openssl.exe
```

### Clang

Download [Clang/LLVM for Windows 64-bit](http://releases.llvm.org/7.0.1/LLVM-7.0.1-win64.exe).
Install Clang 7.0.1 and add the LLVM folder (typically C:\Program Files\LLVM\bin)
to PATH. Open Enclave SDK uses clang to build the enclave binaries.

Open up a command prompt and ensure that clang is added to PATH.

```cmd
C:\> where clang
C:\Program Files\LLVM\bin\clang.exe
C:\> where llvm-ar
C:\Program Files\LLVM\bin\llvm-ar.exe
C:\> where ld.lld
C:\Program Files\LLVM\bin\ld.lld.exe
```

### SGX1 with Flexible Launch Control (FLC) Prerequisites

Instructions to install Intel's PSW 2.4, Intel's Data Center Attestation Primitives and related dependencies can be found [here](Contributors/WindowsManualSGX1FLCDCAPPrereqs.md).

## Download and install the Open Enclave SDK NuGet Package

Download the required Windows NuGet Package from [here](https://github.com/openenclave/openenclave/releases) and place it in a directory of your choice. Use the command below to install the NuGet package. In this example, we are placing the NuGet Package in `C:\openenclave_nuget` and installing it to `C:\oe`.

```cmd
 nuget.exe install open-enclave -Source C:\openenclave_nuget -OutputDirectory C:\oe -ExcludeVersion
```

Note: If it is an RC package, append `-pre` to the command above.

## Verify the Open Enclave SDK installation

See [Using the Open Enclave SDK](Windows_using_oe_sdk.md) for verifying and using the installed SDK.
