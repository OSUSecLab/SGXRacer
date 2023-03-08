// Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//  * Neither the name of Baidu, Inc., nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// App.cpp : Defines the entry point for the console application.
#include <stdio.h>
#include <map>
#include "Enclave1_u.h"
#include "Enclave2_u.h"
#include "Enclave3_u.h"
#include "sgx_eid.h"
#include "sgx_urts.h"

#define UNUSED(val) (void)(val)
#define TCHAR   char
#define _TCHAR  char
#define _T(str) str
#define scanf_s scanf
#define _tmain  main

extern std::map<sgx_enclave_id_t, uint32_t>g_enclave_id_map;


sgx_enclave_id_t e1_enclave_id = 0;
sgx_enclave_id_t e2_enclave_id = 0;
sgx_enclave_id_t e3_enclave_id = 0;

#define ENCLAVE1_PATH "enclave1.signed.so"
#define ENCLAVE2_PATH "enclave2.signed.so"
#define ENCLAVE3_PATH "enclave3.signed.so"

void waitForKeyPress()
{
    printf("\n\nHit a key....\n");
    getchar();
}

uint32_t load_enclaves()
{
    uint32_t enclave_temp_no;
    int ret, launch_token_updated;
    sgx_launch_token_t launch_token;

    enclave_temp_no = 0;

    ret = sgx_create_enclave(ENCLAVE1_PATH, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated, &e1_enclave_id, NULL);
    if (ret != SGX_SUCCESS) {
                return ret;
    }

    enclave_temp_no++;
    g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e1_enclave_id, enclave_temp_no));

    ret = sgx_create_enclave(ENCLAVE2_PATH, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated, &e2_enclave_id, NULL);
    if (ret != SGX_SUCCESS) {
                return ret;
    }

    enclave_temp_no++;
    g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e2_enclave_id, enclave_temp_no));

    ret = sgx_create_enclave(ENCLAVE3_PATH, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated, &e3_enclave_id, NULL);
    if (ret != SGX_SUCCESS) {
                return ret;
    }

    enclave_temp_no++;
    g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e3_enclave_id, enclave_temp_no));



    return SGX_SUCCESS;
}

int _tmain(int argc, _TCHAR* argv[])
{
    uint32_t ret_status;
    sgx_status_t status;

    UNUSED(argc);
    UNUSED(argv);

    if(load_enclaves() != SGX_SUCCESS)
    {
        printf("\nLoad Enclave Failure");
    }

    do
    {
        Enclave1_test_enclave_init(e1_enclave_id);
        Enclave2_test_enclave_init(e2_enclave_id);
        Enclave3_test_enclave_init(e3_enclave_id);

        //Test Create session between Enclave1(Source) and Enclave2(Destination)
        status = Enclave1_test_create_session(e1_enclave_id, &ret_status, e1_enclave_id, e2_enclave_id);
        if (status!=SGX_SUCCESS)
        {
            printf("Enclave1_test_create_session Ecall failed: Error code is %x", status);
            break;
        }
        else
        {
            if(ret_status==0)
            {
                printf("\n\nSecure Channel Establishment between Source (E1) and Destination (E2) Enclaves successful !!!");
            }
            else
            {
                printf("\nSession establishment and key exchange failure between Source (E1) and Destination (E2): Error code is %x", ret_status);
                break;
            }
        }

        //Test Create session between Enclave1(Source) and Enclave3(Destination)
        status = Enclave1_test_create_session(e1_enclave_id, &ret_status, e1_enclave_id, e3_enclave_id);
        if (status!=SGX_SUCCESS)
        {
            printf("Enclave1_test_create_session Ecall failed: Error code is %x", status);
            break;
        }
        else
        {
            if(ret_status==0)
            {
                printf("\n\nSecure Channel Establishment between Source (E1) and Destination (E3) Enclaves successful !!!");
            }
            else
            {
                printf("\n\nSession establishment and key exchange failure between Source (E1) and Destination (E3): Error code is %x", ret_status);
                break;
            }
        }

        //Test Create session between Enclave2(Source) and Enclave3(Destination)
        status = Enclave2_test_create_session(e2_enclave_id, &ret_status, e2_enclave_id, e3_enclave_id);
        if (status!=SGX_SUCCESS)
        {
            printf("Enclave2_test_create_session Ecall failed: Error code is %x", status);
            break;
        }
        else
        {
            if(ret_status==0)
            {
                printf("\n\nSecure Channel Establishment between Source (E2) and Destination (E3) Enclaves successful !!!");
            }
            else
            {
                printf("\n\nSession establishment and key exchange failure between Source (E2) and Destination (E3): Error code is %x", ret_status);
                break;
            }
        }

        //Test Create session between Enclave3(Source) and Enclave1(Destination)
        status = Enclave3_test_create_session(e3_enclave_id, &ret_status, e3_enclave_id, e1_enclave_id);
        if (status!=SGX_SUCCESS)
        {
            printf("Enclave3_test_create_session Ecall failed: Error code is %x", status);
            break;
        }
        else
        {
            if(ret_status==0)
            {
                printf("\n\nSecure Channel Establishment between Source (E3) and Destination (E1) Enclaves successful !!!");
            }
            else
            {
                printf("\n\nSession establishment and key exchange failure between Source (E3) and Destination (E1): Error code is %x", ret_status);
                break;
            }
        }

        //Test Closing Session between Enclave1(Source) and Enclave2(Destination)
        status = Enclave1_test_close_session(e1_enclave_id, &ret_status, e1_enclave_id, e2_enclave_id);
        if (status!=SGX_SUCCESS)
        {
            printf("Enclave1_test_close_session Ecall failed: Error code is %x", status);
            break;
        }
        else
        {
            if(ret_status==0)
            {
                printf("\n\nClose Session between Source (E1) and Destination (E2) Enclaves successful !!!");
            }
            else
            {
                printf("\n\nClose session failure between Source (E1) and Destination (E2): Error code is %x", ret_status);
                break;
            }
        }
        //Test Closing Session between Enclave1(Source) and Enclave3(Destination)
        status = Enclave1_test_close_session(e1_enclave_id, &ret_status, e1_enclave_id, e3_enclave_id);
        if (status!=SGX_SUCCESS)
        {
            printf("Enclave1_test_close_session Ecall failed: Error code is %x", status);
            break;
        }
        else
        {
            if(ret_status==0)
            {
                printf("\n\nClose Session between Source (E1) and Destination (E3) Enclaves successful !!!");
            }
            else
            {
                printf("\n\nClose session failure between Source (E1) and Destination (E3): Error code is %x", ret_status);
                break;
            }
        }
        //Test Closing Session between Enclave2(Source) and Enclave3(Destination)
        status = Enclave2_test_close_session(e2_enclave_id, &ret_status, e2_enclave_id, e3_enclave_id);
        if (status!=SGX_SUCCESS)
        {
            printf("Enclave2_test_close_session Ecall failed: Error code is %x", status);
            break;
        }
        else
        {
            if(ret_status==0)
            {
                printf("\n\nClose Session between Source (E2) and Destination (E3) Enclaves successful !!!");
            }
            else
            {
                printf("\n\nClose session failure between Source (E2) and Destination (E3): Error code is %x", ret_status);
                break;
            }
        }
        //Test Closing Session between Enclave3(Source) and Enclave1(Destination)
        status = Enclave3_test_close_session(e3_enclave_id, &ret_status, e3_enclave_id, e1_enclave_id);
        if (status!=SGX_SUCCESS)
        {
            printf("Enclave3_test_close_session Ecall failed: Error code is %x", status);
            break;
        }
        else
        {
            if(ret_status==0)
            {
                printf("\n\nClose Session between Source (E3) and Destination (E1) Enclaves successful !!!");
            }
            else
            {
                printf("\n\nClose session failure between Source (E3) and Destination (E1): Error code is %x", ret_status);
                break;
            }
        }

#pragma warning (push)
#pragma warning (disable : 4127)
    }while(0);
#pragma warning (pop)

    sgx_destroy_enclave(e1_enclave_id);
    sgx_destroy_enclave(e2_enclave_id);
    sgx_destroy_enclave(e3_enclave_id);

    waitForKeyPress();

    return 0;
}
