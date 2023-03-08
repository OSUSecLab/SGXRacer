// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openenclave/host.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "../common/common.h"

int verify_callback(int preverify_ok, X509_STORE_CTX* ctx);
int create_socket(char* server_name, char* server_port);

int parse_arguments(
    int argc,
    char** argv,
    char** server_name,
    char** server_port)
{
    int ret = 1;
    const char* option = NULL;
    int param_len = 0;

    if (argc != 3)
        goto print_usage;

    option = "-server:";
    param_len = strlen(option);
    if (strncmp(argv[1], option, param_len) != 0)
        goto print_usage;
    *server_name = (char*)(argv[1] + param_len);

    option = "-port:";
    param_len = strlen(option);
    if (strncmp(argv[2], option, param_len) != 0)
        goto print_usage;

    *server_port = (char*)(argv[2] + param_len);
    ret = 0;
    goto done;

print_usage:
    printf(TLS_CLIENT "Usage: %s -server:<name> -port:<port>\n", argv[0]);
done:
    return ret;
}

// This routine conducts a simple HTTP request/response communication with
// server
int communicate_with_server(SSL* ssl)
{
    unsigned char buf[200];
    int ret = 1;
    int error = 0;
    int len = 0;
    int bytes_written = 0;
    int bytes_read = 0;

    // Write an GET request to the server
    printf(TLS_CLIENT "Write to server-->:\n\n");
    len = snprintf((char*)buf, sizeof(buf) - 1, CLIENT_PAYLOAD);
    while ((bytes_written = SSL_write(ssl, buf, (size_t)len)) <= 0)
    {
        error = SSL_get_error(ssl, bytes_written);
        if (error == SSL_ERROR_WANT_WRITE)
            continue;
        printf(TLS_CLIENT "Failed! SSL_write returned %d\n", error);
        ret = bytes_written;
        goto done;
    }

    printf(TLS_CLIENT "\n\n%d bytes written\n\n", bytes_written);

    // Read the HTTP response from server
    printf(TLS_CLIENT "\n\n<-- Read from server:\n");
    do
    {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        bytes_read = SSL_read(ssl, buf, (size_t)len);
        if (bytes_read <= 0)
        {
            int error = SSL_get_error(ssl, bytes_read);
            if (error == SSL_ERROR_WANT_READ)
                continue;

            printf(TLS_CLIENT "Failed! SSL_read returned error=%d\n", error);
            ret = bytes_read;
            break;
        }

        printf(TLS_CLIENT " %d bytes read\n", bytes_read);
#ifdef ADD_TEST_CHECKING
        // check to to see if received payload is expected
        if ((bytes_read != SERVER_PAYLOAD_SIZE) ||
            (memcmp(SERVER_PAYLOAD, buf, bytes_read) != 0))
        {
            printf(
                TLS_CLIENT "ERROR: expected reading %lu bytes but only "
                           "received %d bytes\n",
                SERVER_PAYLOAD_SIZE,
                bytes_read);
            ret = bytes_read;
            goto done;
        }
        else
        {
            printf(TLS_CLIENT
                   " received all the expected data from server\n\n");
            ret = 0;
            break;
        }
        printf("Verified: the contents of server payload were expected\n\n");
#endif
    } while (1);
    ret = 0;
done:
    return ret;
}

// create a socket and connect to the server_name:server_port
int create_socket(char* server_name, char* server_port)
{
    int sockfd = -1;
    char* addr_ptr = NULL;
    int port = 0;
    struct hostent* host = NULL;
    struct sockaddr_in dest_addr;

    if ((host = gethostbyname(server_name)) == NULL)
    {
        printf(TLS_CLIENT "Error: Cannot resolve hostname %s.\n", server_name);
        goto done;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        printf(TLS_CLIENT "Error: Cannot create socket %d.\n", errno);
        goto done;
    }

    port = atoi(server_port);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);

    memset(&(dest_addr.sin_zero), '\0', 8);
    addr_ptr = inet_ntoa(dest_addr.sin_addr);

    if (connect(
            sockfd, (struct sockaddr*)&dest_addr, sizeof(struct sockaddr)) ==
        -1)
    {
        printf(
            TLS_CLIENT "failed to connect to %s:%s (errno=%d)\n",
            server_port,
            server_port,
            errno);
        close(sockfd);
        sockfd = -1;
        goto done;
    }
    printf(TLS_CLIENT "connected to %s:%s\n", server_name, server_port);
done:
    return sockfd;
}

int main(int argc, char** argv)
{
    int ret = 1;
    X509* cert = NULL;
    SSL_CTX* ctx = NULL;
    SSL* ssl = NULL;
    int serversocket = 0;
    char* server_name = NULL;
    char* server_port = NULL;
    int error = 0;

    printf("\nStarting" TLS_CLIENT "\n\n\n");
    if ((error = parse_arguments(argc, argv, &server_name, &server_port)) != 0)
    {
        printf(
            TLS_CLIENT "TLS client:parse input parmeter failed (%d)!\n", error);
        goto done;
    }

    // initialize openssl library and register algorithms
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    if (SSL_library_init() < 0)
    {
        printf(TLS_CLIENT
               "TLS client: could not initialize the OpenSSL library !\n");
        goto done;
    }

    if ((ctx = SSL_CTX_new(SSLv23_client_method())) == NULL)
    {
        printf(TLS_CLIENT "TLS client: unable to create a new SSL context\n");
        goto done;
    }

    // choose TLSv1.2 by excluding SSLv2, SSLv3 ,TLS 1.0 and TLS 1.1
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);

    // specify the verify_callback for custom verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, &verify_callback);

    if ((ssl = SSL_new(ctx)) == NULL)
    {
        printf(TLS_CLIENT
               "Unable to create a new SSL connection state object\n");
        goto done;
    }

    serversocket = create_socket(server_name, server_port);
    if (serversocket == -1)
    {
        printf(
            TLS_CLIENT
            "create a socket and initate a TCP connect to server: %s:%s "
            "(errno=%d)\n",
            server_name,
            server_port,
            errno);
        goto done;
    }

    // setup ssl socket and initiate TLS connection with TLS server
    SSL_set_fd(ssl, serversocket);
    if ((error = SSL_connect(ssl)) != 1)
    {
        printf(
            TLS_CLIENT "Error: Could not establish an SSL session ret2=%d "
                       "SSL_get_error()=%d\n",
            error,
            SSL_get_error(ssl, error));
        goto done;
    }
    printf(
        TLS_CLIENT "successfully established TLS channel:%s\n",
        SSL_get_version(ssl));

    // start the client server communication
    if ((error = communicate_with_server(ssl)) != 0)
    {
        printf(TLS_CLIENT "Failed: communicate_with_server (ret=%d)\n", error);
        goto done;
    }

    // Free the structures we don't need anymore
    if (serversocket != -1)
        close(serversocket);

    ret = 0;
done:
    if (ssl)
        SSL_free(ssl);

    if (cert)
        X509_free(cert);

    if (ctx)
        SSL_CTX_free(ctx);

    printf(TLS_CLIENT " %s\n", (ret == 0) ? "success" : "failed");
    return (ret);
}
