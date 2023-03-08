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

#include "NetworkManagerClient.h"
#include "../GeneralSettings.h"

NetworkManagerClient* NetworkManagerClient::instance = NULL;

NetworkManagerClient::NetworkManagerClient() {}


void NetworkManagerClient::Init() {
    if (client) {
        delete client;
        client = NULL;
    }

    boost::asio::ip::tcp::resolver resolver(this->io_service);
    boost::asio::ip::tcp::resolver::query query(this->host, std::to_string(this->port).c_str());
    boost::asio::ip::tcp::resolver::iterator iterator = resolver.resolve(query);

    boost::asio::ssl::context ctx(boost::asio::ssl::context::sslv23);
    ctx.load_verify_file(Settings::server_crt);

    this->client = new Client(io_service, ctx, iterator);
}


NetworkManagerClient* NetworkManagerClient::getInstance(int port,  std::string host) {
    if (instance == NULL) {
        instance = new NetworkManagerClient();
        instance->setPort(port);
        instance->setHost(host);
    }

    return instance;
}


void NetworkManagerClient::startService() {
    this->client->startConnection();
}


void NetworkManagerClient::setHost(std::string host) {
    this->host = host;
}


void NetworkManagerClient::connectCallbackHandler(CallbackHandler cb) {
    this->client->setCallbackHandler(cb);
}
