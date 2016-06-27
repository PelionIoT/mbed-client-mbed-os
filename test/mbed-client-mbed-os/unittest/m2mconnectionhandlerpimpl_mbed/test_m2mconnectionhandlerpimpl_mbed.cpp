/*
 * Copyright (c) 2015 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "CppUTest/TestHarness.h"
#include "test_m2mconnectionhandlerpimpl_mbed.h"
#include "m2mconnectionobserver.h"
#include "common_stub.h"
#include "m2mconnectionsecurity_stub.h"
#include "m2msecurity_stub.h"
#include "m2mconnectionhandler.h"

class TestObserver : public M2MConnectionObserver {

public:
    TestObserver() :
        dataAvailable(false),
        error(false),
        addressReady(false),
        dataSent(false)
    {
    }

    virtual ~TestObserver(){}

    void data_available(uint8_t*,
                        uint16_t,
                        const M2MConnectionObserver::SocketAddress &){dataAvailable = true;}

    void socket_error(uint8_t, bool ){ error = true; }

    void address_ready(const M2MConnectionObserver::SocketAddress &,
                       M2MConnectionObserver::ServerType,
                       const uint16_t){ addressReady = true;}

    void data_sent(){dataSent = true;}

    bool dataAvailable;
    bool error;
    bool addressReady;
    bool dataSent;
};

Test_M2MConnectionHandlerPimpl_mbed::Test_M2MConnectionHandlerPimpl_mbed()
{
    observer = new TestObserver();
    m2mconnectionsecurityimpl_stub::clear();
    common_stub::clear();
    handler = new M2MConnectionHandlerPimpl(NULL,*observer,NULL,M2MInterface::NOT_SET,M2MInterface::Uninitialized);
}

Test_M2MConnectionHandlerPimpl_mbed::~Test_M2MConnectionHandlerPimpl_mbed()
{
    delete handler;
    delete observer;
}

void Test_M2MConnectionHandlerPimpl_mbed::test_constructor()
{
    TestObserver obs;
    M2MConnectionHandlerPimpl impl = M2MConnectionHandlerPimpl(NULL,obs,NULL,M2MInterface::TCP_QUEUE,M2MInterface::Uninitialized);
    CHECK(impl._socket_address != NULL);
}

void Test_M2MConnectionHandlerPimpl_mbed::test_bind_connection()
{
    common_stub::error = SOCKET_ERROR_NONE;
    handler->_network_stack = M2MInterface::LwIP_IPv4;
    CHECK( handler->bind_connection(7) == true);

    handler->_network_stack = M2MInterface::Nanostack_IPv6;
    CHECK( handler->bind_connection(7) == true);
}

void Test_M2MConnectionHandlerPimpl_mbed::test_resolve_server_address()
{
    common_stub::error = SOCKET_ERROR_NONE;
    CHECK(handler->resolve_server_address("10", 7, M2MConnectionObserver::LWM2MServer, NULL) == false);
    handler->init_socket();
    CHECK(handler->resolve_server_address("10", 7, M2MConnectionObserver::LWM2MServer, NULL) == true);
}

void Test_M2MConnectionHandlerPimpl_mbed::test_send_data()
{
    sn_nsdl_addr_s* addr = (sn_nsdl_addr_s*)malloc(sizeof(sn_nsdl_addr_s));
    memset(addr, 0, sizeof(sn_nsdl_addr_s));
    CHECK( false == handler->send_data(NULL, 0 , NULL));

    uint8_t* data = (uint8_t*)malloc(5);
    CHECK(false == handler->send_data(data, 0 , NULL));
    CHECK(false == handler->send_data(data, 0 , addr));

    handler->init_socket();
    CHECK(true == handler->send_data(data, 0 , addr));

    handler->_binding_mode = M2MInterface::TCP;
    CHECK(true == handler->send_data(data, 0 , addr));

    M2MConnectionSecurity* conSec = new M2MConnectionSecurity(M2MConnectionSecurity::TLS);
    handler->_security_impl = conSec;
    handler->_use_secure_connection = true;
    CHECK(false == handler->send_data(data, 0 , addr));

    m2mconnectionsecurityimpl_stub::int_value = 5;
    CHECK(true == handler->send_data(data, 0 , addr));
    handler->_security_impl = NULL;
    delete conSec;

    // Non secure
    handler->_use_secure_connection = false;
    CHECK(true == handler->send_data(data, 0 , addr));

    handler->_binding_mode = M2MInterface::UDP;
    CHECK(true == handler->send_data(data, 0 , addr));

    free(data);
    free(addr);
}

void Test_M2MConnectionHandlerPimpl_mbed::test_start_listening_for_data()
{
    CHECK(false == handler->start_listening_for_data());
    handler->init_socket();
    CHECK(true == handler->start_listening_for_data());
}

void Test_M2MConnectionHandlerPimpl_mbed::test_send_handler()
{
    handler->send_handler(NULL, 10);
    CHECK(observer->dataSent == true);
}

void Test_M2MConnectionHandlerPimpl_mbed::test_receive_handler()
{
    handler->receive_handler(NULL);
    CHECK(handler->_mbed_socket == NULL);
    handler->init_socket();

    observer->dataAvailable = false;
    handler->_network_stack = M2MInterface::LwIP_IPv4;
    handler->receive_handler(NULL);
    CHECK(observer->dataAvailable == true);

    observer->dataAvailable = false;
    handler->_network_stack = M2MInterface::Nanostack_IPv6;
    handler->receive_handler(NULL);
    CHECK(observer->dataAvailable == true);

    common_stub::error = SOCKET_ERROR_NONE;
    common_stub::size = 5;
    handler->_binding_mode = M2MInterface::TCP;
    observer->dataAvailable = false;
    handler->_network_stack = M2MInterface::Nanostack_IPv6;
    handler->receive_handler(NULL);
    CHECK(observer->dataAvailable == true);


    handler->_binding_mode = M2MInterface::TCP_QUEUE;
    observer->dataAvailable = false;
    handler->_network_stack = M2MInterface::Nanostack_IPv6;
    handler->receive_handler(NULL);
    CHECK(observer->dataAvailable == true);

    common_stub::size = 0;
    handler->_binding_mode = M2MInterface::TCP_QUEUE;
    observer->dataAvailable = false;
    handler->_network_stack = M2MInterface::Nanostack_IPv6;
    handler->receive_handler(NULL);
    CHECK(observer->error == false);
    CHECK(observer->dataAvailable == false);

    common_stub::error = SOCKET_ERROR_BAD_FAMILY;
    handler->receive_handler(NULL);
    CHECK(observer->error == false);
    CHECK(observer->dataAvailable == false);

    common_stub::error = SOCKET_ERROR_NONE;

    M2MConnectionSecurity* conSec = new M2MConnectionSecurity(M2MConnectionSecurity::TLS);
    handler->_security_impl = conSec;
    handler->_use_secure_connection = true;
    m2mconnectionsecurityimpl_stub::int_value = -5;
    handler->receive_handler(NULL);
    CHECK(observer->error == false);
    CHECK(observer->dataAvailable == false);

    observer->dataAvailable = false;
    observer->error = false;
    m2mconnectionsecurityimpl_stub::int_value = M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ;
    handler->receive_handler(NULL);
    CHECK(observer->error == false);
    CHECK(observer->dataAvailable == false);

    handler->_binding_mode = M2MInterface::TCP;
    observer->dataAvailable = false;
    m2mconnectionsecurityimpl_stub::int_value = 5;
    handler->receive_handler(NULL);
    CHECK(observer->dataAvailable == true);

    observer->dataAvailable = false;
    m2mconnectionsecurityimpl_stub::int_value = 2;
    handler->receive_handler(NULL);
    CHECK(observer->dataAvailable == true);

    handler->_security_impl = NULL;
    delete conSec;
}

void Test_M2MConnectionHandlerPimpl_mbed::test_receive_handshake_handler()
{
    handler->_is_handshaking = false;
    handler->receive_handshake_handler(NULL);
    CHECK(false == handler->_is_handshaking);

    handler->init_socket();
    handler->_is_handshaking = true;
    m2mconnectionsecurityimpl_stub::int_value = M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ;
    handler->receive_handshake_handler(NULL);
    CHECK(true == handler->_is_handshaking);

    m2mconnectionsecurityimpl_stub::int_value = 0;
    handler->receive_handshake_handler(NULL);
    CHECK(false == handler->_is_handshaking);
    CHECK(true == observer->addressReady);

    handler->_is_handshaking = true;
    m2mconnectionsecurityimpl_stub::int_value = -10;
    handler->receive_handshake_handler(NULL);
    CHECK(false == handler->_is_handshaking);
    CHECK(true == handler->_error_reported);
    CHECK(true == observer->error)
}

void Test_M2MConnectionHandlerPimpl_mbed::test_dns_handler()
{
    socket_addr sa;
    memset(&sa, 0, sizeof(struct socket_addr));
    handler->dns_handler(NULL,sa,NULL);
    CHECK(observer->addressReady == false);

    handler->init_socket();
    common_stub::event = (socket_event_t*)malloc(sizeof(socket_event_t));
    memset(common_stub::event, 0, sizeof(socket_event_t));
    handler->_network_stack = M2MInterface::LwIP_IPv4;
    common_stub::bool_value = true;

    handler->dns_handler(NULL,sa,NULL);
    CHECK(observer->addressReady == true);
    observer->addressReady = false;

    common_stub::bool_value = false;
    handler->_network_stack = M2MInterface::Nanostack_IPv6;
    handler->dns_handler(NULL,sa,NULL);
    CHECK(observer->addressReady == true);
    observer->addressReady = false;

    handler->_binding_mode = M2MInterface::TCP;
    handler->dns_handler(NULL,sa,NULL);
    CHECK(observer->error == false);
    CHECK(observer->addressReady == true);

    M2MConnectionSecurity* conSec = new M2MConnectionSecurity(M2MConnectionSecurity::TLS);
    handler->_security_impl = conSec;
    handler->_use_secure_connection = true;
    m2mconnectionsecurityimpl_stub::int_value = -5;
    m2msecurity_stub::int_value = M2MSecurity::Psk;

    M2MSecurity* sec = new M2MSecurity(M2MSecurity::M2MServer);
    handler->_security = sec;
    handler->dns_handler(NULL,sa,NULL);
    CHECK(false == handler->_is_handshaking);

    /*m2mconnectionsecurityimpl_stub::int_value = 5;
    handler->dns_handler(NULL,sa,NULL);
    CHECK(true == handler->_is_handshaking);*/

    handler->_security_impl = NULL;
    delete conSec;
    delete sec;
    free(common_stub::event);
}

void Test_M2MConnectionHandlerPimpl_mbed::test_error_handler()
{
    handler->error_handler(NULL,SOCKET_ERROR_BAD_FAMILY);
    CHECK(observer->error == false);

    handler->init_socket();
    handler->error_handler(NULL,SOCKET_ERROR_NONE);
    CHECK(observer->error == false);

    handler->error_handler(NULL,SOCKET_ERROR_BAD_FAMILY);
    CHECK(observer->error == true);
    CHECK(handler->_mbed_socket == NULL);

    handler->init_socket();
    handler->error_handler(NULL,SOCKET_ERROR_DNS_FAILED);
    CHECK(observer->error == true);
    CHECK(handler->_mbed_socket == NULL);

    handler->init_socket();
    handler->error_handler(NULL,SOCKET_ERROR_RESET);
    CHECK(observer->error == true);
    CHECK(handler->_mbed_socket == NULL);

    handler->init_socket();
    handler->_is_handshaking = true;
    handler->error_handler(NULL,SOCKET_ERROR_RESET);
    CHECK(observer->error == true);
    CHECK(handler->_mbed_socket == NULL);
}

void Test_M2MConnectionHandlerPimpl_mbed::test_stop_listening()
{
    // Empty function to cover the cases
    handler->stop_listening();
    CHECK(handler->_error_reported == true);
}

void Test_M2MConnectionHandlerPimpl_mbed::test_send_to_socket()
{
    const char buf[] = "hello";
    CHECK( -1 == handler->send_to_socket((unsigned char *)&buf, 5) );

    handler->init_socket();
    CHECK( 5 == handler->send_to_socket((unsigned char *)&buf, 5) );

    handler->_binding_mode = M2MInterface::TCP;
    CHECK( 5 == handler->send_to_socket((unsigned char *)&buf, 5) );

    handler->_binding_mode = M2MInterface::TCP_QUEUE;
    CHECK( 5 == handler->send_to_socket((unsigned char *)&buf, 5) );

    handler->_binding_mode = M2MInterface::UDP;

    common_stub::error = SOCKET_ERROR_WOULD_BLOCK;
    CHECK( M2MConnectionHandler::CONNECTION_ERROR_WANTS_WRITE == handler->send_to_socket((unsigned char *)&buf, 5) );

    common_stub::error = SOCKET_ERROR_ALREADY_CONNECTED;
    CHECK( -1 == handler->send_to_socket((unsigned char *)&buf, 5) );
}

void Test_M2MConnectionHandlerPimpl_mbed::test_receive_from_socket()
{
    unsigned char *buf = (unsigned char *)malloc(6);
    CHECK( -1 == handler->receive_from_socket(buf, 5));

    handler->init_socket();
    CHECK( 5 == handler->receive_from_socket(buf, 5));

    handler->_binding_mode = M2MInterface::TCP;
    common_stub::size = 5;
    CHECK( 5 == handler->receive_from_socket(buf, 5));

    handler->_binding_mode = M2MInterface::TCP_QUEUE;
    CHECK( 5 == handler->receive_from_socket(buf, 5));

    handler->_binding_mode = M2MInterface::UDP;

    common_stub::error = SOCKET_ERROR_WOULD_BLOCK;
    CHECK( M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ == handler->receive_from_socket(buf, 5) );

    common_stub::error = SOCKET_ERROR_ALREADY_CONNECTED;
    CHECK( -1 == handler->receive_from_socket(buf, 5) );

    free(buf);
}

void Test_M2MConnectionHandlerPimpl_mbed::test_handle_connection_error()
{
    handler->handle_connection_error(4);
    CHECK(observer->error == true);
}

void Test_M2MConnectionHandlerPimpl_mbed::test_init_socket()
{
    TestObserver obs;

    M2MConnectionHandlerPimpl impl2 = M2MConnectionHandlerPimpl(NULL,obs,NULL,M2MInterface::NOT_SET,M2MInterface::LwIP_IPv4);
    impl2.init_socket();
    CHECK(impl2._socket_stack == SOCKET_STACK_LWIP_IPV4);
    CHECK(obs.error == false);

    M2MConnectionHandlerPimpl impl3 = M2MConnectionHandlerPimpl(NULL,obs,NULL,M2MInterface::NOT_SET,M2MInterface::LwIP_IPv6);
    impl3.init_socket();
    CHECK(impl3._socket_stack == SOCKET_STACK_LWIP_IPV6);
    CHECK(obs.error == false);

    M2MConnectionHandlerPimpl impl4 = M2MConnectionHandlerPimpl(NULL,obs,NULL,M2MInterface::NOT_SET,M2MInterface::Reserved);
    impl4.init_socket();
    CHECK(impl4._socket_stack == SOCKET_STACK_RESERVED);
    CHECK(obs.error == false);

    M2MConnectionHandlerPimpl impl5 = M2MConnectionHandlerPimpl(NULL,obs,NULL,M2MInterface::NOT_SET,M2MInterface::Nanostack_IPv6);
    impl5.init_socket();
    CHECK(impl5._socket_stack == SOCKET_STACK_NANOSTACK_IPV6);
    CHECK(obs.error == false);

    M2MConnectionHandlerPimpl impl6 = M2MConnectionHandlerPimpl(NULL,obs,NULL,M2MInterface::NOT_SET,M2MInterface::ATWINC_IPv4);
    impl6.init_socket();
    CHECK(impl6._socket_stack == SOCKET_STACK_ATWINC_IPV4);
    CHECK(obs.error == false);

    M2MConnectionHandlerPimpl impl7 = M2MConnectionHandlerPimpl(NULL,obs,NULL,M2MInterface::NOT_SET,M2MInterface::Unknown);
    common_stub::error = SOCKET_ERROR_ABORT;
    impl7.init_socket();
    CHECK(impl7._socket_stack == SOCKET_STACK_MAX);
    CHECK(obs.error == true);

    M2MConnectionHandlerPimpl impl8 = M2MConnectionHandlerPimpl(NULL,obs,NULL,M2MInterface::TCP,M2MInterface::LwIP_IPv4);
    impl8.init_socket();
    CHECK(impl8._socket_stack == SOCKET_STACK_LWIP_IPV4);
    CHECK(obs.error == true);
}

void Test_M2MConnectionHandlerPimpl_mbed::test_close_socket()
{
    handler->close_socket();
    CHECK(handler->_mbed_socket == NULL);

    handler->init_socket();
    handler->close_socket();
    CHECK(handler->_mbed_socket == NULL);

    M2MConnectionSecurity* conSec = new M2MConnectionSecurity(M2MConnectionSecurity::TLS);
    handler->_security_impl = conSec;
    handler->_use_secure_connection = true;
    handler->init_socket();
    handler->close_socket();
    CHECK(handler->_mbed_socket == NULL);

    handler->_security_impl = NULL;
    delete conSec;
}
