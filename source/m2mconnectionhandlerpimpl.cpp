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
#include "mbed-client-mbed-os/m2mconnectionhandlerpimpl.h"
#include "mbed-client/m2mconnectionobserver.h"
#include "mbed-client/m2mconstants.h"
#include "mbed-client/m2msecurity.h"
#include "mbed-client/m2mconnectionhandler.h"

using namespace mbed::Sockets::v0;

M2MConnectionHandlerPimpl::M2MConnectionHandlerPimpl(M2MConnectionHandler* base, M2MConnectionObserver &observer,
                                                   M2MConnectionSecurity* sec,
                                                   M2MInterface::NetworkStack stack)
:_base(base),
 _observer(observer),
 _security_impl(sec),
  _use_secure_connection(false),
 _network_stack(stack),
  _resolved_Address(new SocketAddr()),
  _resolved(true),
 _socket_stack(SOCKET_STACK_UNINIT),
 _is_handshaking(false)
{
    _socket_address = (M2MConnectionObserver::SocketAddress *)malloc(sizeof(M2MConnectionObserver::SocketAddress));
    memset(_socket_address, 0, sizeof(M2MConnectionObserver::SocketAddress));
    _socket_address->_address = _received_address;

    socket_address_family_t socket_family = SOCKET_AF_INET4;

    switch(_network_stack) {
        case M2MInterface::Uninitialized:
            _socket_stack = SOCKET_STACK_UNINIT;
            break;
        case M2MInterface::LwIP_IPv4:
            _socket_stack = SOCKET_STACK_LWIP_IPV4;
            break;
        case M2MInterface::LwIP_IPv6:
            _socket_stack = SOCKET_STACK_LWIP_IPV6;
            socket_family = SOCKET_AF_INET6;
            break;
        case M2MInterface::Reserved:
            _socket_stack = SOCKET_STACK_RESERVED;
            break;
        case M2MInterface::Nanostack_IPv6:
            _socket_stack = SOCKET_STACK_NANOSTACK_IPV6;
            socket_family = SOCKET_AF_INET6;
            break;
        case M2MInterface::Unknown:
            _socket_stack = SOCKET_STACK_MAX;
            break;
        default:
            break;
    }

    memset(_receive_buffer,0,sizeof(_receive_buffer));

    _socket = new UDPSocket(_socket_stack);
    //TODO: select socket_address_family based on Network stack
    _socket->open(socket_family);
    _socket->setOnSent(UDPSocket::SentHandler_t(this, &M2MConnectionHandlerPimpl::send_handler));
    _socket->setOnError(UDPSocket::ErrorHandler_t(this, &M2MConnectionHandlerPimpl::error_handler));
}

M2MConnectionHandlerPimpl::~M2MConnectionHandlerPimpl()
{
    if(_resolved_Address) {
        delete _resolved_Address;
        _resolved_Address = NULL;
    }
    if(_socket) {
        delete _socket;
        _socket = NULL;
    }
    if(_socket_address) {
        free(_socket_address);
    }

    delete _security_impl;
}

bool M2MConnectionHandlerPimpl::bind_connection(const uint16_t listen_port)
{
    //TODO: Use bind in mbed Socket
    socket_error_t err = SOCKET_ERROR_NONE;
    if(_socket) {
        if(_network_stack == M2MInterface::LwIP_IPv4) {
            err = _socket->bind("0.0.0.0", listen_port);
        } else if(_network_stack == M2MInterface::Nanostack_IPv6) {
            err = _socket->bind("0:0:0:0:0:0:0:0", listen_port);
        }
    }
    return SOCKET_ERROR_NONE == err;
}

bool M2MConnectionHandlerPimpl::resolve_server_address(const String& server_address,
                                                      const uint16_t server_port,
                                                      M2MConnectionObserver::ServerType server_type,
                                                      const M2MSecurity* security)
{
    _security = security;
    socket_error_t err = SOCKET_ERROR_NONE;
    if(_resolved) {
        _resolved = false;
        _server_address = server_address;
        _server_port = server_port;
        _server_type = server_type;

        err = _socket->resolve(_server_address.c_str(),
                               UDPSocket::DNSHandler_t(this, &M2MConnectionHandlerPimpl::dns_handler));
    }
    return SOCKET_ERROR_NONE == err;
}

bool M2MConnectionHandlerPimpl::send_data(uint8_t *data,
                                     uint16_t data_len,
                                     sn_nsdl_addr_s *address)
{
    if( address == NULL ){
        return false;
    }
    socket_error_t error = SOCKET_ERROR_NONE;
    if( _use_secure_connection ){
        if( _security_impl->send_message(data, data_len) > 0){
            error = SOCKET_ERROR_NONE;
        }else{
            error = SOCKET_ERROR_UNKNOWN;
        }
    }else{
        error = _socket->send_to(data, data_len,_resolved_Address,address->port);
    }
    return SOCKET_ERROR_NONE == error;
}

void M2MConnectionHandlerPimpl::send_handler(Socket */*socket*/, uint16_t /*data_sent*/)
{
    _observer.data_sent();
}

bool M2MConnectionHandlerPimpl::start_listening_for_data()
{
    // Boolean return required for other platforms,
    // not needed in mbed Socket.
    _socket->setOnReadable(UDPSocket::ReadableHandler_t(this, &M2MConnectionHandlerPimpl::receive_handler));
    return true;
}

void M2MConnectionHandlerPimpl::stop_listening()
{

}

int M2MConnectionHandlerPimpl::sendToSocket(const unsigned char *buf, size_t len)
{
    //socket_error_t error = _socket->send(buf, len);
    socket_error_t error = _socket->send_to(buf, len,_resolved_Address,_server_port);
    if( SOCKET_ERROR_WOULD_BLOCK == error ){
        return M2MConnectionHandler::CONNECTION_ERROR_WANTS_WRITE;
    }else if( SOCKET_ERROR_NONE != error ){
        return -1;
    }else{
        return len;
    }

}

int M2MConnectionHandlerPimpl::receiveFromSocket(unsigned char *buf, size_t len)
{
    SocketAddr remote_address;
    uint16_t remote_port;
    //socket_error_t error = _socket->recv(buf, &len);
    socket_error_t error;
    error = _socket->recv_from(buf, &len,&remote_address,&remote_port);

    if( SOCKET_ERROR_WOULD_BLOCK == error ){
        return M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ;
    }else if( SOCKET_ERROR_NONE != error ){
        return -1;
    }else{
        return len;
    }
}

void M2MConnectionHandlerPimpl::receive_handshake_handler(Socket */*socket*/)
{
    memset(_receive_buffer, 0, BUFFER_LENGTH);
    if( _is_handshaking ){
        int ret = _security_impl->continue_connecting();
        if( ret == M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ ){ //We wait for next readable event
            return;
        } else if( ret == 0 ){
            _is_handshaking = false;
            _socket->setOnReadable(NULL);
            _use_secure_connection = true;
            _observer.address_ready(*_socket_address,
                                    _server_type,
                                    _server_port);
        }else if( ret < 0 ){
            //TODO: Socket error in SSL handshake,
            // Define error code.
            _is_handshaking = false;
            _socket->setOnReadable(NULL);
            _observer.socket_error(4);
        }
    }
}

void M2MConnectionHandlerPimpl::receive_handler(Socket */*socket*/)
{
    memset(_receive_buffer, 0, BUFFER_LENGTH);
    size_t receive_length = sizeof(_receive_buffer);
    SocketAddr remote_address;
    uint16_t remote_port;
    if( _use_secure_connection ){
        int rcv_size = _security_impl->read(_receive_buffer, receive_length);
        if(rcv_size >= 0){
            receive_length = rcv_size;
        }else{
            _observer.socket_error(1);
            return;
        }
    }else{
        socket_error_t error = _socket->recv_from(_receive_buffer, &receive_length,&remote_address,&remote_port);
        if (SOCKET_ERROR_NONE == error) {

            memset(_socket_address,0,sizeof(M2MConnectionObserver::SocketAddress));

            _socket_address->_address =remote_address.getAddr()->ipv6be;
            //TODO: Current support only for IPv4, add IPv6 support
            if(_network_stack == M2MInterface::LwIP_IPv4) {
                _socket_address->_length = 4;
            } else if(_network_stack == M2MInterface::Nanostack_IPv6) {
                _socket_address->_length = 16;
            }
            _socket_address->_port = remote_port;
            _socket_address->_stack = _network_stack;

        } else {
            // Socket error in receiving
            _observer.socket_error(1);
            return;
        }
    }
    // Send data for processing.
    _observer.data_available((uint8_t*)_receive_buffer,
                             receive_length, *_socket_address);
}

void M2MConnectionHandlerPimpl::dns_handler(Socket */*socket*/, struct socket_addr sa, const char */*domain*/)
{
    _resolved = true;
    memset(_socket_address,0,sizeof(M2MConnectionObserver::SocketAddress));

    _resolved_Address->setAddr(&sa);
    _socket_address->_address = sa.ipv6be;

    if(_resolved_Address->is_v4()) {
        _socket_address->_length = 4;
    } else {
        _socket_address->_length = 16;
    }
    _socket_address->_stack = _network_stack;
    _socket_address->_port = _server_port;

    if( _security ){
        if( _security->resource_value_int(M2MSecurity::SecurityMode) == M2MSecurity::Certificate ||
           _security->resource_value_int(M2MSecurity::SecurityMode) == M2MSecurity::Psk ){
            if( _security_impl != NULL ){
                _security_impl->reset();
                _security_impl->init(_security);
                _is_handshaking = true;
                _socket->setOnReadable(UDPSocket::ReadableHandler_t(this, &M2MConnectionHandlerPimpl::receive_handshake_handler));
                if( _security_impl->start_connecting_non_blocking(_base) < 0 ){
                    //TODO: Socket error in SSL handshake,
                    // Define error code.
                    _is_handshaking = false;
                    _socket->setOnReadable(NULL);
                    _observer.socket_error(4);
                    return;
                }
            }
        }
    }
    if( !_is_handshaking ){
        _observer.address_ready(*_socket_address,
                                _server_type,
                                _server_port);
    }
}

void M2MConnectionHandlerPimpl::error_handler(Socket */*socket*/,
                                              socket_error_t error)
{
    //TODO: Socket error in dns resolving,
    // Define error code.
    if(SOCKET_ERROR_NONE != error) {
        _observer.socket_error(2);
    }
}
