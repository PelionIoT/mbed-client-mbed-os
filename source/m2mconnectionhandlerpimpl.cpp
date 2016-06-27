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
#include "mbed-client/m2msecurity.h"
#include "mbed-client/m2mconnectionhandler.h"
#include "mbed-trace/mbed_trace.h"

#define TRACE_GROUP "mClt"
using namespace mbed::Sockets::v0;

M2MConnectionHandlerPimpl::M2MConnectionHandlerPimpl(M2MConnectionHandler* base, M2MConnectionObserver &observer,
                                                     M2MConnectionSecurity* sec,
                                                     M2MInterface::BindingMode mode,
                                                     M2MInterface::NetworkStack stack)
:_base(base),
 _observer(observer),
 _security_impl(sec),
 _security(NULL),
 _use_secure_connection(false),
 _binding_mode(mode),
 _network_stack(stack),
 _resolved_address(new SocketAddr()),
 _socket_stack(SOCKET_STACK_UNINIT),
 _is_handshaking(false),
 _mbed_socket(NULL),
 _error_reported(false)
{
    _socket_address = (M2MConnectionObserver::SocketAddress *)malloc(sizeof(M2MConnectionObserver::SocketAddress));
    memset(_socket_address, 0, sizeof(M2MConnectionObserver::SocketAddress));
    _socket_address->_address = _received_address;
    memset(_receive_buffer,0,sizeof(_receive_buffer));
}

M2MConnectionHandlerPimpl::~M2MConnectionHandlerPimpl()
{
    if(_resolved_address) {
        delete _resolved_address;
        _resolved_address = NULL;
    }
    close_socket();
    if(_socket_address) {
        free(_socket_address);
    }

    delete _security_impl;
}

bool M2MConnectionHandlerPimpl::bind_connection(const uint16_t listen_port)
{
    tr_debug("M2MConnectionHandlerPimpl::bind_connection , port %d", listen_port);
    close_socket();
    init_socket();
    socket_error_t err = SOCKET_ERROR_NONE;
    if(_mbed_socket) {
        if(_network_stack == M2MInterface::LwIP_IPv4) {
            err = _mbed_socket->bind("0.0.0.0", listen_port);
        } else if(_network_stack == M2MInterface::Nanostack_IPv6) {
            err = _mbed_socket->bind("0:0:0:0:0:0:0:0", listen_port);
        }
    }
    return SOCKET_ERROR_NONE == err;
}

bool M2MConnectionHandlerPimpl::resolve_server_address(const String& server_address,
                                                      const uint16_t server_port,
                                                      M2MConnectionObserver::ServerType server_type,
                                                      const M2MSecurity* security)
{
    tr_debug("M2MConnectionHandlerPimpl::resolve_server_address");
    if (!_mbed_socket) {
        return false;
    }
    _security = security;
    socket_error_t err = SOCKET_ERROR_NONE;
    _server_address = server_address;
    _server_port = server_port;
    _server_type = server_type;

    err = _mbed_socket->resolve(_server_address.c_str(),
                           MbedSocket::DNSHandler_t(this, &M2MConnectionHandlerPimpl::dns_handler));
    return SOCKET_ERROR_NONE == err;
}

bool M2MConnectionHandlerPimpl::send_data(uint8_t *data,
                                     uint16_t data_len,
                                     sn_nsdl_addr_s *address)
{
    tr_debug("M2MConnectionHandlerPimpl::send_data");
    if( address == NULL || data == NULL || !_mbed_socket){
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
        if(is_tcp_connection()){
            //We need to "shim" the length in front
            uint16_t d_len = data_len+4;
            uint8_t* d = (uint8_t*)malloc(data_len+4);

            d[0] = (data_len >> 24 )& 0xff;
            d[1] = (data_len >> 16 )& 0xff;
            d[2] = (data_len >> 8 )& 0xff;
            d[3] = data_len & 0xff;
            memmove(d+4, data, data_len);
            error = _mbed_socket->send(d, d_len);
            free(d);
        }else{
            error = _mbed_socket->send_to(data, data_len,_resolved_address,_server_port);
        }
    }
    return SOCKET_ERROR_NONE == error;
}

void M2MConnectionHandlerPimpl::send_handler(Socket */*socket*/, uint16_t /*data_sent*/)
{
    _observer.data_sent();
}

bool M2MConnectionHandlerPimpl::start_listening_for_data()
{
    tr_debug("M2MConnectionHandlerPimpl::start_listening_for_data");
    if (_mbed_socket) {
        _mbed_socket->setOnReadable(NULL);
        _mbed_socket->setOnReadable(MbedSocket::ReadableHandler_t(this, &M2MConnectionHandlerPimpl::receive_handler));
        return true;
    }
    return false;
}

void M2MConnectionHandlerPimpl::stop_listening()
{
    _error_reported = true;
}

int M2MConnectionHandlerPimpl::send_to_socket(const unsigned char *buf, size_t len)
{
    tr_debug("M2MConnectionHandlerPimpl::send_to_socket");
    if (!_mbed_socket) {
        return -1;
    }

    socket_error_t error = SOCKET_ERROR_NONE;
    if(is_tcp_connection()){
        error = _mbed_socket->send(buf, len);
    }else{ 
        error = _mbed_socket->send_to(buf, len,_resolved_address,_server_port);
    }

    if( SOCKET_ERROR_WOULD_BLOCK == error ){
        return M2MConnectionHandler::CONNECTION_ERROR_WANTS_WRITE;
    }else if( SOCKET_ERROR_NONE != error ){
        return -1;
    }else{
        return len;
    }
}

int M2MConnectionHandlerPimpl::receive_from_socket(unsigned char *buf, size_t len)
{
    tr_debug("M2MConnectionHandlerPimpl::receive_from_socket");
    if (!_mbed_socket) {
        return -1;
    }
    socket_error_t error;

    if(is_tcp_connection()){
        error = _mbed_socket->recv(buf, &len);
    }else{
        SocketAddr remote_address;
        uint16_t remote_port;
        error = _mbed_socket->recv_from(buf, &len,&remote_address,&remote_port);
        _socket_address->_port = remote_port;
    }

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
    tr_debug("M2MConnectionHandlerPimpl::receive_handshake_handler");
    if (!_mbed_socket) {
        return;
    }

    memset(_receive_buffer, 0, BUFFER_LENGTH);
    if( _is_handshaking ){
        int ret = _security_impl->continue_connecting();
        if( ret == M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ ){ //We wait for next readable event
            return;
        } else if( ret == 0 ){
            _is_handshaking = false;
            _mbed_socket->setOnReadable(NULL);
            _use_secure_connection = true;
            _observer.address_ready(*_socket_address,
                                    _server_type,
                                    _server_port);
        }else if( ret < 0 ){
            tr_debug("M2MConnectionHandlerPimpl::receive_handshake_handler - SSL handshake failed");
            _is_handshaking = false;
            _observer.socket_error(M2MConnectionHandler::SSL_CONNECTION_ERROR, false);
            _error_reported = true;
            close_socket();
        }
    }
}

void M2MConnectionHandlerPimpl::receive_handler(Socket */*socket*/)
{
    tr_debug("M2MConnectionHandlerPimpl::receive_handler");
    if (!_mbed_socket) {
        return;
    }

    memset(_receive_buffer, 0, BUFFER_LENGTH);
    size_t receive_length = sizeof(_receive_buffer);

    if( _use_secure_connection ){
        int rcv_size = _security_impl->read(_receive_buffer, receive_length);
        if(rcv_size >= 0){
            _observer.data_available((uint8_t*)_receive_buffer,
                                     rcv_size, *_socket_address);
        } else if (M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ != rcv_size) {
            tr_debug("M2MConnectionHandlerPimpl::receive_handler - SOCKET_READ_ERROR");
            return;
        }
    }else{
        socket_error_t error = SOCKET_ERROR_NONE;
        uint16_t remote_port;
        if(is_tcp_connection()){
            error = _mbed_socket->recv(_receive_buffer, &receive_length);
        }else{
            SocketAddr remote_address;
            error = _mbed_socket->recv_from(_receive_buffer, &receive_length,&remote_address,&remote_port);
        }
        if (SOCKET_ERROR_NONE == error) {
            _socket_address->_port = remote_port;
            // Send data for processing.
            if(is_tcp_connection()){
                //We need to "shim" out the length from the front
                if( receive_length > 4 ){
                    uint64_t len = (_receive_buffer[0] << 24 & 0xFF000000) + (_receive_buffer[1] << 16 & 0xFF0000);
                    len += (_receive_buffer[2] << 8 & 0xFF00) + (_receive_buffer[3] & 0xFF);
                    if(len > 0) {
                        uint8_t* buf = (uint8_t*)malloc(len);
                        if(buf) {
                            memmove(buf, _receive_buffer+4, len);
                            // Observer for TCP plain mode
                            _observer.data_available(buf,len,*_socket_address);
                            free(buf);
                        }
                    }
                }
            } else { // Observer for UDP plain mode
                _observer.data_available((uint8_t*)_receive_buffer,
                                         receive_length, *_socket_address);
            }
        }
    }
}

void M2MConnectionHandlerPimpl::dns_handler(Socket */*socket*/, struct socket_addr sa, const char */*domain*/)
{
    tr_debug("M2MConnectionHandlerPimpl::dns_handler");
    if (!_mbed_socket) {
        return;
    }

    _resolved_address->setAddr(&sa);
    socket_error_t socket_err = SOCKET_ERROR_NONE;
    if(_resolved_address->is_v4()) {
        _socket_address->_length = 4;
        *(uint32_t *)(_socket_address->_address) = sa.ipv6be[3];
    } else {
        _socket_address->_length = 16;
        memcpy(_socket_address->_address, sa.ipv6be, 16);
    }

    _socket_address->_stack = _network_stack;
    _socket_address->_port = _server_port;

    if(is_tcp_connection()){
        socket_err = _mbed_socket->connect(_resolved_address, _server_port);
    }
    if( _security && SOCKET_ERROR_NONE == socket_err ){
        if( _security->resource_value_int(M2MSecurity::SecurityMode) == M2MSecurity::Certificate ||
           _security->resource_value_int(M2MSecurity::SecurityMode) == M2MSecurity::Psk ){
            if( _security_impl != NULL ){
                _security_impl->reset();
                if (_security_impl->init(_security) == 0) {
                    _is_handshaking = true;
                    _mbed_socket->setOnReadable(MbedSocket::ReadableHandler_t(this,
                            &M2MConnectionHandlerPimpl::receive_handshake_handler));
                    tr_debug("M2MConnectionHandlerPimpl::dns_handler - start handshake");
                    if( _security_impl->start_connecting_non_blocking(_base) < 0 ){
                        tr_debug("M2MConnectionHandlerPimpl::dns_handler - handshake failed");
                        _is_handshaking = false;
                        _mbed_socket->setOnReadable(NULL);
                        if (!_error_reported) {
                            _observer.socket_error(M2MConnectionHandler::SSL_CONNECTION_ERROR);
                            _error_reported = true;
                            close_socket();
                        }
                        return;
                    }
                } else {
                    tr_error("M2MConnectionHandlerPimpl::dns_handler - init failed");
                    _observer.socket_error(M2MConnectionHandler::SSL_CONNECTION_ERROR, false);
                    _error_reported = true;
                    close_socket();
                }
            } else {
                tr_error("M2MConnectionHandlerPimpl::dns_handler - sec is null");
                _observer.socket_error(M2MConnectionHandler::SSL_CONNECTION_ERROR, false);
                _error_reported = true;
                close_socket();
            }
        }
    }
    if( !_is_handshaking ){
        tr_debug("M2MConnectionHandlerPimpl::dns_handler - address_ready");
        _observer.address_ready(*_socket_address,
                                _server_type,
                                _server_port);
    }
}

void M2MConnectionHandlerPimpl::error_handler(Socket */*socket*/,
                                              socket_error_t error)
{
    if (!_mbed_socket) {
        return;
    }
    tr_debug("M2MConnectionHandlerPimpl::error_handler - error code: %d", error);
    M2MConnectionHandler::ConnectionError error_code = M2MConnectionHandler::ERROR_NONE;
    switch(error) {
        case SOCKET_ERROR_UNKNOWN:
        case SOCKET_ERROR_UNIMPLEMENTED:
        case SOCKET_ERROR_BUSY:
        case SOCKET_ERROR_NULL_PTR:
        case SOCKET_ERROR_BAD_FAMILY:
        case SOCKET_ERROR_TIMEOUT:
        case SOCKET_ERROR_BAD_ALLOC:
        case SOCKET_ERROR_NO_CONNECTION:
        case SOCKET_ERROR_SIZE:
        case SOCKET_ERROR_STACK_EXISTS:
        case SOCKET_ERROR_STACKS:
        case SOCKET_ERROR_BAD_STACK:
        case SOCKET_ERROR_BAD_ADDRESS:
        case SOCKET_ERROR_WOULD_BLOCK:
        case SOCKET_ERROR_CLOSED:
        case SOCKET_ERROR_VALUE:
        case SOCKET_ERROR_ALREADY_CONNECTED:
        case SOCKET_ERROR_BAD_ARGUMENT:
        case SOCKET_ERROR_INTERFACE_ERROR:
        case SOCKET_ERROR_API_VERSION:
        case SOCKET_ERROR_NOT_BOUND:
            error_code = M2MConnectionHandler::SOCKET_ABORT;
            break;
        case SOCKET_ERROR_DNS_FAILED:
        case SOCKET_ERROR_ADDRESS_IN_USE:
            error_code = M2MConnectionHandler::DNS_RESOLVING_ERROR;
            break;            
        case SOCKET_ERROR_ABORT:
        case SOCKET_ERROR_RESET:
            if (_is_handshaking)
                error_code = M2MConnectionHandler::SSL_CONNECTION_ERROR;
            else{
                error_code = M2MConnectionHandler::SOCKET_READ_ERROR;
            }
            break;
        default:
            break;
    }

    if(SOCKET_ERROR_NONE != error && !_error_reported) {
        _observer.socket_error(error_code, true);
        close_socket();
    } else {
        tr_debug("M2MConnectionHandlerPimpl::error_handler - error already reported");
    }
}

void M2MConnectionHandlerPimpl::handle_connection_error(int error)
{
    //This will come from M2MConnectionSecurity class
    _observer.socket_error(error);
}

void M2MConnectionHandlerPimpl::init_socket()
{
    tr_debug("M2MConnectionHandlerPimpl::init_socket - IN");
    _error_reported = false;
    _is_handshaking = false;
    int ret = 0;
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
        case M2MInterface::ATWINC_IPv4:
            _socket_stack = SOCKET_STACK_ATWINC_IPV4;
            break;
        case M2MInterface::Unknown:
            _socket_stack = SOCKET_STACK_MAX;
            break;
        default:
            break;
    }

    if(is_tcp_connection()){
        _mbed_socket = new MbedSocket(_socket_stack, SOCKET_STREAM);
        ret = _mbed_socket->open(socket_family, SOCKET_STREAM);
    }else{
        _mbed_socket = new MbedSocket(_socket_stack, SOCKET_DGRAM);
        ret = _mbed_socket->open(socket_family, SOCKET_DGRAM);
    }
    if (ret == SOCKET_ERROR_NONE) {
        _mbed_socket->setOnSent(MbedSocket::SentHandler_t(this, &M2MConnectionHandlerPimpl::send_handler));
        _mbed_socket->setOnError(MbedSocket::ErrorHandler_t(this, &M2MConnectionHandlerPimpl::error_handler));
    } else {
        _observer.socket_error(M2MConnectionHandler::SOCKET_ABORT);
        _error_reported = true;
    }
    tr_debug("M2MConnectionHandlerPimpl::init_socket - OUT");
}

bool M2MConnectionHandlerPimpl::is_tcp_connection()
{
    return _binding_mode == M2MInterface::TCP ||
            _binding_mode == M2MInterface::TCP_QUEUE ? true : false;
}

void M2MConnectionHandlerPimpl::close_socket()
{
    if (_security_impl) {
        _security_impl->reset();
    }
    if(_mbed_socket) {
        _mbed_socket->close();
        delete _mbed_socket;
        _mbed_socket = NULL;
    }
}
