/*
 * Copyright (c) 2015 ARM. All rights reserved.
 */
#include "lwm2m-client-mbed/m2mconnectionhandlerpimpl.h"
#include "lwm2m-client/m2mconnectionobserver.h"
#include "lwm2m-client/m2mconnectionhandler.h"
#include "lwm2m-client/m2mconstants.h"

M2MConnectionHandler::M2MConnectionHandler(M2MConnectionObserver &observer,
                                                   M2MConnectionSecurity* sec,
                                                   M2MInterface::NetworkStack stack)
:_observer(observer)
{
    _private_impl = new M2MConnectionHandlerPimpl(this, observer, sec, stack);
}

M2MConnectionHandler::~M2MConnectionHandler()
{
    delete _private_impl;
}

bool M2MConnectionHandler::bind_connection(const uint16_t listen_port)
{

    return _private_impl->bind_connection(listen_port);
}

bool M2MConnectionHandler::resolve_server_address(const String& server_address,
                                                      const uint16_t server_port,
                                                      M2MConnectionObserver::ServerType server_type,
                                                      const M2MSecurity* security)
{
    return _private_impl->resolve_server_address(server_address, server_port,
                                                 server_type, security);
}

bool M2MConnectionHandler::start_listening_for_data()
{
    return _private_impl->start_listening_for_data();
}

void M2MConnectionHandler::stop_listening()
{
    _private_impl->stop_listening();
}

int M2MConnectionHandler::sendToSocket(const unsigned char *buf, size_t len)
{
    return _private_impl->sendToSocket(buf, len);
}

int M2MConnectionHandler::receiveFromSocket(unsigned char *buf, size_t len)
{
    return _private_impl->receiveFromSocket(buf, len);
}

bool M2MConnectionHandler::send_data(uint8_t *data,
                                     uint16_t data_len,
                                     sn_nsdl_addr_s *address)
{
    return _private_impl->send_data(data, data_len, address);
}

