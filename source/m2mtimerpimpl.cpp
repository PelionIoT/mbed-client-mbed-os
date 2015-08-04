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
#include "lwm2m-client-mbed/m2mtimerpimpl.h"
#include "lwm2m-client/m2mtimerobserver.h"

M2MTimerPimpl::M2MTimerPimpl(M2MTimerObserver& observer)
: _observer(observer),
  _single_shot(true),
  _interval(0),
  _type(M2MTimerObserver::Notdefined),
  _intermediate_interval(0),
  _total_interval(0),
  _status(0)
{

}

M2MTimerPimpl::~M2MTimerPimpl()
{
}

void M2MTimerPimpl::start_timer( uint64_t interval,
                                 M2MTimerObserver::Type type,
                                 bool single_shot)
{
    _intermediate_interval = 0;
    _total_interval = 0;
    _status = 0;
    _single_shot = single_shot;
    _interval = interval;
    _type = type;

    _ticker.detach();
    _ticker.attach_us(this,
                      &M2MTimerPimpl::timer_expired,
                      _interval * 1000);
}

void M2MTimerPimpl::start_dtls_timer(uint64_t intermediate_interval, uint64_t total_interval, M2MTimerObserver::Type type)
{
    _intermediate_interval = intermediate_interval;
    _total_interval = total_interval;
    _type = type;
    _ticker.detach();
    _status = 0;
    _ticker.attach_us(this,
                      &M2MTimerPimpl::dtls_timer_expired,
                      _intermediate_interval * 1000);
}

void M2MTimerPimpl::stop_timer()
{
    _interval = 0;
    _single_shot = false;
    _ticker.detach();
}

void M2MTimerPimpl::timer_expired()
{
    _observer.timer_expired(_type);
    if(!_single_shot) {
        start_timer(_interval, _type, true);
    }
}

void M2MTimerPimpl::dtls_timer_expired()
{
    _status++;
    if(_status == 1) {
        _ticker.attach_us(this,
                          &M2MTimerPimpl::dtls_timer_expired,
                          (_total_interval - _intermediate_interval) * 1000);
    }else{
        _ticker.detach();
    }
}


bool M2MTimerPimpl::is_intermediate_interval_passed()
{
    if( _status > 0 ){
        return true;
    }
    return false;
}

bool M2MTimerPimpl::is_total_interval_passed()
{
    if( _status > 1 ){
        return true;
    }
    return false;
}
