// Copyright (c) 2015-2019 Bitdefender SRL, All rights reserved.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library.

#ifndef __BDVMIKVMEVENTMANAGER_H_INCLUDED__
#define __BDVMIKVMEVENTMANAGER_H_INCLUDED__

#include <string>
#include <fstream>
#include <bitset>
#include "bdvmi/eventmanager.h"

namespace bdvmi {

class KvmDriver;

class KvmEventManager : public EventManager {
public:
	KvmEventManager( KvmDriver &driver, sig_atomic_t &sigStop );

	virtual ~KvmEventManager();

public:
	void waitForEvents() override;

	void stop() override;

	std::string uuid() override;

private:
	bool enableMsrEventsImpl( unsigned int msr ) override;

	bool disableMsrEventsImpl( unsigned int msr ) override;

	bool enableCrEventsImpl( unsigned int cr ) override;

	bool disableCrEventsImpl( unsigned int cr ) override;

	bool enableXSETBVEventsImpl() override;

	bool disableXSETBVEventsImpl() override;

	bool enableBreakpointEventsImpl() override;

	bool disableBreakpointEventsImpl() override;

	bool enableVMCALLEventsImpl() override;

	bool disableVMCALLEventsImpl() override;

	bool enableDescriptorEventsImpl() override;

	bool disableDescriptorEventsImpl() override;

	void flushEventQueue();

private:
	KvmEventManager( const KvmEventManager & );

	KvmEventManager &operator=( const KvmEventManager & );

	bool initVMEvents();

	bool initVcpuEvents();

	void traceEventMessage( const struct kvmi_dom_event &msg );

	void traceEventReply( const struct kvmi_dom_event &msg, const struct KvmDriver::EventReply &rpl );

private:
	KvmDriver &driver_;
	bool       stop_{ false };
	bool       disconnected_{ false };
};
} // namespace bdvmi

#endif // __BDVMIKVMEVENTMANAGER_H_INCLUDED__
