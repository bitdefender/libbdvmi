// Copyright (c) 2015-2018 Bitdefender SRL, All rights reserved.
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

#ifndef __BDVMIEVENTMANAGER_H_INCLUDED__
#define __BDVMIEVENTMANAGER_H_INCLUDED__

#include <signal.h>
#include <set>
#include <string>

namespace bdvmi {

// forward declaration, minimize compile-time file dependencies
class EventHandler;

class EventManager {

public:
	EventManager( sig_atomic_t &sigStop );

	// base class, so virtual destructor
	virtual ~EventManager() = default;

public:
	// Set the handler
	void handler( EventHandler *handler )
	{
		handler_ = handler;
	}

	// Get the handler
	EventHandler *handler() const
	{
		return handler_;
	}

	bool enableMsrEvents( unsigned int msr, bool &oldValue );

	bool disableMsrEvents( unsigned int msr, bool &oldValue );

	bool enableCrEvents( unsigned int cr );

	bool disableCrEvents( unsigned int cr );

	bool enableXSETBVEvents();

	bool disableXSETBVEvents();

	bool enableBreakpointEvents();

	bool disableBreakpointEvents();

	bool enableVMCALLEvents();

	bool disableVMCALLEvents();

	// Loop waiting for events
	virtual void waitForEvents() = 0;

	// Stop the event loop
	virtual void stop() = 0;

	// Get the domain UUID
	virtual std::string uuid() = 0;

	//
	// If a guest cannot be hooked until it is rebooted, the backend
	// might need to be informed about this. For example, on KVM we
	// need to hold on to the guest until said event otherwise qemu
	// will automatically re-trigger a new guest notification leading
	// to a loop where we continuosly try to hook, determine we are
	// unable to do so, disconnect, get re-notified and so on.
	//
	// The same applies for domains running unsupported OS-es.
	//
	virtual void waitForReboot()
	{
	}

	void lastSignal( int sig )
	{
		lastSignal_ = sig;
	}

private:
	virtual bool enableMsrEventsImpl( unsigned int msr ) = 0;

	virtual bool disableMsrEventsImpl( unsigned int msr ) = 0;

	virtual bool enableCrEventsImpl( unsigned int cr ) = 0;

	virtual bool disableCrEventsImpl( unsigned int cr ) = 0;

	virtual bool enableXSETBVEventsImpl() = 0;

	virtual bool disableXSETBVEventsImpl() = 0;

	virtual bool enableBreakpointEventsImpl() = 0;

	virtual bool disableBreakpointEventsImpl() = 0;

	virtual bool enableVMCALLEventsImpl() = 0;

	virtual bool disableVMCALLEventsImpl() = 0;

protected:
	sig_atomic_t &         sigStop_;
	std::set<unsigned int> enabledCrs_;
	std::set<unsigned int> enabledMsrs_;
	sig_atomic_t           lastSignal_{ 0 };

private:
	EventHandler *handler_{ nullptr };
	bool          breakpointEnabled_{ false };
	bool          xsetbvEnabled_{ false };
	bool          vmcallEnabled_{ false };
};
} // namespace bdvmi

#endif // __BDVMIEVENTMANAGER_H_INCLUDED__
