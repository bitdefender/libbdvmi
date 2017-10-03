// Copyright (c) 2015-2017 Bitdefender SRL, All rights reserved.
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
#include <string>

namespace bdvmi {

// forward declaration, minimize compile-time file dependencies
class EventHandler;

class EventManager {

public:
	EventManager( EventHandler *handler = 0 ) : sigStop_( 0 ), handler_( handler )
	{
	}

	// base class, so virtual destructor
	virtual ~EventManager()
	{
	}

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

	void signalStopVar( sig_atomic_t *sigStop )
	{
		sigStop_ = sigStop;
	}

	virtual bool enableMsrEvents( unsigned int msr, bool &oldValue ) = 0;

	virtual bool disableMsrEvents( unsigned int msr, bool &oldValue ) = 0;

	virtual bool enableCrEvents( unsigned int cr ) = 0;

	virtual bool disableCrEvents( unsigned int cr ) = 0;

	// Loop waiting for events
	virtual void waitForEvents() = 0;

	// Stop the event loop
	virtual void stop() = 0;

	// Get the domain UUID
	virtual std::string uuid() = 0;

protected:
	sig_atomic_t *sigStop_;

private:
	EventHandler *handler_;
};

} // namespace bdvmi

#endif // __BDVMIEVENTMANAGER_H_INCLUDED__
