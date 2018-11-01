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

#ifndef __BDVMIXENEVENTMANAGER_H_INCLUDED__
#define __BDVMIXENEVENTMANAGER_H_INCLUDED__

#include "bdvmi/eventmanager.h"
#include <fstream>
#include <stdint.h>
#include <string>

extern "C" {
#define private rprivate /* private is a C++ keyword */
#include <xen/vm_event.h>
#undef private
}

#include "xcwrapper.h"
#include "xswrapper.h"

namespace bdvmi {

class XenDriver;
class LogHelper;

class XenEventManager : public EventManager {

public:
	XenEventManager( XenDriver &driver, sig_atomic_t &sigStop, LogHelper *logHelper, bool useAltP2m = false );

	virtual ~XenEventManager();

public:
	// Loop waiting for events
	void waitForEvents() override;

	// Stop the event loop
	void stop() override;

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

private:
	void initXenStore();

	void initEventChannels();

	void initMemAccess();

	void initAltP2m();

	int waitForEventOrTimeout( int ms );

	void getRequest( vm_event_request_t *req );

	void putResponse( vm_event_response_t *rsp );

	void resumePage();

	std::string uuid() override;

	void cleanup();

	void setRegisters( vm_event_response_t &rsp );

	bool setCrEvents( unsigned int cr, bool enable );

	uint64_t getMsr( unsigned short vcpu, uint32_t msr ) const;

private:
	// Don't allow copying for these objects
	XenEventManager( const XenEventManager & );

	// Don't allow copying for these objects
	XenEventManager &operator=( const XenEventManager & );

private:
	XenDriver &          driver_;
	XC &                 xc_;
	domid_t              domain_;
	bool                 stop_{ false };
	xc_evtchn *          xce_{ nullptr };
	int                  port_{ -1 };
	XS                   xs_;
	uint32_t             evtchnPort_{ 0 };
	vm_event_back_ring_t backRing_;
	void *               ringPage_{ nullptr };
	std::string          watchToken_;
	std::string          controlXenStorePath_;
	bool                 memAccessOn_{ false };
	bool                 evtchnOn_{ false };
	bool                 evtchnBindOn_{ false };
	bool                 guestStillRunning_{ true };
	LogHelper *          logHelper_;
	bool                 firstReleaseWatch_{ true };
	bool                 firstXenServerWatch_{ true };
	bool                 useAltP2m_;
	bool                 foundEvents_{ false };

	using msrs_values_map_t = std::map<uint32_t, uint64_t>;
	using vcpu_msrs_t       = std::map<unsigned short, msrs_values_map_t>;
	vcpu_msrs_t msrOldValueCache_;

#ifdef DEBUG_DUMP_EVENTS
	std::ofstream eventsFile_;
#endif
};

} // namespace bdvmi

#endif // __BDVMIXENEVENTMANAGER_H_INCLUDED__
