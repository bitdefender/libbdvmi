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

#ifndef __BDVMIXENEVENTMANAGER_H_INCLUDED__
#define __BDVMIXENEVENTMANAGER_H_INCLUDED__

#include "bdvmi/eventhandler.h"
#include "bdvmi/eventmanager.h"
#include <fstream>
#include <stdint.h>
#include <string>
#include <unordered_map>

extern "C" {
#define private rprivate /* private is a C++ keyword */
#include <xen/vm_event.h>
#undef private
}

#include "xcwrapper.h"
#include "xswrapper.h"

namespace bdvmi {

class XenDriver;

class XenEventManager : public EventManager {

public:
	XenEventManager( XenDriver &driver, sig_atomic_t &sigStop );

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

	bool enableDescriptorEventsImpl() override;

	bool disableDescriptorEventsImpl() override;

private:
	void initXenStore();

	void initEventChannels();

	void initMemAccess();

	int waitForEventOrTimeout( int ms );

	template <typename Request, typename Ring> void getRequest( Request &req );

	template <typename Response, typename Ring> void putResponse( const Response &rsp );

	void resumePage();

	std::string uuid() override;

	void cleanup();

	template <typename Response> void setRegisters( Response &rsp );

	bool setCrEvents( unsigned int cr, bool enable );

	uint64_t getMsr( unsigned short vcpu, uint32_t msr ) const;

	template <typename Request, typename Response, typename Ring> void waitForEventsByVMEventVersion();

	template <typename Request, typename Response>
	void handleMemAccess( const Request &req, Response &rsp, bool &skip );

	template <typename Request, typename Response> void handleCrWrite( const Request &req, Response &rsp );

	template <typename Request, typename Response> void handleMsrWrite( const Request &req, Response &rsp );

	template <typename Request, typename Response>
	void handleDescriptorWrite( const Request &req, Response &rsp, bool &skip );

	template <typename Request> void handleBreakpoint( const Request &req );

public:
	// Don't allow copying for these objects
	XenEventManager( const XenEventManager & ) = delete;

	// Don't allow copying for these objects
	XenEventManager &operator=( const XenEventManager & ) = delete;

private:
	XenDriver & driver_;
	XC &        xc_;
	domid_t     domain_;
	bool        stop_{ false };
	xc_evtchn * xce_{ nullptr };
	int         port_{ -1 };
	XS          xs_;
	uint32_t    evtchnPort_{ 0 };
	void *      backRing_{ nullptr };
	void *      ringPage_{ nullptr };
	std::string watchToken_;
	std::string controlXenStorePath_;
	bool        memAccessOn_{ false };
	bool        evtchnOn_{ false };
	bool        evtchnBindOn_{ false };
	bool        firstReleaseWatch_{ true };
	bool        firstControlCommand_{ true };
	bool        foundEvents_{ false };
	uint32_t    vmEventInterfaceVersion_{ 0 };
	GuestState  guestState_{ RUNNING };

	using msrs_values_map_t = std::unordered_map<uint32_t, uint64_t>;
	using vcpu_msrs_t       = std::unordered_map<unsigned short, msrs_values_map_t>;
	vcpu_msrs_t msrOldValueCache_;

#ifdef DEBUG_DUMP_EVENTS
	std::ofstream eventsFile_;
#endif
};

} // namespace bdvmi

#endif // __BDVMIXENEVENTMANAGER_H_INCLUDED__
