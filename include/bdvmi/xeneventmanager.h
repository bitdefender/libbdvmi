// Copyright (c) 2015 Bitdefender SRL, All rights reserved.
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

#include "eventmanager.h"
#include <stdint.h>
#include <string>

extern "C" {
#include <xen/xen-compat.h>
#if __XEN_LATEST_INTERFACE_VERSION__ >= 0x00040300
#include <xenstore.h>
#else
#error unsupported Xen version
#endif

#include <xenctrl.h>
#include <xen/hvm/save.h>

#define private rprivate /* private is a C++ keyword */
#if __XEN_LATEST_INTERFACE_VERSION__ >= 0x00040500
#include <xen/vm_event.h>
#define mem_event_request_t vm_event_request_t
#define mem_event_response_t vm_event_response_t
#define mem_event_back_ring_t vm_event_back_ring_t
#define mem_event_sring_t vm_event_sring_t
#define MEM_EVENT_REASON_VIOLATION VM_EVENT_REASON_MEM_ACCESS
#define MEM_EVENT_REASON_CR0 VM_EVENT_REASON_MOV_TO_CR0
#define MEM_EVENT_REASON_CR3 VM_EVENT_REASON_MOV_TO_CR3
#define MEM_EVENT_REASON_CR4 VM_EVENT_REASON_MOV_TO_CR4
#define MEM_EVENT_REASON_MSR VM_EVENT_REASON_MOV_TO_MSR
#define MEM_EVENT_FLAG_EMULATE VM_EVENT_FLAG_EMULATE
#define MEM_EVENT_FLAG_EMULATE_NOWRITE VM_EVENT_FLAG_EMULATE_NOWRITE
#else
#include <xen/mem_event.h>
#endif
#undef private
}

#include "xeninlines.h"

namespace bdvmi {

class XenDriver;
class LogHelper;

class XenEventManager : public EventManager {

public:
	XenEventManager( const XenDriver &driver, unsigned short handlerFlags, LogHelper *logHelper );

	virtual ~XenEventManager();

public:
	virtual bool handlerFlags( unsigned short flags );

	virtual unsigned short handlerFlags() const
	{
		return handlerFlags_;
	}

	// Loop waiting for events
	virtual void waitForEvents();

	// Stop the event loop
	virtual void stop();

private:
	void initXenStore();

	void initEventChannels();

	void initMemAccess();

	int waitForEventOrTimeout( int ms );

	void getRequest( mem_event_request_t *req );

	void putResponse( mem_event_response_t *rsp );

	void resumePage( mem_event_response_t *rsp );

	std::string uuid();

	void cleanup();

private:
	// Don't allow copying for these objects
	XenEventManager( const XenEventManager & );

	// Don't allow copying for these objects
	XenEventManager &operator=( const XenEventManager & );

private:
	const XenDriver &driver_;
	xc_interface *xci_;
	domid_t domain_;
	bool stop_;
	xc_evtchn *xce_;
	int port_;
	xs_handle *xsh_;
	uint32_t evtchnPort_;
	mem_event_back_ring_t backRing_;
	void *ringPage_;
	std::string watchToken_;
	bool memAccessOn_;
	bool evtchnOn_;
	bool evtchnBindOn_;
	unsigned short handlerFlags_;
	bool guestStillRunning_;
	LogHelper *logHelper_;
};

} // namespace bdvmi

#endif // __BDVMIXENEVENTMANAGER_H_INCLUDED__
