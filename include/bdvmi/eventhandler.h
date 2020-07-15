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

#ifndef __BDVMIEVENTHANDLER_H_INCLUDED__
#define __BDVMIEVENTHANDLER_H_INCLUDED__

#include <stdint.h>

namespace bdvmi {

// Forward declaration
struct Registers;
struct EmulatorContext;

enum HVAction { NONE, EMULATE_NOWRITE, SKIP_INSTRUCTION, ALLOW_VIRTUAL, EMULATE_SET_CTXT };

enum GuestState { RUNNING, POST_SHUTDOWN, SHUTDOWN_IN_PROGRESS };

#define BDVMI_DESC_ACCESS_IDTR  0x01
#define BDVMI_DESC_ACCESS_GDTR  0x02
#define BDVMI_DESC_ACCESS_TR    0x04
#define BDVMI_DESC_ACCESS_LDTR  0x08
#define BDVMI_DESC_ACCESS_READ  0x10
#define BDVMI_DESC_ACCESS_WRITE 0x20

class EventHandler {

public:
	// Base class, so virtual destructor.
	virtual ~EventHandler() = default;

public:
	// Callback for CR{0,3,4} write events.
	virtual void handleCR( unsigned short vcpu, unsigned short crNumber, const bdvmi::Registers &regs,
	                       uint64_t oldValue, uint64_t newValue, HVAction &action ) = 0;

	// Callback for writes in MSR addresses.
	virtual void handleMSR( unsigned short vcpu, uint32_t msr, uint64_t oldValue, uint64_t newValue,
	                        HVAction &action ) = 0;

	// Callback for page faults.
	virtual void handlePageFault( unsigned short vcpu, const Registers &regs, uint64_t physAddress,
	                              uint64_t virtAddress, bool read, bool write, bool execute, bool inGpt,
	                              HVAction &action, EmulatorContext &emulatorCtx,
	                              unsigned short &instructionSize ) = 0;

	// Callback for VMCALL events.
	virtual void handleVMCALL( unsigned short vcpu, const Registers &regs ) = 0;

	virtual void handleXSETBV( unsigned short vcpu ) = 0;

	// Return false if you want to reinject
	virtual bool handleBreakpoint( unsigned short vcpu, const Registers &regs, uint64_t gpa ) = 0;

	virtual void handleInterrupt( unsigned short vcpu, const Registers &regs, uint32_t vector, uint64_t errorCode,
	                              uint64_t cr2 ) = 0;

	virtual void handleDescriptorAccess( unsigned short vcpu, const Registers &regs,
	                                     unsigned int flags, unsigned short &instructionLength,
					     HVAction &action ) = 0;

	// Notice that the connection to the guest has been terminated (if guestStillRunning is true
	// then this has _not_ happened because the guest shut down or has been forcefully terminated).
	virtual void handleSessionOver( GuestState state ) = 0;

	virtual void handleFatalError() = 0;

	// Useful for reloading configuration, checking state, etc.
	virtual void runPreEvent() = 0;

	virtual void runPostEvent() = 0;
};

} // namespace bdvmi

#endif // __BDVMIEVENTHANDLER_H_INCLUDED__
