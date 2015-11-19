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

#ifndef __BDVMIEVENTHANDLER_H_INCLUDED__
#define __BDVMIEVENTHANDLER_H_INCLUDED__

#include <stdint.h>

namespace bdvmi {

// Forward declaration
class Registers;

enum HVAction { NONE, EMULATE_NOWRITE, SKIP_INSTRUCTION, ALLOW_VIRTUAL, EMULATE_SET_CTXT };

class EventHandler {

public:
	// Base class, so virtual destructor.
	virtual ~EventHandler()
	{
	}

public:
	// Callback for CR{0,3,4} write events.
	virtual void handleCR( unsigned short vcpu, unsigned short crNumber, const bdvmi::Registers &regs,
	                       uint64_t oldValue, uint64_t newValue, HVAction &action ) = 0;

	// Callback for writes in MSR addresses.
	virtual void handleMSR( unsigned short vcpu, uint32_t msr, uint64_t oldValue, uint64_t newValue,
	                        HVAction &action ) = 0;

	// Callback for page faults.
	virtual void handlePageFault( unsigned short vcpu, const Registers &regs, uint64_t physAddress,
	                              uint64_t virtAddress, bool read, bool write, bool execute,
	                              HVAction &action, uint8_t *emulatorCtx, uint32_t &emuCtxSize,
	                              unsigned short &instructionSize ) = 0;

	// Callback for VMCALL events.
	virtual void handleVMCALL( unsigned short vcpu, const Registers &regs, uint64_t rip, uint64_t eax ) = 0;

	virtual void handleXSETBV( unsigned short vcpu, uint64_t xcr0 ) = 0;

	// Notice that the connection to the guest has been terminated (if guestStillRunning is true
	// then this has _not_ happened because the guest shut down or has been forcefully terminated).
	virtual void handleSessionOver( bool guestStillRunning ) = 0;

	// Useful for reloading configuration, checking state, etc.
	virtual void runPreEvent() = 0;
};

} // namespace bdvmi

#endif // __BDVMIEVENTHANDLER_H_INCLUDED__

