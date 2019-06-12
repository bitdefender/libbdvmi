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

#include <bdvmi/backendfactory.h>
#include <bdvmi/domainhandler.h>
#include <bdvmi/domainwatcher.h>
#include <bdvmi/driver.h>
#include <bdvmi/eventhandler.h>
#include <bdvmi/eventmanager.h>
#include <bdvmi/logger.h>
#include <iostream>
#include <memory>
#include <signal.h>
#include <sstream>

using namespace std;

namespace { // Anonymous namespace

sig_atomic_t stop;

void stop_handler( int /* signo */ )
{
	stop = 1;
}
}

class DemoEventHandler : public bdvmi::EventHandler {

public:
	// Callback for CR write events
	void handleCR( unsigned short /* vcpu */, unsigned short crNumber, const bdvmi::Registers & /* regs */,
	               uint64_t /* oldValue */, uint64_t         newValue, bdvmi::HVAction & /* hvAction */ ) override
	{
		cout << "CR" << crNumber << " event, newValue: 0x" << hex << newValue << endl;
	}

	// Callback for writes in MSR addresses
	void handleMSR( unsigned short /* vcpu */, uint32_t msr, uint64_t /* oldValue */, uint64_t newValue,
	                bdvmi::HVAction & /* hvAction */ ) override
	{
		cout << "MSR " << msr << " event, newValue: 0x" << hex << newValue << endl;
	}

	// Callback for page faults
	void handlePageFault( unsigned short vcpu, const bdvmi::Registers & /* regs */, uint64_t /* physAddress */,
	                      uint64_t /* virtAddress */, bool /* read */, bool /* write */, bool /* execute */,
	                      bool /* inGpt */, bdvmi::HVAction & /* action */, bdvmi::EmulatorContext & /* emulatorCtx */,
			      unsigned short & /* instructionLength */ ) override
	{
		cout << "Page fault event on VCPU: " << vcpu << endl;
	}

	void handleVMCALL( unsigned short vcpu, const bdvmi::Registers &regs ) override
	{
		cout << "VMCALL event on VCPU " << vcpu << ", EAX: 0x" << hex << regs.rax << endl;
	}

	void handleXSETBV( unsigned short vcpu ) override
	{
		cout << "XSETBV event on VCPU " << vcpu << endl;
	}

	// Reserved (currently not in use)
	bool handleBreakpoint( unsigned short vcpu, const bdvmi::Registers & /* regs */, uint64_t gpa ) override
	{
		cout << "INT3 (breakpoint) event on VCPU " << vcpu << ", gpa: " << hex << showbase << gpa << endl;

		// Did not do anything about the breakpoint, so reinject it.
		return false;
	}

	void handleInterrupt( unsigned short vcpu, const bdvmi::Registers & /* regs */, uint32_t /* vector */,
	                      uint64_t /* errorCode */, uint64_t /* cr2 */ ) override
	{
		cout << "Interrupt event on VCPU " << vcpu << endl;
	}

	void handleDescriptorAccess( unsigned short vcpu, const bdvmi::Registers & /* regs */, unsigned int /* flags */,
	                             unsigned short & /* instructionLength */, bdvmi::HVAction & /* action */ ) override
	{
		cout << "Descriptor access on VCPU " << vcpu << endl;
	}

	void handleSessionOver( bdvmi::GuestState /* state */ ) override
	{
		cout << "Session over." << endl;
	}

	// This callback will run before each event (helper)
	void runPreEvent() override
	{
		cout << "Prepare for event ..." << endl;
	}

	void handleFatalError() override
	{
		throw std::runtime_error( "A fatal error occurred, cannot continue" );
	}

	void runPostEvent() override
	{
		cout << "Event handled ..." << endl;
	}
};

class DemoDomainHandler : public bdvmi::DomainHandler {

public:
	DemoDomainHandler( bdvmi::BackendFactory &bf ) : bf_{ bf }
	{
	}

public:
	// Found a domain
	void handleDomainFound( const string &uuid, const string &name ) override
	{
		cout << "A new domain started running: " << name << ", UUID: " << uuid << endl;
		hookDomain( uuid );
	}

	// The domain is no longer running
	void handleDomainFinished( const string &uuid ) override
	{
		cout << "Domain finished: " << uuid << endl;
	}

	void cleanup( bool /* suspendIntrospectorDomain */ ) override
	{
		cout << "Done waiting for domains to start." << endl;
	}

private:
	void hookDomain( const string &uuid )
	{
		auto pd = bf_.driver( uuid, false );
		auto em = bf_.eventManager( *pd, stop );

		DemoEventHandler deh;

		em->handler( &deh );

		em->enableCrEvents( 0 );
		em->enableCrEvents( 3 );

		em->waitForEvents();
	}

private:
	bdvmi::BackendFactory &bf_;
};

int main()
{
	try {
		signal( SIGINT, stop_handler );
		signal( SIGHUP, stop_handler );
		signal( SIGTERM, stop_handler );

		bdvmi::logger.info( []( const std::string &s ) { cout << "[INFO] " << s << endl; } );
		bdvmi::logger.debug( []( const std::string &s ) { cout << "[DEBUG] " << s << endl; } );
		bdvmi::logger.warning( []( const std::string &s ) { cout << "[WARNING] " << s << endl; } );
		bdvmi::logger.error( []( const std::string &s ) { cerr << "[ERROR] " << s << "\n"; } );

		bdvmi::BackendFactory bf( bdvmi::BackendFactory::BACKEND_XEN );
		DemoDomainHandler     ddh( bf );

		auto pdw = bf.domainWatcher( stop );

		cout << "Registering handler ... " << endl;

		pdw->handler( &ddh );

		cout << "Waiting for domains ..." << endl;
		pdw->waitForDomains();

		cout << "\nDone." << endl;
	} catch ( const exception &e ) {
		cerr << "Error: caught exception: " << e.what() << endl;
		return -1;
	}

	return 0;
}
