// Copyright (c) 2015-2016 Bitdefender SRL, All rights reserved.
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
#include <bdvmi/eventhandler.h>
#include <bdvmi/eventmanager.h>
#include <bdvmi/loghelper.h>
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

class DemoLogHelper : public bdvmi::LogHelper {

public:
	DemoLogHelper( const string &domainName = "" )
	{
		if ( !domainName.empty() )
			prefix_ = string( "[" ) + domainName + "] ";
	}

public:
	virtual void error( const string &message )
	{
		cerr << prefix_ << "ERROR " << message << endl;
	}

	virtual void warning( const string &message )
	{
		cout << prefix_ << "WARNING " << message << endl;
	}

	virtual void info( const string &message )
	{
		cout << prefix_ << "INFO " << message << endl;
	}

	virtual void debug( const string &message )
	{
		cout << prefix_ << "DEBUG " << message << endl;
	}

private:
	string prefix_;
};

class DemoEventHandler : public bdvmi::EventHandler {

public:
	// Callback for CR write events
	virtual void handleCR( unsigned short /* vcpu */, unsigned short crNumber, const bdvmi::Registers & /* regs */,
	                       uint64_t /* oldValue */, uint64_t newValue, bdvmi::HVAction & /* hvAction */ )
	{
		cout << "CR" << crNumber << " event, newValue: 0x" << hex << newValue << endl;
	}

	// Callback for writes in MSR addresses
	virtual void handleMSR( unsigned short /* vcpu */, uint32_t msr, uint64_t /* oldValue */, uint64_t newValue,
	                        bdvmi::HVAction & /* hvAction */ )
	{
		cout << "MSR " << msr << " event, newValue: 0x" << hex << newValue << endl;
	}

	// Callback for page faults
	virtual void handlePageFault( unsigned short vcpu, const bdvmi::Registers & /* regs */,
	                              uint64_t /* physAddress */, uint64_t /* virtAddress */, bool /* read */,
	                              bool /* write */, bool /* execute */, bdvmi::HVAction & /* action */,
	                              uint8_t * /* data */, uint32_t & /* size */,
	                              unsigned short & /* instructionLength */ )
	{
		cout << "Page fault event on VCPU: " << vcpu << endl;
	}

	virtual void handleVMCALL( unsigned short vcpu, const bdvmi::Registers & /* regs */, uint64_t /* rip */,
	                           uint64_t eax )
	{
		cout << "VMCALL event on VCPU " << vcpu << ", EAX: 0x" << hex << eax << endl;
	}

	virtual void handleXSETBV( unsigned short vcpu, uint64_t ecx )
	{
		cout << "XSETBV event on VCPU " << vcpu << ", ECX: 0x" << hex << ecx << endl;
	}

	virtual void handleSessionOver( bool /* domainStillRunning */ )
	{
		cout << "Session over." << endl;
	}

	// This callback will run before each event (helper)
	virtual void runPreEvent()
	{
		cout << "Prepare for event ..." << endl;
	}
};

class DemoDomainHandler : public bdvmi::DomainHandler {

public:
	DemoDomainHandler( bdvmi::BackendFactory &bf ) : bf_( bf )
	{
	}

public:
	// A new domain appeared (it has just been started)
	virtual void handleNewDomain( const string &domain )
	{
		cout << "A new domain started running: " << domain << endl;
		hookDomain( domain );

	}

	// Found an already running domain
	virtual void handleRunningDomain( const string &domain )
	{
		cout << "Found already running domain: " << domain << endl;
		// Already running domains won't be hooked in this example.
	}

private:
	void hookDomain( const string &domain )
	{
		auto_ptr<bdvmi::Driver> pd( bf_.driver( domain ) );
		auto_ptr<bdvmi::EventManager> em( bf_.eventManager( *pd, bdvmi::EventManager::ENABLE_MSR |
		                                                         bdvmi::EventManager::ENABLE_XSETBV |
		                                                         bdvmi::EventManager::ENABLE_CR ) );

		DemoEventHandler deh;

		em->signalStopVar( &stop );

		em->handler( &deh );

		em->waitForEvents();
	}

private:
	bdvmi::BackendFactory &bf_;
};

int main()
{
	try
	{
		signal( SIGINT, stop_handler );
		signal( SIGHUP, stop_handler );
		signal( SIGTERM, stop_handler );

		DemoLogHelper logHelper;
		bdvmi::BackendFactory bf( bdvmi::BackendFactory::BACKEND_XEN, &logHelper );
		DemoDomainHandler ddh( bf );

		// Unique_ptr<T> would have been better, but the user's compiler might not
		// support C++0x.
		auto_ptr<bdvmi::DomainWatcher> pdw( bf.domainWatcher() );

		cout << "Registering handler ... " << endl;

		pdw->handler( &ddh );

		cout << "Setting up break-out-of-the-loop (stop) variable ..." << endl;
		pdw->signalStopVar( &stop );

		cout << "Waiting for domains ..." << endl;
		pdw->waitForDomains();

		cout << "\nDone." << endl;
	}
	catch ( const exception &e )
	{
		cerr << "Error: caught exception: " << e.what() << endl;
		return -1;
	}

	return 0;
}
