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

#define BDVMI_DISABLE_STATS

#include "kvmdriver.h"
#include "kvmeventmanager.h"
#include "bdvmi/eventhandler.h"
#include "bdvmi/logger.h"
#include "bdvmi/statscollector.h"
#include "utils.h"
#include <stdexcept>
#include <cstring>
#include <cerrno>
#include <iomanip>
#include <unistd.h>

namespace {

#define __case( x )                                                                                                    \
	case x:                                                                                                        \
		return #x;

const char *event_to_string( __u32 event )
{
	switch ( event ) {
		__case( KVMI_EVENT_CR );
		__case( KVMI_EVENT_MSR );
		__case( KVMI_EVENT_XSETBV );
		__case( KVMI_EVENT_BREAKPOINT );
		__case( KVMI_EVENT_HYPERCALL );
		__case( KVMI_EVENT_PF );
		__case( KVMI_EVENT_TRAP );
		__case( KVMI_EVENT_DESCRIPTOR );
		__case( KVMI_EVENT_CREATE_VCPU );
		__case( KVMI_EVENT_PAUSE_VCPU );
		__case( KVMI_EVENT_UNHOOK );
		__case( KVMI_EVENT_SINGLESTEP );
		default:
			return "UNKNOWN_EVENT";
	}
}

const char *action_to_string( __u32 action )
{
	switch ( action ) {
		__case( KVMI_EVENT_ACTION_CONTINUE );
		__case( KVMI_EVENT_ACTION_RETRY );
		__case( KVMI_EVENT_ACTION_CRASH );
		default:
			return "UNKNOWN_ACTION";
	}
}

const char *descriptor_to_string( __u8 descriptor )
{
	switch ( descriptor ) {
		__case( KVMI_DESC_IDTR );
		__case( KVMI_DESC_GDTR );
		__case( KVMI_DESC_LDTR );
		__case( KVMI_DESC_TR );
		default:
			return "UNKNOWN_DESC";
	}
}

} // namespace

namespace bdvmi {

bool KvmEventManager::initVMEvents()
{
	return driver_.registerVMEvent( KVMI_EVENT_CREATE_VCPU, true );
}

bool KvmEventManager::initVcpuEvents()
{
	// KVMI_EVENT_PAUSE_VCPU does not have to be enabled.

	driver_.setVcpuEventsLater( KVMI_EVENT_PF );
	driver_.setVcpuEventsLater( KVMI_EVENT_SINGLESTEP );

	if ( driver_.veSupported() )
		driver_.enablePendingVcpusCache();

	// XEN integration enables this event after an injection command (PF/BP)
	// and disables the event after sending it (right?).
	// We may not have this liberty in KVM (the admin could disallow almost any event).
	// Maybe we'll change this.
	return driver_.setVcpuEvents( KVMI_EVENT_TRAP );
}

KvmEventManager::KvmEventManager( KvmDriver &driver, sig_atomic_t &sigStop )
    : EventManager{ sigStop }
    , driver_{ driver }
{
	if ( !initVMEvents() )
		throw std::runtime_error( "[KVM events] could not init the VM events" );

	if ( !driver_.updateVcpuCount() )
		throw std::runtime_error( std::string( "[KVM events] could not get the cpu count: " ) +
		                          strerror( errno ) );

	if ( !initVcpuEvents() )
		throw std::runtime_error( "[KVM events] could not init the vcpu events" );
}

KvmEventManager::~KvmEventManager()
{
	if ( driver_.isConnected() && !driver_.suspending() )
		flushEventQueue();
}

bool KvmEventManager::enableMsrEventsImpl( unsigned int /* msr */ )
{
	return driver_.setVcpuEvents( KVMI_EVENT_MSR );
}

bool KvmEventManager::disableMsrEventsImpl( unsigned int /* msr */ )
{
	return true;
}

bool KvmEventManager::enableCrEventsImpl( unsigned int /* cr */ )
{
	return driver_.setVcpuEvents( KVMI_EVENT_CR );
}

bool KvmEventManager::disableCrEventsImpl( unsigned int /* cr */ )
{
	return true;
}

bool KvmEventManager::enableXSETBVEventsImpl()
{
	return driver_.setVcpuEvents( KVMI_EVENT_XSETBV );
}

bool KvmEventManager::disableXSETBVEventsImpl()
{
	return driver_.clearVcpuEvents( KVMI_EVENT_XSETBV );
}

bool KvmEventManager::enableBreakpointEventsImpl()
{
	return driver_.setVcpuEvents( KVMI_EVENT_BREAKPOINT );
}

bool KvmEventManager::disableBreakpointEventsImpl()
{
	return driver_.clearVcpuEvents( KVMI_EVENT_BREAKPOINT );
}

bool KvmEventManager::enableVMCALLEventsImpl()
{
	return driver_.setVcpuEvents( KVMI_EVENT_HYPERCALL );
}

bool KvmEventManager::disableVMCALLEventsImpl()
{
	return driver_.clearVcpuEvents( KVMI_EVENT_HYPERCALL );
}

bool KvmEventManager::enableDescriptorEventsImpl()
{
	return driver_.setVcpuEvents( KVMI_EVENT_DESCRIPTOR );
}

bool KvmEventManager::disableDescriptorEventsImpl()
{
	return driver_.clearVcpuEvents( KVMI_EVENT_DESCRIPTOR );
}

void KvmEventManager::traceEventMessage( const struct kvmi_dom_event &msg )
{
	if ( !logger.trace() )
		return;

	logger << TRACE << event_to_string( msg.event.common.event ) << ": vcpu " << msg.event.common.vcpu;

	switch ( msg.event.common.event ) {
		case KVMI_EVENT_CR:
			logger << " cr " << HEXLOG( msg.event.cr.cr ) << " old " << HEXLOG( msg.event.cr.old_value )
			       << " new " << HEXLOG( msg.event.cr.new_value );
			break;
		case KVMI_EVENT_MSR:
			logger << " msr " << HEXLOG( msg.event.msr.msr ) << " old " << HEXLOG( msg.event.msr.old_value )
			       << " new " << HEXLOG( msg.event.msr.new_value );
			break;
		case KVMI_EVENT_BREAKPOINT:
			logger << " gpa " << HEXLOG( msg.event.breakpoint.gpa ) << " rip "
			       << HEXLOG( msg.event.common.arch.regs.rip );
			break;
		case KVMI_EVENT_HYPERCALL:
			break;
		case KVMI_EVENT_PF: {
			bool        read    = !!( msg.event.page_fault.access & KVMI_PAGE_ACCESS_R );
			bool        write   = !!( msg.event.page_fault.access & KVMI_PAGE_ACCESS_W );
			bool        execute = !!( msg.event.page_fault.access & KVMI_PAGE_ACCESS_X );
			std::string access =
			    std::string( ( read ? "r" : "-" ) ) + ( write ? "w" : "-" ) + ( execute ? "x" : "-" );

			logger << " gpa " << HEXLOG( msg.event.page_fault.gpa ) << " gva "
			       << HEXLOG( msg.event.page_fault.gva ) << " access " << access.c_str() << " rip "
			       << HEXLOG( msg.event.common.arch.regs.rip );
			break;
		}
		case KVMI_EVENT_TRAP:
			logger << " vector " << HEXLOG( msg.event.trap.vector ) << " err_code "
			       << HEXLOG( msg.event.trap.error_code ) << " cr2 " << HEXLOG( msg.event.trap.cr2 );
			break;
		case KVMI_EVENT_DESCRIPTOR:
			logger << " descriptor " << descriptor_to_string( msg.event.desc.descriptor )
			       << ( msg.event.desc.write ? " write" : " read" ) << " rip "
			       << HEXLOG( msg.event.common.arch.regs.rip );
			break;
		case KVMI_EVENT_SINGLESTEP:
			break;
		default:
			break;
	}

	logger << std::flush;
}

void KvmEventManager::traceEventReply( const struct kvmi_dom_event &msg, const struct KvmDriver::EventReply &rpl )
{
	if ( !logger.trace() )
		return;

	logger << TRACE << event_to_string( msg.event.common.event ) << ": vcpu " << msg.event.common.vcpu << " "
	       << action_to_string( rpl.reply_.common_.action );

	switch ( msg.event.common.event ) {
		case KVMI_EVENT_CR:
			logger << " new " << HEXLOG( rpl.reply_.event_.cr.new_val );
			break;
		case KVMI_EVENT_MSR:
			logger << " new " << HEXLOG( rpl.reply_.event_.msr.new_val );
			break;
		case KVMI_EVENT_BREAKPOINT:
			logger << " rip " << HEXLOG( driver_.getNextRip() );
			break;
		case KVMI_EVENT_PF:
			logger << " rip " << HEXLOG( driver_.getNextRip() );
			if ( rpl.reply_.event_.pf.ctx_size ) {
				logger << " ctx_data:" << std::noshowbase;
				for ( size_t i = 0; i < rpl.reply_.event_.pf.ctx_size; i++ )
					logger << " " << std::setfill( '0' ) << std::setw( 2 ) << std::hex
					       << unsigned( rpl.reply_.event_.pf.ctx_data[i] );
			}
			logger << std::dec;
			break;
		case KVMI_EVENT_DESCRIPTOR:
			logger << " rip " << HEXLOG( driver_.getNextRip() );
			break;
		default:
			break;
	}

	logger << std::flush;
}

void KvmEventManager::waitForEvents()
{
	while ( !disconnected_ ) {
		HVAction  action = NONE;
		Registers regs;

		if ( sigStop_ )
			stop();

		kvmi_dom_event *           msg = nullptr;
		CUniquePtr<kvmi_dom_event> eventPtr;

		if ( !driver_.getEventMsg( msg, KVMI_WAIT, disconnected_ ) ) {
			if ( disconnected_ )
				stop();
			// The check is placed here to allow at least one event to be processed
			// when Introcore tries to unhook
			if ( stop_ )
				break;
			continue;
		}

		eventPtr.reset( msg );

		EventHandler *h = handler();

		if ( !h )
			throw std::runtime_error( "We don't know how to handle the missing handler" );

		StatsCounter counter( event_to_string( msg->event.common.event ) );

		traceEventMessage( *msg );

		// VM event (+ no reply)
		if ( msg->event.common.event == KVMI_EVENT_UNHOOK ) {
			logger << DEBUG << "Unhook signal from QEMU" << std::flush;
			driver_.suspending( true );
			stop();
			break;
		}

		if ( h )
			h->runPreEvent();

		driver_.beginEvent( regs, msg->event.common );

		struct KvmDriver::EventReply reply( msg );

		switch ( msg->event.common.event ) {
			case KVMI_EVENT_CR: {
				StatsCounter counter( "eventsCr" );
				h->handleCR( msg->event.common.vcpu, msg->event.cr.cr, regs, msg->event.cr.old_value,
				             msg->event.cr.new_value, action );

				if ( action == SKIP_INSTRUCTION || action == EMULATE_NOWRITE )
					reply.reply_.event_.cr.new_val = msg->event.cr.old_value;
				else
					reply.reply_.event_.cr.new_val = msg->event.cr.new_value;

				break;
			}
			case KVMI_EVENT_MSR: {
				StatsCounter counter( "eventsMsr" );
				h->handleMSR( msg->event.common.vcpu, msg->event.msr.msr, msg->event.msr.old_value,
				              msg->event.msr.new_value, action );

				if ( action == SKIP_INSTRUCTION || action == EMULATE_NOWRITE )
					reply.reply_.event_.msr.new_val = msg->event.msr.old_value;
				else
					reply.reply_.event_.msr.new_val = msg->event.msr.new_value;

				break;
			}
			case KVMI_EVENT_XSETBV: {
				StatsCounter counter( "eventsXsetbv" );
				h->handleXSETBV( msg->event.common.vcpu );

				break;
			}
			case KVMI_EVENT_BREAKPOINT: {
				bool handled;

				StatsCounter counter( "eventsBreakpoint" );
				handled =
				    h->handleBreakpoint( msg->event.common.vcpu, regs, msg->event.breakpoint.gpa );

				if ( handled )
					// the breakpoint has been handled by the introspector
					reply.reply_.common_.action = KVMI_EVENT_ACTION_RETRY;

				break;
			}
			case KVMI_EVENT_HYPERCALL: {
				StatsCounter counter( "eventsHypercall" );
				h->handleVMCALL( msg->event.common.vcpu, regs );

				break;
			}
			case KVMI_EVENT_PF: {
				bool            read, write, execute;
				unsigned short  instructionSize = 0;
				EmulatorContext emulatorCtx;

				if ( msg->event.page_fault.gva == ~0ull )
					msg->event.page_fault.gva = 0;

				// Xen's page fault handler carries this comment:
				//
				// Treat all write violations also as read violations.
				// The reason why this is required is the following warning:
				// "An EPT violation that occurs during as a result of execution of a
				// read-modify-write operation sets bit 1 (data write). Whether it also
				// sets bit 0 (data read) is implementation-specific and, for a given
				// implementation, may differ for different kinds of read-modify-write
				// operations."
				//  - Intel(R) 64 and IA-32 Architectures Software Developer's Manual
				//    Volume 3C: System Programming Guide, Part 3
				if ( msg->event.page_fault.access & KVMI_PAGE_ACCESS_W )
					msg->event.page_fault.access |= KVMI_PAGE_ACCESS_R;

				read    = !!( msg->event.page_fault.access & KVMI_PAGE_ACCESS_R );
				write   = !!( msg->event.page_fault.access & KVMI_PAGE_ACCESS_W );
				execute = !!( msg->event.page_fault.access & KVMI_PAGE_ACCESS_X );

				{
					StatsCounter counter( "eventsPf" );
					h->handlePageFault( msg->event.common.vcpu, regs, msg->event.page_fault.gpa,
					                    msg->event.page_fault.gva, read, write, execute, false,
					                    action, emulatorCtx, instructionSize );
				}

				switch ( action ) {
					case SKIP_INSTRUCTION:
						driver_.skipInstruction( instructionSize );
						reply.reply_.common_.action = KVMI_EVENT_ACTION_RETRY;
						break;
					case ALLOW_VIRTUAL:
						reply.reply_.common_.action = KVMI_EVENT_ACTION_RETRY;
						break;
					case EMULATE_SET_CTXT:
						memcpy( reply.reply_.event_.pf.ctx_data, emulatorCtx.data_,
						        std::min( ( std::size_t )emulatorCtx.size_,
						                  sizeof( reply.reply_.event_.pf.ctx_data ) ) );
						reply.reply_.event_.pf.ctx_addr = emulatorCtx.address_;
						reply.reply_.event_.pf.ctx_size = emulatorCtx.size_;
						break;
					default:
						break;
				}

				reply.reply_.event_.pf.rep_complete = driver_.getRepOptimizations();

				break;
			}
			case KVMI_EVENT_TRAP: {
				StatsCounter counter( "eventsTrap" );
				h->handleInterrupt( msg->event.common.vcpu, regs, msg->event.trap.vector,
				                    msg->event.trap.error_code, msg->event.trap.cr2 );

				break;
			}
			case KVMI_EVENT_DESCRIPTOR: {
				unsigned short instructionSize = 0;
				unsigned int   flags           = 0;

				switch ( msg->event.desc.descriptor ) {
					case KVMI_DESC_IDTR:
						flags |= BDVMI_DESC_ACCESS_IDTR;
						break;
					case KVMI_DESC_GDTR:
						flags |= BDVMI_DESC_ACCESS_GDTR;
						break;
					case KVMI_DESC_LDTR:
						flags |= BDVMI_DESC_ACCESS_LDTR;
						break;
					case KVMI_DESC_TR:
						flags |= BDVMI_DESC_ACCESS_TR;
						break;
				}

				flags |= ( msg->event.desc.write ? BDVMI_DESC_ACCESS_WRITE : BDVMI_DESC_ACCESS_READ );

				{
					StatsCounter counter( "eventsDtr" );
					h->handleDescriptorAccess( msg->event.common.vcpu, regs, flags, instructionSize,
					                           action );
				}

				switch ( action ) {
					case SKIP_INSTRUCTION:
						// fallthrough
					case EMULATE_NOWRITE:
						driver_.skipInstruction( instructionSize );
						// fallthrough
					case ALLOW_VIRTUAL:
						reply.reply_.common_.action = KVMI_EVENT_ACTION_RETRY;
						break;
					default:
						break;
				}

				break;
			}
			case KVMI_EVENT_CREATE_VCPU: {
				StatsCounter counter( "eventsCreateVcpu" );
				driver_.updateVcpuCount();
				driver_.waitForUnpause();
				break;
			}
			case KVMI_EVENT_PAUSE_VCPU: {
				StatsCounter counter( "eventsPauseVcpu" );
				driver_.pauseEventReceived();
				driver_.waitForUnpause();
				break;
			}
			case KVMI_EVENT_SINGLESTEP: {
				StatsCounter counter( "eventsSinglestep" );
				break;
			}
			default:
				logger << ERROR << "Unsupported event: 0x" << std::setfill( '0' ) << std::setw( 8 )
				       << std::hex << msg->event.common.event << std::flush;
				break;
		}

		// move this to batch
		driver_.flushCtrlEvents( msg->event.common.vcpu, enabledCrs_, enabledMsrs_ );

		if ( !driver_.replyEvent( reply ) )
			break;

		traceEventReply( *msg, reply );

		if ( h )
			h->runPostEvent();

		// The check is placed here to allow at least one event to be processed
		// when Introcore tries to unhook
		if ( stop_ )
			break;
	}
}

void KvmEventManager::stop()
{
	if ( stop_ )
		return;

	EventHandler *h = handler();

	if ( h ) {
		bool alive = driver_.isConnected();

		logger << DEBUG << "Signal session over with guest status: " << ( alive ? "connected" : "disconnected" )
		       << std::flush;

		h->handleSessionOver( alive ? RUNNING : POST_SHUTDOWN );
	}

	stop_ = true;
}

std::string KvmEventManager::uuid()
{
	return driver_.uuid();
}

void KvmEventManager::flushEventQueue()
{
	int       ms = KVMI_WAIT;
	Registers regs;

	driver_.registerVMEvent( KVMI_EVENT_CREATE_VCPU, false );

	driver_.clearVcpuEvents();

	logger << DEBUG << "Events to wait for " << driver_.pendingPauseEvents() << std::flush;

	if ( !driver_.pendingPauseEvents() )
		ms = KVMI_NOWAIT;

	for ( ;; ) {
		struct kvmi_dom_event *                msg = nullptr;
		std::unique_ptr<struct kvmi_dom_event> eventPtr;

		try {
			if ( !driver_.getEventMsg( msg, ms, disconnected_ ) ) {
				if ( disconnected_ )
					break;
				if ( !driver_.pendingPauseEvents() )
					break;
				continue;
			}
		} catch ( ... ) {
			break;
		}

		eventPtr.reset( msg );

		// VM event (+ no reply)
		if ( msg->event.common.event == KVMI_EVENT_UNHOOK ) {
			logger << DEBUG << "Unhook signal from QEMU. We're closing the socket right now." << std::flush;
			driver_.suspending( true );
			continue;
		}

		driver_.beginEvent( regs, msg->event.common );

		struct KvmDriver::EventReply reply( msg );

		traceEventMessage( *msg );

		switch ( msg->event.common.event ) {
			case KVMI_EVENT_CR:
				reply.reply_.event_.cr.new_val = msg->event.cr.new_value;
				break;
			case KVMI_EVENT_MSR:
				reply.reply_.event_.msr.new_val = msg->event.msr.new_value;
				break;
			case KVMI_EVENT_PAUSE_VCPU:
				driver_.pauseEventReceived();

				logger << DEBUG << "Events to wait for " << driver_.pendingPauseEvents() << std::flush;
				// If there are no more pending pause events then leave the
				// method as soon as possible. We don't just return from
				// it and instead call getEventMsg() just one more time
				// in case there's something left in the libkvmi queue
				if ( !driver_.pendingPauseEvents() )
					ms = KVMI_NOWAIT;
				break;
			case KVMI_EVENT_PF:
				driver_.setPageProtection( msg->event.page_fault.gpa, true, true, true );
				break;
			case KVMI_EVENT_XSETBV:
			// fallthrough
			case KVMI_EVENT_BREAKPOINT:
			// fallthrough
			case KVMI_EVENT_HYPERCALL:
			// fallthrough
			case KVMI_EVENT_TRAP:
			// fallthrough
			case KVMI_EVENT_DESCRIPTOR:
			// fallthrough
			case KVMI_EVENT_CREATE_VCPU:
			// fallthrough
			case KVMI_EVENT_SINGLESTEP:
				break;
			default:
				logger << ERROR << "Unsupported event " << std::hex << msg->event.common.event
				       << std::flush;
				break;
		}

		driver_.flushCtrlEvents( msg->event.common.vcpu, enabledCrs_, enabledMsrs_ );

		if ( !driver_.replyEvent( reply ) )
			break;

		traceEventReply( *msg, reply );
	}
}

} // namespace bdvmi
