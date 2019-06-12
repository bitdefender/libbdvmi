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

#include "bdvmi/statscollector.h"
#include "xendriver.h"
#include "xeneventmanager.h"
#include "xenvmevent_v3.h"
#include "xenvmevent_v4.h"
#include "xenvmevent_v5.h"
#include "bdvmi/logger.h"
#include <sys/mman.h>
#include <poll.h>
#include <errno.h>
#include <cstring>
#include <cstdlib>
#include <iomanip>
#include <stdexcept>

#define GLA_VALID( x ) ( x.u.mem_access.flags & MEM_ACCESS_GLA_VALID )
#define ACCESS_R( x ) ( x.u.mem_access.flags & MEM_ACCESS_R )
#define ACCESS_W( x ) ( x.u.mem_access.flags & MEM_ACCESS_W )
#define ACCESS_X( x ) ( x.u.mem_access.flags & MEM_ACCESS_X )

#ifndef HVMOP_TRAP_sw_exc
#define HVMOP_TRAP_sw_exc 6
#endif

/* From xen/include/asm-x86/x86-defns.h */
#define X86_CR4_PGE 0x00000080 /* enable global pages */
#define X86_TRAP_INT3 3

namespace bdvmi {

XenEventManager::XenEventManager( XenDriver &driver, sig_atomic_t &sigStop )
    : EventManager{ sigStop }, driver_{ driver }, xc_{ driver_.nativeHandle() },
      domain_{ static_cast<domid_t>( driver.id() ) }
{
	initXenStore();

#ifndef DISABLE_MEM_EVENT
	/*
	if ( xc_.monitorSinglestep( domain_, 1 ) < 0 ) {
	        cleanup();
	        throw std::runtime_error( "[ALTP2M] could not enable singlestep monitoring" );
	}
	*/

	initMemAccess();

#endif // DISABLE_MEM_EVENT

	logger << INFO << "Running on Xen " << xc_.version << std::flush;

#ifdef DEBUG_DUMP_EVENTS
	std::string eventsFile = "/tmp/" + driver.uuid() + ".events";
	eventsFile_.open( eventsFile.c_str(), std::ios_base::out | std::ios_base::trunc );
#endif
}

XenEventManager::~XenEventManager()
{
	handler( nullptr );
	stop();

	disableVMCALLEvents();
	disableBreakpointEvents();

	// cleanup events
	try {
		constexpr int CLEANUP_TRIES = 10;

		// Loop until no more events are found in CLEANUP_TRIES ...
		do {
			foundEvents_ = false;

			for ( int i = 0; i < CLEANUP_TRIES; ++i )
				waitForEvents();

		} while ( foundEvents_ );

		// ... then one more batch just for safety.
		for ( int i = 0; i < CLEANUP_TRIES; ++i )
			waitForEvents();
	} catch ( const std::exception &e ) {
		logger << WARNING << e.what() << std::flush;
	} catch ( ... ) {
		// std::runtime_errors not allowed to escape destructors
	}

	cleanup();
}

void XenEventManager::cleanup()
{
#ifndef DISABLE_MEM_EVENT
	/*
	unsigned int cpus = 0;
	driver_.cpuCount( cpus );

	for ( unsigned int vcpu = 0; vcpu < cpus; ++vcpu )
	        xc_.domainDebugControl( domain_, vcpu, XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_OFF );
	*/

	/* Tear down domain xenaccess in Xen */
	if ( ringPage_ )
		munmap( ringPage_, XC::pageSize );

	if ( memAccessOn_ )
		xc_.monitorDisable( domain_ );

	// Unbind VIRQ
	if ( evtchnBindOn_ )
		xc_.evtchnUnbind( xce_, port_ );

	if ( evtchnOn_ )
		xc_.evtchnClose( xce_ );
#endif // DISABLE_MEM_EVENT

	xs_.unwatch( "@releaseDomain", watchToken_ );
	xs_.unwatch( watchToken_, watchToken_ );
	xs_.unwatch( controlXenStorePath_, watchToken_ );
	xs_.rm( XS::xbtNull, controlXenStorePath_ );

	switch ( vmEventInterfaceVersion_ ) {
	case 5:
		delete static_cast<vm_event_v5_back_ring_t *>( backRing_ );
		break;
	case 4:
		delete static_cast<vm_event_v4_back_ring_t *>( backRing_ );
		break;
	default:
		delete static_cast<vm_event_v3_back_ring_t *>( backRing_ );
	}
}

bool XenEventManager::enableMsrEventsImpl( unsigned int msr )
{
	return ( xc_.monitorMovToMsr( domain_, msr, 1, true ) == 0 );
}

bool XenEventManager::disableMsrEventsImpl( unsigned int msr )
{
	return ( xc_.monitorMovToMsr( domain_, msr, 0, true ) == 0 );
}

bool XenEventManager::setCrEvents( unsigned int cr, bool enable )
{
	uint16_t index;
	bool     retval;
	uint64_t bitmask = 0;

	switch ( cr ) {
		case 0:
			index = VM_EVENT_X86_CR0;
			break;
		case 4:
			index   = VM_EVENT_X86_CR4;
			bitmask = X86_CR4_PGE;
			break;
		case 3:
			index = VM_EVENT_X86_CR3;
			break;
		default:
			return false; // Unsupported CR index
	}

	retval = xc_.monitorWriteCtrlreg( domain_, index, enable, 1, bitmask, 1 );

	if ( retval ) {
		logger << ERROR << "[Xen events] could not set up CR" << cr << " event handler" << std::flush;
		return false;
	}

	return true;
}

bool XenEventManager::enableCrEventsImpl( unsigned int cr )
{
	return setCrEvents( cr, true );
}

bool XenEventManager::disableCrEventsImpl( unsigned int cr )
{
	return setCrEvents( cr, false );
}

bool XenEventManager::enableXSETBVEventsImpl()
{
	return ( xc_.monitorWriteCtrlreg( domain_, VM_EVENT_X86_XCR0, 1, 1, 0, 1 ) == 0 );
}

bool XenEventManager::disableXSETBVEventsImpl()
{
	return ( xc_.monitorWriteCtrlreg( domain_, VM_EVENT_X86_XCR0, 0, 1, 0, 1 ) == 0 );
}

bool XenEventManager::enableBreakpointEventsImpl()
{
	return ( xc_.monitorSoftwareBreakpoint( domain_, 1 ) == 0 );
}

bool XenEventManager::disableBreakpointEventsImpl()
{
	return ( xc_.monitorSoftwareBreakpoint( domain_, 0 ) == 0 );
}

bool XenEventManager::enableVMCALLEventsImpl()
{
	return ( xc_.monitorGuestRequest( domain_, true, true, true ) == 0 );
}

bool XenEventManager::disableVMCALLEventsImpl()
{
	return ( xc_.monitorGuestRequest( domain_, false, true, true ) == 0 );
}

bool XenEventManager::enableDescriptorEventsImpl()
{
	if ( !driver_.dtrEventsSupported() ) {
		logger << WARNING << "Descriptor access events support not available!" << std::flush;
		return false;
	}

	return ( xc_.monitorDescriptorAccess( domain_, true ) == 0 );
}

bool XenEventManager::disableDescriptorEventsImpl()
{
	if ( !driver_.dtrEventsSupported() ) {
		logger << WARNING << "Descriptor access events support not available!" << std::flush;
		return false;
	}

	return ( xc_.monitorDescriptorAccess( domain_, false ) == 0 );
}

void copySegmentRegisters( Registers &regs, const vm_event_request_v3_t &req )
{
	regs.cs_arbytes = req.data.regs.x86.cs_arbytes;
}

void copySegmentRegisters( Registers &regs, const vm_event_request_v4_t &req )
{
	regs.cs_arbytes = req.data.regs.x86.cs.ar;
}

void copySegmentRegisters( Registers &regs, const vm_event_request_v5_t &req )
{
	regs.cs_arbytes = req.data.regs.x86.cs.ar;
}

template <typename Request> inline void copyRegisters( Registers &regs, const Request &req )
{
	regs.sysenter_cs  = req.data.regs.x86.sysenter_cs;
	regs.sysenter_esp = req.data.regs.x86.sysenter_esp;
	regs.sysenter_eip = req.data.regs.x86.sysenter_eip;
	regs.msr_efer     = req.data.regs.x86.msr_efer;
	regs.msr_star     = req.data.regs.x86.msr_star;
	regs.msr_lstar    = req.data.regs.x86.msr_lstar;
	regs.fs_base      = req.data.regs.x86.fs_base;
	regs.gs_base      = req.data.regs.x86.gs_base;
	/*
	regs.idtr_base    = req.data.regs.x86.idtr_base;
	regs.idtr_limit   = req.data.regs.x86.idtr_limit;
	regs.gdtr_base    = req.data.regs.x86.gdtr_base;
	regs.gdtr_limit   = req.data.regs.x86.gdtr_limit;
	*/
	regs.rflags = req.data.regs.x86.rflags;
	regs.rax    = req.data.regs.x86.rax;
	regs.rcx    = req.data.regs.x86.rcx;
	regs.rdx    = req.data.regs.x86.rdx;
	regs.rbx    = req.data.regs.x86.rbx;
	regs.rsp    = req.data.regs.x86.rsp;
	regs.rbp    = req.data.regs.x86.rbp;
	regs.rsi    = req.data.regs.x86.rsi;
	regs.rdi    = req.data.regs.x86.rdi;
	regs.r8     = req.data.regs.x86.r8;
	regs.r9     = req.data.regs.x86.r9;
	regs.r10    = req.data.regs.x86.r10;
	regs.r11    = req.data.regs.x86.r11;
	regs.r12    = req.data.regs.x86.r12;
	regs.r13    = req.data.regs.x86.r13;
	regs.r14    = req.data.regs.x86.r14;
	regs.r15    = req.data.regs.x86.r15;
	regs.rip    = req.data.regs.x86.rip;
	regs.cr0    = req.data.regs.x86.cr0;
	regs.cr2    = req.data.regs.x86.cr2;
	regs.cr3    = req.data.regs.x86.cr3;
	regs.cr4    = req.data.regs.x86.cr4;

	copySegmentRegisters( regs, req );

	int32_t x86Mode = XenDriver::guestX86Mode( regs );

	switch ( x86Mode ) {
		case 2:
			regs.guest_x86_mode = Registers::CS_TYPE_16;
			break;
		case 4:
			regs.guest_x86_mode = Registers::CS_TYPE_32;
			break;
		case 8:
			regs.guest_x86_mode = Registers::CS_TYPE_64;
			break;
		default:
			regs.guest_x86_mode = Registers::ERROR;
			break;
	}
}

template <typename Response> void XenEventManager::setRegisters( Response &rsp )
{
	XenDriver::DelayedWrite &dw = driver_.delayedWrite();

	if ( !dw.pending_ )
		return;

	rsp.data.regs.x86.rflags = dw.registers_.rflags;
	rsp.data.regs.x86.rax    = dw.registers_.rax;
	rsp.data.regs.x86.rcx    = dw.registers_.rcx;
	rsp.data.regs.x86.rdx    = dw.registers_.rdx;
	rsp.data.regs.x86.rbx    = dw.registers_.rbx;
	rsp.data.regs.x86.rsp    = dw.registers_.rsp;
	rsp.data.regs.x86.rbp    = dw.registers_.rbp;
	rsp.data.regs.x86.rsi    = dw.registers_.rsi;
	rsp.data.regs.x86.rdi    = dw.registers_.rdi;
	rsp.data.regs.x86.r8     = dw.registers_.r8;
	rsp.data.regs.x86.r9     = dw.registers_.r9;
	rsp.data.regs.x86.r10    = dw.registers_.r10;
	rsp.data.regs.x86.r11    = dw.registers_.r11;
	rsp.data.regs.x86.r12    = dw.registers_.r12;
	rsp.data.regs.x86.r13    = dw.registers_.r13;
	rsp.data.regs.x86.r14    = dw.registers_.r14;
	rsp.data.regs.x86.r15    = dw.registers_.r15;

	rsp.data.regs.x86.rip = dw.registers_.rip;

	if ( xc_.version != Version( 4, 6 ) || xc_.isXenServer )
		rsp.flags |= VM_EVENT_FLAG_SET_REGISTERS;
	else
		logger << WARNING << "VM_EVENT_FLAG_SET_REGISTERS is not available, try a newer Xen!" << std::flush;

	dw.pending_ = false;
}

void XenEventManager::waitForEvents()
{
	switch ( vmEventInterfaceVersion_ ) {
	case 5:
		return waitForEventsByVMEventVersion<vm_event_request_v5_t, vm_event_response_v5_t,
		                                     vm_event_v5_back_ring_t>();
	case 4:
		return waitForEventsByVMEventVersion<vm_event_request_v4_t, vm_event_response_v4_t,
		                                     vm_event_v4_back_ring_t>();
	default:
		return waitForEventsByVMEventVersion<vm_event_request_v3_t, vm_event_response_v3_t, vm_event_v3_back_ring_t>();
	}
}

template <typename Request, typename Response, typename Ring> void XenEventManager::waitForEventsByVMEventVersion()
{
	EventHandler *h            = handler();
	bool          shuttingDown = false;

	for ( ;; ) {
		waitForEventOrTimeout( 100 );

		if ( sigStop_ )
			stop();

		if ( stop_ )
			shuttingDown = true;

#ifndef DISABLE_MEM_EVENT
		Request  req;
		Response rsp;

		int events = 0;

		while ( RING_HAS_UNCONSUMED_REQUESTS( static_cast<Ring *>( backRing_ ) ) ) {
			getRequest<Request, Ring>( req );

#ifdef DEBUG_DUMP_EVENTS
			eventsFile_.write( ( const char * )&req, sizeof( req ) );
#endif
			++events;
			foundEvents_ = true;

			StatsCounter counter( "eventCount" );

			memset( &rsp, 0, sizeof( rsp ) );

			rsp.vcpu_id       = req.vcpu_id;
			rsp.flags         = req.flags & ~VM_EVENT_FLAG_ALTERNATE_P2M;
			rsp.reason        = req.reason;
			rsp.altp2m_idx    = req.altp2m_idx;
			rsp.data.regs.x86 = req.data.regs.x86;

			rsp.version            = req.version;
			rsp.u.mem_access.flags = req.u.mem_access.flags;

			driver_.enableCache( req.vcpu_id );

			if ( h )
				h->runPreEvent();

			bool skip = false;

			switch ( req.reason ) {
				case VM_EVENT_REASON_MEM_ACCESS:
					handleMemAccess( req, rsp, skip );
					break;

				case VM_EVENT_REASON_SINGLESTEP: {
					StatsCounter counter2( "eventsSingleStep" );

					rsp.reason = req.reason;
					rsp.flags |= VM_EVENT_FLAG_ALTERNATE_P2M | VM_EVENT_FLAG_TOGGLE_SINGLESTEP;
					rsp.altp2m_idx = driver_.eptpIndex();

					break;
				}

				case VM_EVENT_REASON_WRITE_CTRLREG:
					handleCrWrite( req, rsp );
					break;

				case VM_EVENT_REASON_MOV_TO_MSR:
					handleMsrWrite( req, rsp );
					break;

				case VM_EVENT_REASON_GUEST_REQUEST: {
					StatsCounter counter2( "eventsGuestRequest" );

					if ( h ) {
						Registers regs;
						copyRegisters( regs, req );

						h->handleVMCALL( req.vcpu_id, regs );
					}

					break;
				}

				case VM_EVENT_REASON_SOFTWARE_BREAKPOINT:
					handleBreakpoint( req );
					break;

				case VM_EVENT_REASON_INTERRUPT:
					if ( h ) {
						Registers regs;
						copyRegisters( regs, req );

						h->handleInterrupt( req.vcpu_id, regs, req.u.interrupt.x86.vector,
						                    req.u.interrupt.x86.error_code,
						                    req.u.interrupt.x86.cr2 );
					}

					break;

				case VM_EVENT_REASON_DESCRIPTOR_ACCESS:
					handleDescriptorWrite( req, rsp, skip );
					break;

				default:
					// unknown reason code
					break;
			}

			if ( driver_.pendingInjection( req.vcpu_id ) ) {
				if ( xc_.version >= Version( 4, 9 ) || xc_.isXenServer )
					rsp.flags |= VM_EVENT_FLAG_GET_NEXT_INTERRUPT;
				else
					logger << WARNING
					       << "VM_EVENT_FLAG_GET_NEXT_INTERRUPT is not available, try a newer Xen!"
					       << std::flush;
				driver_.clearInjection( req.vcpu_id );
			}

			if ( !skip )
				setRegisters( rsp );

			driver_.flushPageProtections();

			if ( h )
				h->runPostEvent();

			driver_.disableCache();

			/* Put the page info on the ring */
			putResponse<Response, Ring>( rsp );
			resumePage();
		}

// if ( events )
//	resumePage();
#endif // DISABLE_MEM_EVENT

		if ( shuttingDown )
			return;
	}
}

template <typename Request, typename Response>
void XenEventManager::handleMemAccess( const Request &req, Response &rsp, bool &skip )
{
	uint64_t        gva             = 0;
	const bool      read            = ( ACCESS_R( req ) != 0 );
	const bool      write           = ( ACCESS_W( req ) != 0 );
	const bool      execute         = ( ACCESS_X( req ) != 0 );
	const bool      gptFault        = req.u.mem_access.flags & MEM_ACCESS_FAULT_IN_GPT;
	HVAction        action          = NONE;
	unsigned short  instructionSize = 0;
	EventHandler *  h               = handler();
	Registers       regs;
	EmulatorContext emulatorCtx;

	StatsCounter counter( "eventsMemAccess" );

	rsp.flags |= VM_EVENT_FLAG_EMULATE;
	rsp.u.mem_access.gfn = req.u.mem_access.gfn;

	if ( !h )
		return;

	copyRegisters( regs, req );

	if ( GLA_VALID( req ) )
		gva = req.u.mem_access.gla;

	uint64_t gpa = ( req.u.mem_access.gfn << XC::pageShift ) + req.u.mem_access.offset;

	h->handlePageFault( req.vcpu_id, regs, gpa, gva, read, write, execute, gptFault, action,
	                    emulatorCtx, instructionSize );

	switch ( action ) {
		case EMULATE_NOWRITE:
		case SKIP_INSTRUCTION:
			if ( xc_.version != Version( 4, 6 ) || xc_.isXenServer ) {
				skip                  = true;
				rsp.data.regs.x86.rip = req.data.regs.x86.rip + instructionSize;
				rsp.flags |= VM_EVENT_FLAG_SET_REGISTERS;
				rsp.flags &= ~VM_EVENT_FLAG_EMULATE;
			} else
				rsp.flags |= VM_EVENT_FLAG_EMULATE_NOWRITE;
			break;

		case ALLOW_VIRTUAL:
			// go on, but don't emulate (monitoring application changed EIP)
			rsp.flags &= ~VM_EVENT_FLAG_EMULATE;
			break;

		case EMULATE_SET_CTXT:
			memcpy( rsp.data.emul.read.data, emulatorCtx.data_,
			        std::min( ( std::size_t )emulatorCtx.size_, sizeof( rsp.data.emul.read.data ) ) );
			rsp.data.emul.read.size = emulatorCtx.size_;
			rsp.flags |= VM_EVENT_FLAG_SET_EMUL_READ_DATA;
			break;

		case NONE:
		default:
			/*
			if ( useAltP2m_ && // ( execute || gptFault ) &&
			     req.flags & VM_EVENT_FLAG_ALTERNATE_P2M ) {
			        rsp.flags = req.flags |
			                    VM_EVENT_FLAG_TOGGLE_SINGLESTEP;
			        rsp.flags &= ~VM_EVENT_FLAG_EMULATE;
			        rsp.altp2m_idx = 0;
			}
			*/
			break;
	}
}

template <typename Request, typename Response> void XenEventManager::handleCrWrite( const Request &req, Response &rsp )
{
	Registers      regs;
	unsigned short crNumber = 3;
	EventHandler * h        = handler();

	StatsCounter counter( "eventsWriteCtrlReg" );

	rsp.u.write_ctrlreg.index = req.u.write_ctrlreg.index;

	if ( !h )
		return;

	if ( req.u.write_ctrlreg.index == VM_EVENT_X86_XCR0 ) {
		h->handleXSETBV( req.vcpu_id );
		return;
	}

	switch ( req.u.write_ctrlreg.index ) {
		case VM_EVENT_X86_CR0:
			crNumber = 0;
			break;
		case VM_EVENT_X86_CR4:
			crNumber = 4;
			break;
		case VM_EVENT_X86_CR3:
		default:
			crNumber = 3;
			break;
	}

	copyRegisters( regs, req );

	HVAction action = NONE;

	h->handleCR( req.vcpu_id, crNumber, regs, req.u.write_ctrlreg.old_value, req.u.write_ctrlreg.new_value,
	             action );

	if ( action == SKIP_INSTRUCTION || action == EMULATE_NOWRITE )
		rsp.flags |= VM_EVENT_FLAG_DENY;
}

template <typename Request, typename Response> void XenEventManager::handleMsrWrite( const Request &req, Response &rsp )
{
	EventHandler *h = handler();

	StatsCounter counter( "eventsMovToMsr" );

	if ( !h )
		return;

	HVAction action = NONE;

	uint64_t oldValue;
	if ( req.version > 0x00000002 )
		oldValue = req.u.mov_to_msr.old_value;
	else {
		auto i = msrOldValueCache_.find( req.vcpu_id );
		if ( i == msrOldValueCache_.end() ) // not found
			oldValue = getMsr( req.vcpu_id, req.u.mov_to_msr.msr );
		else {
			auto j = i->second.find( req.u.mov_to_msr.msr );

			if ( j == i->second.end() ) // not found
				oldValue = getMsr( req.vcpu_id, req.u.mov_to_msr.msr );
			else
				oldValue = j->second;
		}
	}

	h->handleMSR( req.vcpu_id, req.u.mov_to_msr.msr, oldValue, req.u.mov_to_msr.new_value, action );

	if ( action == SKIP_INSTRUCTION || action == EMULATE_NOWRITE )
		rsp.flags |= VM_EVENT_FLAG_DENY;
	else if ( req.version <= 0x00000002 )
		msrOldValueCache_[req.vcpu_id][req.u.mov_to_msr.msr] = req.u.mov_to_msr.new_value;
}

template <typename Request, typename Response>
void XenEventManager::handleDescriptorWrite( const Request &req, Response &rsp, bool &skip )
{
	EventHandler *h = handler();

	StatsCounter counter( "eventsDtr" );

	if ( !h )
		return;

	HVAction  action = NONE;
	Registers regs;
	copyRegisters( regs, req );

	unsigned int flags = 0;

	switch ( req.u.desc_access.descriptor ) {
		case VM_EVENT_DESC_IDTR:
			flags |= BDVMI_DESC_ACCESS_IDTR;
			break;
		case VM_EVENT_DESC_GDTR:
			flags |= BDVMI_DESC_ACCESS_GDTR;
			break;
		case VM_EVENT_DESC_LDTR:
			flags |= BDVMI_DESC_ACCESS_LDTR;
			break;
		case VM_EVENT_DESC_TR:
			flags |= BDVMI_DESC_ACCESS_TR;
			break;
	}

	flags |= ( req.u.desc_access.is_write ? BDVMI_DESC_ACCESS_WRITE : BDVMI_DESC_ACCESS_READ );

	unsigned short instructionSize = 0;

	h->handleDescriptorAccess( req.vcpu_id, regs, flags, instructionSize, action );

	if ( action == SKIP_INSTRUCTION || action == EMULATE_NOWRITE ) {
		if ( xc_.version != Version( 4, 6 ) || xc_.isXenServer ) {
			skip                  = true;
			rsp.data.regs.x86.rip = req.data.regs.x86.rip + instructionSize;
			rsp.flags |= VM_EVENT_FLAG_SET_REGISTERS;
		} else
			logger << ERROR << "No instruction skip support!" << std::flush;
	} else if ( action != ALLOW_VIRTUAL ) // Do _nothing_ on ALLOW_VIRTUAL
		rsp.flags |= VM_EVENT_FLAG_EMULATE;
}

template <typename Request> void XenEventManager::handleBreakpoint( const Request &req )
{
	EventHandler *h        = handler();
	bool          reinject = ( h != nullptr );
	uint32_t      insn_len = ( req.version < 0x00000002 ? 1 : req.u.software_breakpoint.insn_length );
	uint8_t type = ( req.version < 0x00000002 ? HVMOP_TRAP_sw_exc : req.u.software_breakpoint.type );

	StatsCounter counter( "eventsBreakPoint" );

	if ( h ) {
		Registers regs;
		copyRegisters( regs, req );

		reinject = !h->handleBreakpoint( req.vcpu_id, regs, gfn_to_gpa( req.u.software_breakpoint.gfn ) );
	}

	if ( reinject && xc_.hvmInjectTrap( domain_, req.vcpu_id, X86_TRAP_INT3, type, ~0u, insn_len, 0 ) < 0 )
		logger << ERROR << "Could not reinject breakpoint" << std::flush;
}

void XenEventManager::stop()
{
	if ( stop_ ) // It's already been called
		return;

	EventHandler *h = handler();

	if ( h )
		h->handleSessionOver( guestState_ );

	stop_ = true;

#ifndef DISABLE_MEM_EVENT
	disableXSETBVEvents();
	disableCrEvents( 0 );
	disableCrEvents( 3 );
	disableCrEvents( 4 );
#endif // DISABLE_MEM_EVENT
}

void XenEventManager::initXenStore()
{
	watchToken_          = "/local/domain/0/device-model/" + std::to_string( domain_ );
	controlXenStorePath_ = "/local/domain/" + std::to_string( domain_ ) + "/vm-data/introspection-control";

	const std::string value = "started";

	if ( !xs_.write( XS::xbtNull, controlXenStorePath_, value.c_str(), value.length() ) )
		logger << ERROR << "Could not write XenStore key " << controlXenStorePath_ << std::flush;

	if ( !xs_.watch( "@releaseDomain", watchToken_ ) || !xs_.watch( watchToken_, watchToken_ ) ||
	     !xs_.watch( controlXenStorePath_, watchToken_ ) )
		throw std::runtime_error( "[Xen events] xs_watch() failed" );
}

#define INIT_EVENT_CHANNEL( VERSION )                                                                                  \
	{                                                                                                              \
		backRing_ = new vm_event_v##VERSION##_back_ring_t;                                                     \
		SHARED_RING_INIT( ( vm_event_v##VERSION##_sring_t * )ringPage_ );                                      \
		BACK_RING_INIT( ( vm_event_v##VERSION##_back_ring_t * )backRing_,                                      \
		                ( vm_event_v##VERSION##_sring_t * )ringPage_, XC::pageSize );                          \
	}

void XenEventManager::initEventChannels()
{
	/* Open event channel */
	xce_ = xc_.evtchnOpen();

	if ( !xce_ ) {
		cleanup();
		throw std::runtime_error( "[Xen events] failed to open event channel (modprobe xen_evtchn?)" );
	}

	evtchnOn_ = true;

	/* Bind event notification */
	port_ = xc_.evtchnBindInterdomain( xce_, domain_, evtchnPort_ );

	if ( port_ < 0 ) {
		cleanup();
		throw std::runtime_error( "[Xen events] failed to bind event channel" );
	}

	evtchnBindOn_ = true;

	vmEventInterfaceVersion_ = xc_.vmEventGetVersion();

	logger << DEBUG << "VM_EVENT_INTERFACE_VERSION: 0x" << std::hex << std::setfill( '0' ) << std::setw( 8 )
	       << vmEventInterfaceVersion_ << std::flush;

#define private rprivate
	switch ( vmEventInterfaceVersion_ ) {
	case 5:
		INIT_EVENT_CHANNEL( 5 );
		break;
	case 4:
		INIT_EVENT_CHANNEL( 4 );
		break;
	default:
		INIT_EVENT_CHANNEL( 3 );
		break;
	}
#undef private
}

void XenEventManager::initMemAccess()
{
	ringPage_ = xc_.monitorEnable( domain_, &evtchnPort_ );

	if ( ringPage_ == nullptr ) {
		cleanup();

		switch ( errno ) {
			case EBUSY:
				throw std::runtime_error(
				        "[Xen events] the domain is either already connected "
				        "with a monitoring application, or such an application crashed after "
				        "connecting to it" );
			case ENODEV:
				throw std::runtime_error( "[Xen events] EPT not supported for this guest" );
			default:
				throw std::runtime_error(
				        std::string( "[Xen events] error initialising shared page: " ) +
				        strerror( errno ) );
		}
	}

	memAccessOn_ = true;

	initEventChannels();

	xc_.domainSetAccessRequired( domain_, 0 );
}

int XenEventManager::waitForEventOrTimeout( int ms )
{
#ifndef DISABLE_MEM_EVENT
	struct pollfd fd[2];

	fd[0].fd     = xs_.fileno();
	fd[0].events = POLLIN | POLLERR;
	fd[1].fd     = xc_.evtchnFd( xce_ );
	fd[1].events = POLLIN | POLLERR;

	int rc = poll( fd, 2, ms );
#else
	struct pollfd fd[1];

	fd[0].fd     = xs_.fileno();
	fd[0].events = POLLIN | POLLERR;

	int rc = poll( fd, 1, ms );
#endif

	if ( rc == 0 ) // poll() timeout
		return 0;

	if ( rc < 0 ) {
		if ( errno == EINTR ) // interrupted by signal
			return 0;

		throw std::runtime_error( "[Xen events] poll() failed" );
	}

	if ( fd[0].revents & POLLIN ) { // a XenStore event
		std::vector<std::string> vec;

		if ( xs_.readWatch( vec ) && vec[XS::watchToken] == watchToken_ ) {
			/* Our domain is being shut down */
			if ( vec[XS::watchPath] == watchToken_ ) {
				if ( firstReleaseWatch_ ) {
					// Ignore first triggered watch, xs_watch() does that.
					firstReleaseWatch_ = false;
				} else {
					xs_transaction_t         th = xs_.transactionStart();
					std::vector<std::string> dir;

					if ( !xs_.directory( th, vec[XS::watchPath], dir ) ) {
						guestState_ = ( xs_.isDomainIntroduced( domain_ ) != 0 ) ?
							RUNNING : SHUTDOWN_IN_PROGRESS;
						stop();
					}

					xs_.transactionEnd( th, 0 );
				}
			} else if ( vec[XS::watchPath] == controlXenStorePath_ ) {
				if ( firstControlCommand_ ) {
					// Ignore first triggered watch, xs_watch() does that.
					firstControlCommand_ = false;
				} else {
					CUniquePtr<char> value(
					        xs_.readTimeout( XS::xbtNull, vec[XS::watchPath], nullptr, 1 ) );

					if ( value ) {
						std::string tmp = value.get();

						logger << INFO << "Received control command: " << tmp << std::flush;

						if ( tmp == "shutdown" ) {
							guestState_ = RUNNING;
							stop();
						}
					}
				}
			} else if ( vec[XS::watchPath] == "@releaseDomain" ) {
				if ( !xs_.isDomainIntroduced( domain_ ) ) {
					guestState_ = POST_SHUTDOWN;
					stop();
				}
			}

			return 0;
		}
	}

#ifndef DISABLE_MEM_EVENT
	if ( fd[1].revents & POLLIN ) { // a vm_event
		int port = xc_.evtchnPending( xce_ );

		if ( port == -1 )
			throw std::runtime_error( "[Xen events] failed to read port from event channel" );

		if ( xc_.evtchnUnmask( xce_, port ) != 0 )
			throw std::runtime_error( "[Xen events] failed to unmask event channel port" );

		return port;
	}
#endif

	// shouldn't be here
	throw std::runtime_error( "[Xen events] error getting event" );
}

template <typename Request, typename Ring> void XenEventManager::getRequest( Request &req )
{
	Ring *      backRing   = static_cast<Ring *>( backRing_ );
	RING_IDX    reqCons    = backRing->req_cons;
	const void *ringReqPtr = RING_GET_REQUEST( backRing, reqCons );

	/* Copy request */
	memcpy( &req, ringReqPtr, sizeof( req ) );
	++reqCons;

	/* Update ring */
	backRing->req_cons         = reqCons;
	backRing->sring->req_event = reqCons + 1;
}

template <typename Response, typename Ring> void XenEventManager::putResponse( const Response &rsp )
{
	Ring *   backRing = static_cast<Ring *>( backRing_ );
	RING_IDX rspProd  = backRing->rsp_prod_pvt;

	/* Copy response */
	memcpy( RING_GET_RESPONSE( backRing, rspProd ), &rsp, sizeof( rsp ) );
	++rspProd;

	/* Update ring */
	backRing->rsp_prod_pvt = rspProd;
	RING_PUSH_RESPONSES( backRing );
}

void XenEventManager::resumePage()
{
	/* Tell Xen page is ready */
	if ( xc_.evtchnNotify( xce_, port_ ) < 0 )
		throw std::runtime_error( "[Xen events] error resuming page" );
}

std::string XenEventManager::uuid()
{
	return driver_.uuid();
}

uint64_t XenEventManager::getMsr( unsigned short vcpu, uint32_t msr ) const
{
	bdvmi::Registers regs;

	if ( !driver_.registers( vcpu, regs ) )
		return 0;

	switch ( msr ) {
		case MSR_IA32_SYSENTER_CS:
			return regs.sysenter_cs;
		case MSR_IA32_SYSENTER_ESP:
			return regs.sysenter_esp;
		case MSR_IA32_SYSENTER_EIP:
			return regs.sysenter_eip;
		case MSR_EFER:
			return regs.msr_efer;
		case MSR_LSTAR:
			return regs.msr_lstar;
		case MSR_FS_BASE:
			return regs.fs_base;
		case MSR_GS_BASE:
			return regs.gs_base;
		case MSR_STAR:
			return regs.msr_star;
		case MSR_IA32_CR_PAT:
			return regs.msr_pat;
		case MSR_SHADOW_GS_BASE:
			return regs.shadow_gs;
		case MSR_IA32_MISC_ENABLE:
		case MSR_IA32_MC0_CTL:
		default:
			return 0;
	}
}

} // namespace bdvmi
