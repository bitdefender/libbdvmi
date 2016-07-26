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

#include "bdvmi/statscollector.h"
#include "bdvmi/xendriver.h"
#include "bdvmi/xeneventmanager.h"
#include "bdvmi/eventhandler.h"
#include "bdvmi/loghelper.h"
#include <sys/mman.h>
#include <poll.h>
#include <errno.h>
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <stdexcept>
#include <xen/memory.h>

extern "C" {
#include <xen/xen-compat.h>
#if __XEN_LATEST_INTERFACE_VERSION__ < 0x00040600
#error unsupported Xen version
#endif
}

#define GLA_VALID( x ) ( x.u.mem_access.flags & MEM_ACCESS_GLA_VALID )
#define ACCESS_R( x ) ( x.u.mem_access.flags & MEM_ACCESS_R )
#define ACCESS_W( x ) ( x.u.mem_access.flags & MEM_ACCESS_W )
#define ACCESS_X( x ) ( x.u.mem_access.flags & MEM_ACCESS_X )

#define LOG_ERROR( x )                                                                                                 \
	{                                                                                                              \
		if ( logHelper_ )                                                                                      \
			logHelper_->error( x );                                                                        \
	}

#define LOG_DEBUG( x )                                                                                                 \
	{                                                                                                              \
		if ( logHelper_ )                                                                                      \
			logHelper_->debug( x );                                                                        \
	}

namespace bdvmi {

XenEventManager::XenEventManager( XenDriver &driver, unsigned short hndlFlags, LogHelper *logHelper,
                                  bool useAltP2m )
    : driver_( driver ), xci_( driver.nativeHandle() ), domain_( driver.id() ), stop_( false ), xce_( NULL ),
      port_( -1 ), xsh_( NULL ), evtchnPort_( 0 ), ringPage_( NULL ), memAccessOn_( false ), evtchnOn_( false ),
      evtchnBindOn_( false ), handlerFlags_( 0 ), guestStillRunning_( true ), logHelper_( logHelper ),
      firstReleaseWatch_( true ), firstXenServerWatch_( true ), useAltP2m_( useAltP2m )
{
	initXenStore();

#ifndef DISABLE_MEM_EVENT
	initAltP2m();
	initMemAccess();

	if ( !handlerFlags( hndlFlags ) ) {
		cleanup();
		throw std::runtime_error( "[Xen events] could not set up events" );
	}

#endif // DISABLE_MEM_EVENT
}

XenEventManager::~XenEventManager()
{
	xc_monitor_guest_request( xci_, domain_, 0, 1 );
	xc_monitor_write_ctrlreg( xci_, domain_, VM_EVENT_X86_XCR0, 0, 1, 1 );
	xc_monitor_software_breakpoint( xci_, domain_, 0 );

	handler( NULL );

	if ( !stop_ )
		stop();

	// cleanup events
	try {
		waitForEvents();
	} catch ( ... ) {
		// std::runtime_errors not allowed to escape destructors
	}

	cleanup();
}

void XenEventManager::cleanup()
{
#ifndef DISABLE_MEM_EVENT
	if ( useAltP2m_ ) {
		unsigned int cpus = 0;
		driver_.cpuCount( cpus );

		for ( unsigned int vcpu = 0; vcpu < cpus; ++vcpu )
			xc_domain_debug_control( xci_, domain_, vcpu, XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_OFF );
	}

	/* Tear down domain xenaccess in Xen */
	if ( ringPage_ )
		munmap( ringPage_, XC_PAGE_SIZE );

	if ( memAccessOn_ ) {
		xc_monitor_disable( xci_, domain_ );
	}

	// Unbind VIRQ
	if ( evtchnBindOn_ )
		xc_evtchn_unbind( xce_, port_ );

	if ( evtchnOn_ )
		xc_evtchn_close( xce_ );
#endif // DISABLE_MEM_EVENT

	if ( xsh_ ) {
		xs_unwatch( xsh_, "@releaseDomain", watchToken_.c_str() );
		xs_unwatch( xsh_, watchToken_.c_str(), watchToken_.c_str() );

		xs_unwatch( xsh_, controlXenStorePath_.c_str(), watchToken_.c_str() );
		xs_rm( xsh_, XBT_NULL, controlXenStorePath_.c_str() );

		xs_close( xsh_ );
	}
}

bool XenEventManager::handlerFlags( unsigned short flags )
{
	if ( flags & ENABLE_CR0 ) {
		if ( ( handlerFlags_ & ENABLE_CR0 ) == 0 ) {
			if ( xc_monitor_write_ctrlreg( xci_, domain_, VM_EVENT_X86_CR0, 1, 1, 1 ) ) {
				LOG_ERROR( "[Xen events] could not set up CR0 event handler" );
				return false;
			}
		}
	} else if ( handlerFlags_ & ENABLE_CR0 )
		xc_monitor_write_ctrlreg( xci_, domain_, VM_EVENT_X86_CR0, 0, 1, 1 );

	if ( flags & ENABLE_CR3 ) {
		if ( ( handlerFlags_ & ENABLE_CR3 ) == 0 ) {
			if ( xc_monitor_write_ctrlreg( xci_, domain_, VM_EVENT_X86_CR3, 1, 1, 1 ) ) {
				LOG_ERROR( "[Xen events] could not set up CR3 event handler" );
				return false;
			}
		}
	} else if ( handlerFlags_ & ENABLE_CR3 )
		xc_monitor_write_ctrlreg( xci_, domain_, VM_EVENT_X86_CR3, 0, 1, 1 );

	if ( flags & ENABLE_CR4 ) {
		if ( ( handlerFlags_ & ENABLE_CR4 ) == 0 ) {
			if ( xc_monitor_write_ctrlreg( xci_, domain_, VM_EVENT_X86_CR4, 1, 1, 1 ) ) {
				LOG_ERROR( "[Xen events] could not set up CR4 event handler" );
				return false;
			}
		}
	} else if ( handlerFlags_ & ENABLE_CR4 )
		xc_monitor_write_ctrlreg( xci_, domain_, VM_EVENT_X86_CR4, 0, 1, 1 );

#if XEN_DOMCTL_INTERFACE_VERSION < 0x0000000c
	if ( flags & ENABLE_MSR ) {

		if ( ( handlerFlags_ & ENABLE_MSR ) == 0 ) {

			if ( xc_monitor_mov_to_msr( xci_, domain_, 1, 1 ) ) {
				LOG_ERROR( "[Xen events] could not set up MSR event handler" );
				return false;
			}
		}
	} else {
		if ( handlerFlags_ & ENABLE_MSR )
			xc_monitor_mov_to_msr( xci_, domain_, 0, 1 );
	}
#endif
	handlerFlags_ = flags;

	/*
	   No check for (flags & ENABLE_MEMORY) because Xen memory events
	   are being set up by the driver directly (via setPageProtection()).

	   The flag is, however, necessary, to tell waitForEvents() if it
	   should call EventHandler::handlePageFault() or not.
	*/

	return true;
}

bool XenEventManager::enableMsrEvents( unsigned int msr )
{
#if XEN_DOMCTL_INTERFACE_VERSION < 0x0000000c
	msr = msr; // Avoid unused parameter warning
	return true;
#else
	return ( xc_monitor_mov_to_msr( xci_, domain_, msr, 1 ) == 0 );
#endif
}

bool XenEventManager::disableMsrEvents( unsigned int msr )
{
#if XEN_DOMCTL_INTERFACE_VERSION < 0x0000000c
	msr = msr; // Avoid unused parameter warning
	return true;
#else
	return ( xc_monitor_mov_to_msr( xci_, domain_, msr, 0 ) == 0 );
#endif
}

inline void copyRegisters( Registers &regs, const vm_event_request_t &req )
{
	regs.sysenter_cs = req.data.regs.x86.sysenter_cs;
	regs.sysenter_esp = req.data.regs.x86.sysenter_esp;
	regs.sysenter_eip = req.data.regs.x86.sysenter_eip;
	regs.msr_efer = req.data.regs.x86.msr_efer;
	regs.msr_star = req.data.regs.x86.msr_star;
	regs.msr_lstar = req.data.regs.x86.msr_lstar;
	regs.fs_base = req.data.regs.x86.fs_base;
	regs.gs_base = req.data.regs.x86.gs_base;
	/*
	regs.idtr_base    = req.data.regs.x86.idtr_base;
	regs.idtr_limit   = req.data.regs.x86.idtr_limit;
	regs.gdtr_base    = req.data.regs.x86.gdtr_base;
	regs.gdtr_limit   = req.data.regs.x86.gdtr_limit;
	*/
	regs.rflags = req.data.regs.x86.rflags;
	regs.rax = req.data.regs.x86.rax;
	regs.rcx = req.data.regs.x86.rcx;
	regs.rdx = req.data.regs.x86.rdx;
	regs.rbx = req.data.regs.x86.rbx;
	regs.rsp = req.data.regs.x86.rsp;
	regs.rbp = req.data.regs.x86.rbp;
	regs.rsi = req.data.regs.x86.rsi;
	regs.rdi = req.data.regs.x86.rdi;
	regs.r8 = req.data.regs.x86.r8;
	regs.r9 = req.data.regs.x86.r9;
	regs.r10 = req.data.regs.x86.r10;
	regs.r11 = req.data.regs.x86.r11;
	regs.r12 = req.data.regs.x86.r12;
	regs.r13 = req.data.regs.x86.r13;
	regs.r14 = req.data.regs.x86.r14;
	regs.r15 = req.data.regs.x86.r15;
	regs.rip = req.data.regs.x86.rip;
	regs.cr0 = req.data.regs.x86.cr0;
	regs.cr2 = req.data.regs.x86.cr2;
	regs.cr3 = req.data.regs.x86.cr3;
	regs.cr4 = req.data.regs.x86.cr4;

	regs.cs_arbytes = req.data.regs.x86.cs_arbytes;

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

void XenEventManager::waitForEvents()
{
	EventHandler *h = handler();
	bool shuttingDown = false;

	for ( ;; ) {

		waitForEventOrTimeout( 100 );

		if ( sigStop_ && *sigStop_ )
			stop();

		if ( stop_ )
			shuttingDown = true;

#ifndef DISABLE_MEM_EVENT
		vm_event_request_t req;
		vm_event_response_t rsp;

		int events = 0;

		while ( RING_HAS_UNCONSUMED_REQUESTS( &backRing_ ) ) {
			unsigned short hndlFlags = handlerFlags();

			getRequest( &req );

			++events;

			StatsCollector::instance().incStat( "eventCount" );

			memset( &rsp, 0, sizeof( rsp ) );
			rsp.vcpu_id = req.vcpu_id;
			rsp.flags = req.flags;
			rsp.reason = req.reason;
			rsp.data.regs.x86 = req.data.regs.x86;

			rsp.version = VM_EVENT_INTERFACE_VERSION;
			rsp.u.mem_access.flags = req.u.mem_access.flags;

			driver_.enableCache( req.vcpu_id );

			if ( h )
				h->runPreEvent();

			switch ( req.reason ) {

				case VM_EVENT_REASON_MEM_ACCESS: {
					Registers regs;
					uint32_t rspDataSize = sizeof( rsp.data.emul_read_data.data );

					StatsCollector::instance().incStat( "eventsMemAccess" );

					copyRegisters( regs, req );

					rsp.flags |= VM_EVENT_FLAG_EMULATE;
					rsp.u.mem_access.gfn = req.u.mem_access.gfn;

					if ( h && ( hndlFlags & ENABLE_MEMORY ) ) {
						uint64_t gva = 0;
						bool read = ( ACCESS_R( req ) != 0 );
						bool write = ( ACCESS_W( req ) != 0 );
						bool execute = ( ACCESS_X( req ) != 0 );
						HVAction action = NONE;
						unsigned short instructionSize = 0;

						if ( GLA_VALID( req ) )
							gva = req.u.mem_access.gla;

						uint64_t gpa = ( req.u.mem_access.gfn << XC_PAGE_SHIFT ) +
						               req.u.mem_access.offset;

						if ( req.u.mem_access.flags & MEM_ACCESS_FAULT_IN_GPT )
							break;

						h->handlePageFault( req.vcpu_id, regs, gpa, gva, read, write, execute,
						                    action, rsp.data.emul_read_data.data, rspDataSize,
						                    instructionSize );

						rsp.data.emul_read_data.size = rspDataSize;

						switch ( action ) {
							case EMULATE_NOWRITE:
#ifndef VM_EVENT_FLAG_SET_REGISTERS
							case SKIP_INSTRUCTION:
#endif
								rsp.flags |= VM_EVENT_FLAG_EMULATE_NOWRITE;
								break;
#ifdef VM_EVENT_FLAG_SET_REGISTERS
							case SKIP_INSTRUCTION:
								rsp.data.regs.x86.rip =
								        req.data.regs.x86.rip + instructionSize;
								rsp.flags |= VM_EVENT_FLAG_SET_REGISTERS;
								rsp.flags &= ~VM_EVENT_FLAG_EMULATE;
								break;
#endif
							case ALLOW_VIRTUAL:
								// go on, but don't emulate (monitoring
								// application
								// changed EIP)
								rsp.flags &= ~VM_EVENT_FLAG_EMULATE;
								break;

							case EMULATE_SET_CTXT:
								rsp.flags |= VM_EVENT_FLAG_SET_EMUL_READ_DATA;
								break;

							case NONE:
							default:
								if ( useAltP2m_ &&
								     req.flags & VM_EVENT_FLAG_ALTERNATE_P2M ) {
									rsp.flags = req.flags;
									rsp.altp2m_idx = 0;
									xc_domain_debug_control(
									        xci_, domain_,
									        XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_ON,
									        req.vcpu_id );
								}
								break;
						}
					}

					break;
				}

				case VM_EVENT_REASON_SINGLESTEP:
					StatsCollector::instance().incStat( "eventsSingleStep" );

					if ( useAltP2m_ ) {
						rsp.reason = req.reason;
						rsp.flags |= VM_EVENT_FLAG_ALTERNATE_P2M;
						rsp.altp2m_idx = driver_.altp2mViewId();
					}

					xc_domain_debug_control( xci_, domain_, XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_OFF,
					                         req.vcpu_id );
					break;

				case VM_EVENT_REASON_WRITE_CTRLREG: {
					Registers regs;
					unsigned short crNumber = 3;

					StatsCollector::instance().incStat( "eventsWriteCtrlReg" );

					rsp.u.write_ctrlreg.index = req.u.write_ctrlreg.index;

					if ( req.u.write_ctrlreg.index == VM_EVENT_X86_XCR0 ) {
						if ( h && ( hndlFlags & ENABLE_XSETBV ) )
							h->handleXSETBV( req.vcpu_id, req.u.write_ctrlreg.new_value );

						break;
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

					if ( h ) {
						HVAction action = NONE;

						h->handleCR( req.vcpu_id, crNumber, regs, req.u.write_ctrlreg.old_value,
						             req.u.write_ctrlreg.new_value, action );

						if ( action == SKIP_INSTRUCTION || action == EMULATE_NOWRITE )
							rsp.flags |= VM_EVENT_FLAG_DENY;
					}

					break;
				}

				case VM_EVENT_REASON_MOV_TO_MSR:
					StatsCollector::instance().incStat( "eventsMovToMsr" );

					if ( h && ( hndlFlags & ENABLE_MSR ) ) {

						HVAction action = NONE;

						bool msrEnabled = false;
						driver_.isMsrEnabled( req.u.mov_to_msr.msr, msrEnabled );

						if ( msrEnabled ) {
							// old value == new value (can't get the old one)
							h->handleMSR( req.vcpu_id, req.u.mov_to_msr.msr,
							              req.u.mov_to_msr.value, req.u.mov_to_msr.value,
							              action );

							if ( action == SKIP_INSTRUCTION || action == EMULATE_NOWRITE )
								rsp.flags |= VM_EVENT_FLAG_DENY;
						}
					}

					break;

				case VM_EVENT_REASON_GUEST_REQUEST: {
					StatsCollector::instance().incStat( "eventsGuestRequest" );

					Registers regs;
					copyRegisters( regs, req );

					if ( h && ( hndlFlags & ENABLE_VMCALL ) )
						h->handleVMCALL( req.vcpu_id, regs, req.data.regs.x86.rip,
						                 req.data.regs.x86.rax );

					break;
				}

				case VM_EVENT_REASON_SOFTWARE_BREAKPOINT: {
					StatsCollector::instance().incStat( "eventsBreakPoint" );

					bool reinject = true;

					if ( h )
						reinject = !h->handleBreakpoint( req.vcpu_id,
						                                 req.u.software_breakpoint.gfn );

					if ( reinject )
						if ( xc_hvm_inject_trap( xci_, domain_, req.vcpu_id, 3,
						                         HVMOP_TRAP_sw_exc, ~0u, 1, 0 ) < 0 ) {

							if ( logHelper_ )
								logHelper_->error( "Could not reinject breakpoint" );
						}
				}

				default:
					// unknown reason code
					break;
			}

			if ( h )
				h->runPostEvent();

			driver_.disableCache();

			/* Put the page info on the ring */
			putResponse( &rsp );
			resumePage();
		}

		// if ( events )
		//	resumePage();
#endif // DISABLE_MEM_EVENT

		if ( shuttingDown )
			return;
	}
}

void XenEventManager::stop()
{
	EventHandler *h = handler();

	if ( h )
		h->handleSessionOver( guestStillRunning_ );

	stop_ = true;

#ifndef DISABLE_MEM_EVENT
	handlerFlags( 0 );
#endif // DISABLE_MEM_EVENT
}

void XenEventManager::initXenStore()
{
	xsh_ = xs_open( 0 );

	if ( !xsh_ )
		throw std::runtime_error( "[Xen events] xs_open() failed" );

	std::stringstream ss;
	ss << "/local/domain/0/device-model/" << domain_;

	watchToken_ = ss.str();

	ss.str("");
	ss << "/local/domain/" << domain_ << "/vm-data/introspection-control";

	controlXenStorePath_ = ss.str();

	std::string value = "started";

	if ( !xs_write( xsh_, XBT_NULL, controlXenStorePath_.c_str(), value.c_str(), value.length() ) ) {
		if ( logHelper_ )
			logHelper_->error( std::string("Could not write XenStore key ") + controlXenStorePath_ );
	}

	if ( !xs_watch( xsh_, "@releaseDomain", watchToken_.c_str() ) ||
	     !xs_watch( xsh_, watchToken_.c_str(), watchToken_.c_str() ) ||
	     !xs_watch( xsh_, controlXenStorePath_.c_str(), watchToken_.c_str() ) ) {
		xs_close( xsh_ );
		throw std::runtime_error( "[Xen events] xs_watch() failed" );
	}
}

void XenEventManager::initEventChannels()
{
	/* Open event channel */
	xce_ = xc_evtchn_open( NULL, 0 );

	if ( !xce_ ) {
		cleanup();
		throw std::runtime_error( "[Xen events] failed to open event channel" );
	}

	evtchnOn_ = true;

	/* Bind event notification */
	port_ = xc_evtchn_bind_interdomain( xce_, domain_, evtchnPort_ );

	if ( port_ < 0 ) {
		cleanup();
		throw std::runtime_error( "[Xen events] failed to bind event channel" );
	}

	evtchnBindOn_ = true;

/* Initialise ring */
#define private rprivate
	SHARED_RING_INIT( ( vm_event_sring_t * )ringPage_ );
	BACK_RING_INIT( &backRing_, ( vm_event_sring_t * )ringPage_, XC_PAGE_SIZE );
#undef private
}

void XenEventManager::initMemAccess()
{
	ringPage_ = xc_monitor_enable( xci_, domain_, &evtchnPort_ );

	if ( ringPage_ == NULL ) {
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
				throw std::runtime_error( std::string( "[Xen events] error initialising shared page: " )
					+ strerror( errno ) );
		}
	}

	memAccessOn_ = true;

	initEventChannels();

	xc_domain_set_access_required( xci_, domain_, 0 );

	xc_monitor_guest_request( xci_, domain_, 1, 1 );
	xc_monitor_write_ctrlreg( xci_, domain_, VM_EVENT_X86_XCR0, 1, 1, 1 );
	xc_monitor_software_breakpoint( xci_, domain_, 1 );
}

void XenEventManager::initAltP2m()
{
	if ( !useAltP2m_ )
		return;

	if ( xc_monitor_singlestep( xci_, domain_, 1 ) < 0 ) {
		cleanup();
		throw std::runtime_error( "[ALTP2M] could not enable singlestep monitoring" );
	}
}

int XenEventManager::waitForEventOrTimeout( int ms )
{
#ifndef DISABLE_MEM_EVENT
	struct pollfd fd[2];

	fd[0].fd = xs_fileno( xsh_ );
	fd[0].events = POLLIN | POLLERR;
	fd[1].fd = xc_evtchn_fd( xce_ );
	fd[1].events = POLLIN | POLLERR;

	int rc = poll( fd, 2, ms );
#else
	struct pollfd fd[1];

	fd[0].fd = xs_fileno( xsh_ );
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

		unsigned int num;
		char **vec = xs_read_watch( xsh_, &num );

		if ( vec && watchToken_ == vec[XS_WATCH_TOKEN] ) {
			/* Our domain is being shut down */

			if ( watchToken_ == vec[XS_WATCH_PATH] ) {

				if ( firstReleaseWatch_ ) {
					// Ignore first triggered watch, xs_watch() does that.
					firstReleaseWatch_ = false;
				} else {

					unsigned int len = 0;
					xs_transaction_t th = xs_transaction_start( xsh_ );
					void *buf = xs_directory( xsh_, th, vec[XS_WATCH_PATH], &len );

					if ( !buf ) {
						guestStillRunning_ = ( xs_is_domain_introduced( xsh_, domain_ ) != 0 );
						stop();
					}

					free( buf );
					xs_transaction_end( xsh_, th, 0 );
				}
			} else if ( vec && controlXenStorePath_ == vec[XS_WATCH_PATH] ) {

				if ( firstXenServerWatch_ ) {
					// Ignore first triggered watch, xs_watch() does that.
					firstXenServerWatch_ = false;
				} else {
					char *value = static_cast<char *>(
					        xs_read_timeout( xsh_, XBT_NULL, vec[XS_WATCH_PATH], NULL, 1 ) );

					if ( value ) {
						std::string tmp = value;
						free( value );

						if ( logHelper_ )
							logHelper_->info( std::string( "Received control command: " ) + tmp );

						if ( tmp == "shutdown" ) {
							guestStillRunning_ = true;
							stop();
						}
					}
				}
			} else if ( vec && std::string( "@releaseDomain" ) == vec[XS_WATCH_PATH] ) {
				if ( !xs_is_domain_introduced( xsh_, domain_ ) ) {
					guestStillRunning_ = false;
					stop();
				}
			}

			free( vec );
			return 0;
		}

		free( vec );
	}

#ifndef DISABLE_MEM_EVENT
	if ( fd[1].revents & POLLIN ) { // a vm_event
		int port = xc_evtchn_pending( xce_ );

		if ( port == -1 )
			throw std::runtime_error( "[Xen events] failed to read port from event channel" );

		if ( xc_evtchn_unmask( xce_, port ) != 0 )
			throw std::runtime_error( "[Xen events] failed to unmask event channel port" );

		return port;
	}
#endif

	// shouldn't be here
	throw std::runtime_error( "[Xen events] error getting event" );
}

void XenEventManager::getRequest( vm_event_request_t *req )
{
	vm_event_back_ring_t *back_ring;
	RING_IDX req_cons;

	back_ring = &backRing_;
	req_cons = back_ring->req_cons;

	/* Copy request */
	memcpy( req, RING_GET_REQUEST( back_ring, req_cons ), sizeof( *req ) );
	++req_cons;

	/* Update ring */
	back_ring->req_cons = req_cons;
	back_ring->sring->req_event = req_cons + 1;
}

void XenEventManager::putResponse( vm_event_response_t *rsp )
{
	vm_event_back_ring_t *back_ring;
	RING_IDX rsp_prod;

	back_ring = &backRing_;
	rsp_prod = back_ring->rsp_prod_pvt;

	/* Copy response */
	memcpy( RING_GET_RESPONSE( back_ring, rsp_prod ), rsp, sizeof( *rsp ) );
	++rsp_prod;

	/* Update ring */
	back_ring->rsp_prod_pvt = rsp_prod;
	RING_PUSH_RESPONSES( back_ring );
}

void XenEventManager::resumePage()
{
	/* Tell Xen page is ready */
	// xc_monitor_resume(xci_, domain_);

	if ( xc_evtchn_notify( xce_, port_ ) < 0 )
		throw std::runtime_error( "[Xen events] error resuming page" );
}

std::string XenEventManager::uuid()
{
	return driver_.uuid();
}

} // namespace bdvmi
