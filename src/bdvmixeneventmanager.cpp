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

#include "bdvmi/exception.h"
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

extern "C" {
#include <xen/xen-compat.h>
#if __XEN_LATEST_INTERFACE_VERSION__ < 0x00040400
#error unsupported Xen version
#endif
}

#if __XEN_LATEST_INTERFACE_VERSION__ <= 0x00040500
#define REGS( x ) x.x86_regs
#else
#define REGS( x ) x.data.regs.x86
#endif

#if __XEN_LATEST_INTERFACE_VERSION__ >= 0x00040600
#define GLA( x ) x.u.mem_access.gla
#define GLA_VALID( x ) ( x.u.mem_access.flags & MEM_ACCESS_GLA_VALID )
#define GFN( x ) x.u.mem_access.gfn
#define OFFSET( x ) x.u.mem_access.offset
#define ACCESS_R( x ) ( x.u.mem_access.flags & MEM_ACCESS_R )
#define ACCESS_W( x ) ( x.u.mem_access.flags & MEM_ACCESS_W )
#define ACCESS_X( x ) ( x.u.mem_access.flags & MEM_ACCESS_X )
#define MSR_TYPE( x ) x.u.mov_to_msr.msr
#define MSR_VALUE( x ) x.u.mov_to_msr.value
#define CR_NEW_VALUE( x ) x.u.write_ctrlreg.new_value
#define CR_OLD_VALUE( x ) x.u.write_ctrlreg.old_value
#define VMCALL_RIP( x ) x.data.regs.x86.rip
#define VMCALL_RAX( x ) x.data.regs.x86.rax
#define RESPONSE_DATA( x ) x.data.emul_read_data

#define MEM_EVENT_FLAG_EMUL_SET_CONTEXT VM_EVENT_FLAG_SET_EMUL_READ_DATA
#define MEM_EVENT_FLAG_DENY VM_EVENT_FLAG_DENY
#define MEM_EVENT_REASON_VMCALL VM_EVENT_REASON_GUEST_REQUEST
#define MEM_EVENT_REASON_XSETBV VM_EVENT_REASON_XSETBV

#else
#define GLA( x ) x.gla
#define GLA_VALID( x ) x.gla_valid
#define GFN( x ) x.gfn
#define OFFSET( x ) x.offset
#define ACCESS_R( x ) x.access_r
#define ACCESS_W( x ) x.access_w
#define ACCESS_X( x ) x.access_x
#define MSR_TYPE( x ) x.gla
#define MSR_VALUE( x ) x.gfn
#define CR_NEW_VALUE( x ) x.gfn
#define CR_OLD_VALUE( x ) x.gla
#define VMCALL_RIP( x ) x.gfn
#define VMCALL_RAX( x ) x.gla
#define RESPONSE_DATA( x ) x.rsp_data

#define MEM_EVENT_FLAG_DENY MEM_EVENT_FLAG_SKIP_MSR_WRITE
#endif

#define LOG_ERROR( x )                                                                                                 \
	{                                                                                                              \
		if ( logHelper_ )                                                                                      \
			logHelper_->error( x );                                                                        \
	}

namespace bdvmi {

XenEventManager::XenEventManager( const XenDriver &driver, unsigned short hndlFlags, LogHelper *logHelper )
    : driver_( driver ), xci_( driver.nativeHandle() ), domain_( driver.id() ), stop_( false ), xce_( NULL ),
      port_( -1 ), xsh_( NULL ), evtchnPort_( 0 ), ringPage_( NULL ), memAccessOn_( false ), evtchnOn_( false ),
      evtchnBindOn_( false ), handlerFlags_( 0 ), guestStillRunning_( true ), logHelper_( logHelper ),
      firstReleaseWatch_( true )
{
	initXenStore();

#ifndef DISABLE_MEM_EVENT
	initMemAccess();

	if ( !handlerFlags( hndlFlags ) ) {
		cleanup();
		throw Exception( "[Xen events] could not set up events" );
	}

#endif // DISABLE_MEM_EVENT
}

XenEventManager::~XenEventManager()
{
#if __XEN_LATEST_INTERFACE_VERSION__ >= 0x00040600
	xc_monitor_guest_request( xci_, domain_, 0, 1 );
	xc_monitor_write_ctrlreg( xci_, domain_, VM_EVENT_X86_XCR0, 0, 1, 1 );
#endif

	if ( !stop_ ) {
		stop();

		// cleanup events
		try {
			waitForEvents();
		} catch ( ... ) {
			// Exceptions not allowed to escape destructors
		}
	}

	cleanup();
}

void XenEventManager::cleanup()
{
#ifndef DISABLE_MEM_EVENT
	/* Tear down domain xenaccess in Xen */
	if ( ringPage_ )
		munmap( ringPage_, XC_PAGE_SIZE );

	if ( memAccessOn_ )
#if __XEN_LATEST_INTERFACE_VERSION__ >= 0x00040600
		xc_mem_access_disable_emulate( xci_, domain_ );
		xc_monitor_disable( xci_, domain_ );
#else
		xc_mem_access_disable( xci_, domain_ );
#endif

	// Unbind VIRQ
	if ( evtchnBindOn_ )
		xc_evtchn_unbind( xce_, port_ );

	if ( evtchnOn_ )
		xc_evtchn_close( xce_ );
#endif // DISABLE_MEM_EVENT

	if ( xsh_ ) {
		xs_unwatch( xsh_, "@releaseDomain", watchToken_.c_str() );
		xs_unwatch( xsh_, watchToken_.c_str(), watchToken_.c_str() );
		xs_close( xsh_ );
	}
}

bool XenEventManager::handlerFlags( unsigned short flags )
{
	if ( flags & ENABLE_CR ) {

		if ( ( handlerFlags_ & ENABLE_CR ) == 0 ) {
#if __XEN_LATEST_INTERFACE_VERSION__ >= 0x00040600
			if ( xc_monitor_write_ctrlreg( xci_, domain_, VM_EVENT_X86_CR0, 1, 1, 1 ) ) {
#else
			if ( xc_set_hvm_param( xci_, domain_, HVM_PARAM_MEMORY_EVENT_CR0,
			                       HVMPME_onchangeonly | HVMPME_mode_sync ) ) {
#endif
				LOG_ERROR( "[Xen events] could not set up CR0 event handler" );
				return false;
			}

#if __XEN_LATEST_INTERFACE_VERSION__ >= 0x00040600
			if ( xc_monitor_write_ctrlreg( xci_, domain_, VM_EVENT_X86_CR3, 1, 1, 1 ) ) {
#else
			if ( xc_set_hvm_param( xci_, domain_, HVM_PARAM_MEMORY_EVENT_CR3,
			                       HVMPME_onchangeonly | HVMPME_mode_sync ) ) {
#endif
				LOG_ERROR( "[Xen events] could not set up CR3 event handler" );
				return false;
			}

#if __XEN_LATEST_INTERFACE_VERSION__ >= 0x00040600
			if ( xc_monitor_write_ctrlreg( xci_, domain_, VM_EVENT_X86_CR4, 1, 1, 1 ) ) {
#else
			if ( xc_set_hvm_param( xci_, domain_, HVM_PARAM_MEMORY_EVENT_CR4,
			                       HVMPME_onchangeonly | HVMPME_mode_sync ) ) {
#endif
				LOG_ERROR( "[Xen events] could not set up CR4 event handler" );
				return false;
			}
		}
	} else {
		if ( handlerFlags_ & ENABLE_CR ) {
#if __XEN_LATEST_INTERFACE_VERSION__ >= 0x00040600
			xc_monitor_write_ctrlreg( xci_, domain_, VM_EVENT_X86_CR0, 0, 1, 1 );
			xc_monitor_write_ctrlreg( xci_, domain_, VM_EVENT_X86_CR3, 0, 1, 1 );
			xc_monitor_write_ctrlreg( xci_, domain_, VM_EVENT_X86_CR4, 0, 1, 1 );
#else
			xc_set_hvm_param( xci_, domain_, HVM_PARAM_MEMORY_EVENT_CR0, HVMPME_mode_disabled );
			xc_set_hvm_param( xci_, domain_, HVM_PARAM_MEMORY_EVENT_CR3, HVMPME_mode_disabled );
			xc_set_hvm_param( xci_, domain_, HVM_PARAM_MEMORY_EVENT_CR4, HVMPME_mode_disabled );
#endif
		}
	}

	if ( flags & ENABLE_MSR ) {

		if ( ( handlerFlags_ & ENABLE_MSR ) == 0 ) {

#if __XEN_LATEST_INTERFACE_VERSION__ >= 0x00040600
			if ( xc_monitor_mov_to_msr( xci_, domain_, 1, 1 ) ) {
#else
			if ( xc_set_hvm_param( xci_, domain_, HVM_PARAM_MEMORY_EVENT_MSR, HVMPME_mode_sync ) ) {
#endif
				LOG_ERROR( "[Xen events] could not set up MSR event handler" );
				return false;
			}
		}
	} else {
		if ( handlerFlags_ & ENABLE_MSR )
#if __XEN_LATEST_INTERFACE_VERSION__ >= 0x00040600
			xc_monitor_mov_to_msr( xci_, domain_, 0, 1 );
#else
			xc_set_hvm_param( xci_, domain_, HVM_PARAM_MEMORY_EVENT_MSR, HVMPME_mode_disabled );
#endif
	}

#if __XEN_LATEST_INTERFACE_VERSION__ == 0x00040500
	/* Always on in Xen 4.4. */
	if ( flags & ENABLE_VMCALL ) {
		if ( ( handlerFlags_ & ENABLE_VMCALL ) == 0 &&
		     xc_set_hvm_param( xci_, domain_, HVM_PARAM_MEMORY_EVENT_VMCALL, HVMPME_mode_sync ) ) {
			LOG_ERROR( "[Xen events] could not set up VMCALL event handler" );
			return false;
		}
	} else {
		if ( handlerFlags_ & ENABLE_VMCALL )
			xc_set_hvm_param( xci_, domain_, HVM_PARAM_MEMORY_EVENT_VMCALL, HVMPME_mode_disabled );
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

inline void copyRegisters( Registers &regs, const mem_event_request_t &req )
{
	regs.sysenter_cs = REGS( req ).sysenter_cs;
	regs.sysenter_esp = REGS( req ).sysenter_esp;
	regs.sysenter_eip = REGS( req ).sysenter_eip;
	regs.msr_efer = REGS( req ).msr_efer;
	regs.msr_star = REGS( req ).msr_star;
	regs.msr_lstar = REGS( req ).msr_lstar;
	regs.fs_base = REGS( req ).fs_base;
	regs.gs_base = REGS( req ).gs_base;
	/*
	regs.idtr_base    = REGS(req).idtr_base;
	regs.idtr_limit   = REGS(req).idtr_limit;
	regs.gdtr_base    = REGS(req).gdtr_base;
	regs.gdtr_limit   = REGS(req).gdtr_limit;
	*/
	regs.rflags = REGS( req ).rflags;
	regs.rax = REGS( req ).rax;
	regs.rcx = REGS( req ).rcx;
	regs.rdx = REGS( req ).rdx;
	regs.rbx = REGS( req ).rbx;
	regs.rsp = REGS( req ).rsp;
	regs.rbp = REGS( req ).rbp;
	regs.rsi = REGS( req ).rsi;
	regs.rdi = REGS( req ).rdi;
	regs.r8 = REGS( req ).r8;
	regs.r9 = REGS( req ).r9;
	regs.r10 = REGS( req ).r10;
	regs.r11 = REGS( req ).r11;
	regs.r12 = REGS( req ).r12;
	regs.r13 = REGS( req ).r13;
	regs.r14 = REGS( req ).r14;
	regs.r15 = REGS( req ).r15;
	regs.rip = REGS( req ).rip;
	regs.dr7 = REGS( req ).dr7;
	regs.cr0 = REGS( req ).cr0;
	regs.cr2 = REGS( req ).cr2;
	regs.cr3 = REGS( req ).cr3;
	regs.cr4 = REGS( req ).cr4;

	regs.cs_arbytes = REGS( req ).cs_arbytes;

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
		mem_event_request_t req;
		mem_event_response_t rsp;

		while ( RING_HAS_UNCONSUMED_REQUESTS( &backRing_ ) ) {
			unsigned short hndlFlags = handlerFlags();

			getRequest( &req );

			memset( &rsp, 0, sizeof( rsp ) );
			rsp.vcpu_id = req.vcpu_id;
			rsp.flags = req.flags;
			rsp.reason = req.reason;
			REGS( rsp ) = REGS( req );

#if __XEN_LATEST_INTERFACE_VERSION__ >= 0x00040600
			rsp.version = VM_EVENT_INTERFACE_VERSION;
			rsp.u.mem_access.flags = req.u.mem_access.flags;
#else
			rsp.access_r = req.access_r;
			rsp.access_w = req.access_w;
			rsp.access_x = req.access_x;
#endif

			if ( h )
				h->runPreEvent();

			switch ( req.reason ) {

				case MEM_EVENT_REASON_VIOLATION: {
					Registers regs;
					uint32_t rspDataSize = sizeof( RESPONSE_DATA( rsp ).data );

					copyRegisters( regs, req );

					rsp.flags |= MEM_EVENT_FLAG_EMULATE;
					GFN( rsp ) = GFN( req );
#if __XEN_LATEST_INTERFACE_VERSION__ < 0x00040600
					rsp.p2mt = req.p2mt;
#endif
					if ( h && ( hndlFlags & ENABLE_MEMORY ) ) {
						uint64_t gva = 0;
						bool read = ( ACCESS_R( req ) != 0 );
						bool write = ( ACCESS_W( req ) != 0 );
						bool execute = ( ACCESS_X( req ) != 0 );
						HVAction action = NONE;
						unsigned short instructionSize = 0;

						if ( GLA_VALID( req ) )
							gva = GLA( req );

						uint64_t gpa = ( GFN( req ) << XC_PAGE_SHIFT ) + OFFSET( req );
#if __XEN_LATEST_INTERFACE_VERSION__ == 0x00040500
						if ( req.fault_in_gpt )
							break;
#elif __XEN_LATEST_INTERFACE_VERSION__ >= 0x00040600
						if ( req.u.mem_access.flags & MEM_ACCESS_FAULT_IN_GPT )
							break;
#endif
						h->handlePageFault( req.vcpu_id, regs, gpa, gva, read, write, execute,
						                    action, RESPONSE_DATA( rsp ).data, rspDataSize,
						                    instructionSize );

						RESPONSE_DATA( rsp ).size = rspDataSize;

						switch ( action ) {
							case EMULATE_NOWRITE:
#ifndef VM_EVENT_FLAG_SET_REGISTERS
							case SKIP_INSTRUCTION:
#endif
								rsp.flags |= MEM_EVENT_FLAG_EMULATE_NOWRITE;
								break;
#ifdef VM_EVENT_FLAG_SET_REGISTERS
							case SKIP_INSTRUCTION:
								REGS( rsp ).rip = REGS( req ).rip + instructionSize;
								rsp.flags |= VM_EVENT_FLAG_SET_REGISTERS;
								break;
#endif
							case ALLOW_VIRTUAL:
								// go on, but don't emulate (monitoring application
								// changed EIP)
								rsp.flags &= ~MEM_EVENT_FLAG_EMULATE;
								break;

							case EMULATE_SET_CTXT:
								rsp.flags |= MEM_EVENT_FLAG_EMUL_SET_CONTEXT;
								break;

							case NONE:
							default:
								break;
						}
					}

					break;
				}

#if __XEN_LATEST_INTERFACE_VERSION__ >= 0x00040600
				case VM_EVENT_REASON_WRITE_CTRLREG: {
#else
				case MEM_EVENT_REASON_CR0:
				case MEM_EVENT_REASON_CR3:
				case MEM_EVENT_REASON_CR4: {
#endif
					Registers regs;
					unsigned short crNumber = 3;

#if __XEN_LATEST_INTERFACE_VERSION__ >= 0x00040600
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
#else
					switch ( req.reason ) {
						case MEM_EVENT_REASON_CR0:
							crNumber = 0;
							break;
						case MEM_EVENT_REASON_CR4:
							crNumber = 4;
							break;
						case MEM_EVENT_REASON_CR3:
						default:
							crNumber = 3;
							break;
					}
#endif
					copyRegisters( regs, req );

					if ( h && ( hndlFlags & ENABLE_CR ) ) {
						HVAction action = NONE;

						h->handleCR( req.vcpu_id, crNumber, regs, CR_OLD_VALUE( req ),
						             CR_NEW_VALUE( req ), action );

						if ( action == SKIP_INSTRUCTION || action == EMULATE_NOWRITE ) {
#if __XEN_LATEST_INTERFACE_VERSION__ >= 0x00040600
							rsp.flags |= MEM_EVENT_FLAG_DENY;
#else
							vcpu_guest_context_any_t ctx;

							if ( xc_vcpu_getcontext( xci_, domain_, req.vcpu_id, &ctx ) ==
							     0 ) {

								if ( logHelper_ )
									logHelper_->debug(
									        "Writing back old CR value" );

								ctx.c.ctrlreg[crNumber] = GLA( req ); // old value
								// write the old value back
								xc_vcpu_setcontext( xci_, domain_, req.vcpu_id, &ctx );
							}
#endif
						}
					}

					break;
				}

				case MEM_EVENT_REASON_MSR:

					if ( h && ( hndlFlags & ENABLE_MSR ) ) {

						HVAction action = NONE;

						bool msrEnabled = false;
						driver_.isMsrEnabled( MSR_TYPE( req ), msrEnabled );

						if ( msrEnabled ) {
							// old value == new value (can't get the old one)
							h->handleMSR( req.vcpu_id, MSR_TYPE( req ), MSR_VALUE( req ),
							              MSR_VALUE( req ), action );

							if ( action == SKIP_INSTRUCTION || action == EMULATE_NOWRITE )
								rsp.flags |= MEM_EVENT_FLAG_DENY;
						}
					}

					break;

				case MEM_EVENT_REASON_VMCALL: {
					Registers regs;
					copyRegisters( regs, req );

					if ( h && ( hndlFlags & ENABLE_VMCALL ) )
						h->handleVMCALL( req.vcpu_id, regs, VMCALL_RIP( req ),
						                 VMCALL_RAX( req ) );

					break;
				}

#if __XEN_LATEST_INTERFACE_VERSION__ < 0x00040600
				case MEM_EVENT_REASON_XSETBV:

					if ( h && ( hndlFlags & ENABLE_XSETBV ) )
						h->handleXSETBV( req.vcpu_id, GFN( req ) );

					break;
#endif
				default:
					// unknown reason code
					break;
			}

			resumePage( &rsp ); // will throw on error!
		}
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
	std::stringstream ss;
	ss << "/local/domain/0/device-model/" << domain_;

	watchToken_ = ss.str();

	xsh_ = xs_open( 0 );

	if ( !xsh_ )
		throw Exception( "[Xen events] xs_open() failed" );

	if ( !xs_watch( xsh_, "@releaseDomain", watchToken_.c_str() ) ||
	     !xs_watch( xsh_, watchToken_.c_str(), watchToken_.c_str() ) ) {
		xs_close( xsh_ );
		throw Exception( "[Xen events] xs_watch() failed" );
	}
}

void XenEventManager::initEventChannels()
{
	/* Open event channel */
	xce_ = xc_evtchn_open( NULL, 0 );

	if ( !xce_ ) {
		cleanup();
		throw Exception( "[Xen events] failed to open event channel" );
	}

	evtchnOn_ = true;

	/* Bind event notification */
	port_ = xc_evtchn_bind_interdomain( xce_, domain_, evtchnPort_ );

	if ( port_ < 0 ) {
		cleanup();
		throw Exception( "[Xen events] failed to bind event channel" );
	}

	evtchnBindOn_ = true;

/* Initialise ring */
#define private rprivate
	SHARED_RING_INIT( ( mem_event_sring_t * )ringPage_ );
	BACK_RING_INIT( &backRing_, ( mem_event_sring_t * )ringPage_, XC_PAGE_SIZE );
#undef private
}

#if __XEN_LATEST_INTERFACE_VERSION__ > 0x00040400

void XenEventManager::initMemAccess()
{
#if __XEN_LATEST_INTERFACE_VERSION__ == 0x00040500
	ringPage_ = xc_mem_access_enable_introspection( xci_, domain_, &evtchnPort_ );
#else // 406 or 407
	ringPage_ = xc_monitor_enable( xci_, domain_, &evtchnPort_ );
#endif

	if ( ringPage_ == NULL ) {
		cleanup();

		switch ( errno ) {
			case EBUSY:
				throw Exception( "[Xen events] the domain is either already connected "
				                 "with a monitoring application, or such an application crashed after "
				                 "connecting to it");
			case ENODEV:
				throw Exception( "[Xen events] EPT not supported for this guest" );
			default:
				throw Exception( "[Xen events] error initialising shared page" );
		}
	}

#if __XEN_LATEST_INTERFACE_VERSION__ >= 0x00040600
	xc_mem_access_enable_emulate( xci_, domain_ );
#endif

	memAccessOn_ = true;

	initEventChannels();

	xc_domain_set_access_required( xci_, domain_, 0 );

#if __XEN_LATEST_INTERFACE_VERSION__ >= 0x00040600
	xc_monitor_guest_request( xci_, domain_, 1, 1 );
	xc_monitor_write_ctrlreg( xci_, domain_, VM_EVENT_X86_XCR0, 1, 1, 1 );
#endif
}

#else

void XenEventManager::initMemAccess()
{
	/* Map the ring page */
	unsigned long ring_pfn;
	xc_get_hvm_param( xci_, domain_, HVM_PARAM_ACCESS_RING_PFN, &ring_pfn );

	unsigned long mmap_pfn = ring_pfn;
	ringPage_ = xc_map_foreign_batch( xci_, domain_, PROT_READ | PROT_WRITE, &mmap_pfn, 1 );

	if ( mmap_pfn & XEN_DOMCTL_PFINFO_XTAB ) {

		/* Map failed, populate ring page */
		if ( xc_domain_populate_physmap_exact( xci_, domain_, 1, 0, 0, &ring_pfn ) ) {
			cleanup();
			throw Exception( "[Xen events] failed to populate ring GFN" );
		}

		mmap_pfn = ring_pfn;
		ringPage_ = xc_map_foreign_batch( xci_, domain_, PROT_READ | PROT_WRITE, &mmap_pfn, 1 );

		if ( mmap_pfn & XEN_DOMCTL_PFINFO_XTAB ) {
			cleanup();
			throw Exception( "[Xen events] could not map the ring page" );
		}
	}

	if ( xc_mem_access_enable_introspection( xci_, domain_, &evtchnPort_ ) ) {
		cleanup();

		switch ( errno ) {
			case EBUSY:
				throw Exception( "[Xen events] the domain is either already connected "
				                 "with a monitoring application, or such an application crashed after "
				                 "connecting to it");
			case ENODEV:
				throw Exception( "[Xen events] EPT not supported for this guest" );
			default:
				throw Exception( "[Xen events] error initialising shared page" );
		}
	}

	memAccessOn_ = true;

	initEventChannels();

	/* Now that the ring is set, remove it from the guest's physmap */
	if ( xc_domain_decrease_reservation_exact( xci_, domain_, 1, 0, &ring_pfn ) ) {
		cleanup();
		throw Exception( "[Xen events] failed to remove ring from guest physmap" );
	}

	xc_domain_set_access_required( xci_, domain_, 0 );
}

#endif

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

		throw Exception( "[Xen events] poll() failed" );
	}

	if ( fd[0].revents & POLLIN ) { // a @releaseDomain event

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
	if ( fd[1].revents & POLLIN ) { // a mem_event
		int port = xc_evtchn_pending( xce_ );

		if ( port == -1 )
			throw Exception( "[Xen events] failed to read port from event channel" );

		if ( xc_evtchn_unmask( xce_, port ) != 0 )
			throw Exception( "[Xen events] failed to unmask event channel port" );

		return port;
	}
#endif

	// shouldn't be here
	throw Exception( "[Xen events] error getting event" );
}

void XenEventManager::getRequest( mem_event_request_t *req )
{
	mem_event_back_ring_t *back_ring;
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

void XenEventManager::putResponse( mem_event_response_t *rsp )
{
	mem_event_back_ring_t *back_ring;
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

void XenEventManager::resumePage( mem_event_response_t *rsp )
{
	/* Put the page info on the ring */
	putResponse( rsp );

/* Tell Xen page is ready */
#if __XEN_LATEST_INTERFACE_VERSION__ == 0x00040500
	xc_mem_access_resume( xci_, domain_ );
#elif __XEN_LATEST_INTERFACE_VERSION__ >= 0x00040600
// xc_monitor_resume(xci_, domain_);
#else
	xc_mem_access_resume( xci_, domain_, rsp->gfn );
#endif

	if ( xc_evtchn_notify( xce_, port_ ) < 0 )
		throw Exception( "[Xen events] error resuming page" );
}

std::string XenEventManager::uuid()
{
	return driver_.uuid();
}

} // namespace bdvmi
