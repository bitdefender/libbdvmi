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

#include "bdvmi/eventhandler.h"
#include "bdvmi/statscollector.h"
#include "bdvmi/xendriver.h"
#include "bdvmi/loghelper.h"
#include "bdvmi/xeninlines.h"
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <sys/mman.h>
#include <sys/resource.h>
#include <cpuid.h>

extern "C" {
#include <xen/xen-compat.h>
#if ( __XEN_LATEST_INTERFACE_VERSION__ < 0x00040600 )
#error unsupported Xen version
#endif
#include <xenstore.h>
#define private rprivate /* private is a C++ keyword */
#include <xen/vm_event.h>
#undef private
}

// #define DISABLE_PAGE_CACHE

#define X86_CR0_PE 0x00000001    /* Enable Protected Mode    (RW) */
#define X86_EFLAGS_VM 0x00020000 /* Virtual Mode */
#define _EFER_LMA 10             /* Long mode active (read-only) */
#define EFER_LMA ( 1 << _EFER_LMA )

#define CS_AR_BYTES_L ( 1 << 9 )
#define CS_AR_BYTES_D ( 1 << 10 )

#define TRAP_page_fault 14
#define X86_EVENTTYPE_HW_EXCEPTION 3 /* hardware exception */

#define paddr_to_pfn( pa ) ( ( unsigned long )( ( pa ) >> XC_PAGE_SHIFT ) )

namespace bdvmi {

#ifdef DISABLE_PAGE_CACHE
static bool check_page( void *addr )
{
	unsigned char vec[1] = {};

	// The page is not present or otherwise unavailable
	if ( mincore( addr, XC_PAGE_SIZE, vec ) < 0 || !( vec[0] & 0x01 ) )
		return false;

	return true;
}
#endif

XenDriver::XenDriver( domid_t domain, LogHelper *logHelper, bool hvmOnly, bool useAltP2m )
    : xci_( nullptr ), xsh_( nullptr ), domain_( domain ), pageCache_( logHelper ), guestWidth_( 8 ), logHelper_( logHelper ),
      useAltP2m_( useAltP2m ), altp2mViewId_( 0 ), update_( false ), xenVersionMajor_( 0 ), xenVersionMinor_( 0 ),
      startTime_( -1 ), patInitialized_( false ), msrPat_( 0 )
{
	init( domain, hvmOnly );
}

XenDriver::XenDriver( const std::string &uuid, LogHelper *logHelper, bool hvmOnly, bool useAltP2m )
    : xci_( nullptr ), xsh_( nullptr ), pageCache_( logHelper ), guestWidth_( 8 ), logHelper_( logHelper ),
      useAltP2m_( useAltP2m ), altp2mViewId_( 0 ), update_( false ), xenVersionMajor_( 0 ), xenVersionMinor_( 0 ),
      startTime_( -1 ), patInitialized_( false ), msrPat_( 0 )
{
	domain_ = getDomainId( uuid );
	init( domain_, hvmOnly );
}

XenDriver::~XenDriver()
{
	cleanup();
}

#define hvm_long_mode_enabled( regs ) ( regs.msr_efer & EFER_LMA )

int32_t XenDriver::guestX86Mode( const Registers &regs )
{
	if ( !( regs.cr0 & X86_CR0_PE ) )
		return 0;

	if ( regs.rflags & X86_EFLAGS_VM )
		return 1;

	if ( hvm_long_mode_enabled( regs ) && ( regs.cs_arbytes & CS_AR_BYTES_L ) )
		return 8;

	return ( ( regs.cs_arbytes & CS_AR_BYTES_D ) ? 4 : 2 );
}

bool XenDriver::cpuCount( unsigned int &count ) const
{
	xc_dominfo_t info;

	StatsCollector::instance().incStat( "xcDomainInfo" );

	if ( xc_domain_getinfo( xci_, domain_, 1, &info ) != 1 ) {

		if ( logHelper_ )
			logHelper_->error( std::string( "xc_domain_getinfo() failed: " ) + strerror( errno ) );

		return false;
	}

	count = info.max_vcpu_id + 1;
	// count = info.nr_online_vcpus;

	return true;
}

bool XenDriver::tscSpeed( unsigned long long &speed ) const
{
	uint64_t elapsed_nsec;
	uint32_t tsc_mode, gtsc_khz, incarnation;

	StatsCollector::instance().incStat( "xcTscInfo" );

	if ( xc_domain_get_tsc_info( xci_, domain_, &tsc_mode, &elapsed_nsec, &gtsc_khz, &incarnation ) != 0 ) {
		if ( logHelper_ )
			logHelper_->error( std::string( "xc_domain_get_tsc_info() failed: " ) + strerror( errno ) );

		return false;
	}

	// Convert to Hz (ticks / second)
	speed = gtsc_khz * 1000;
	return true;
}

bool XenDriver::setPageProtection( unsigned long long guestAddress, bool read, bool write, bool execute )
{
	xenmem_access_t memaccess = XENMEM_access_n;

	/*
	 * The Intel SDM says:
	 *
	 * AN EPT misconfiguration occurs if any of the following is identified while translating
	 * a guest-physical address:
	 *
	 * * The value of bits 2:0 of an EPT paging-structure entry is either 010b (write-only)
	 *   or 110b (write/execute).
	 *
	 */
	if ( write && !read ) {
		if ( logHelper_ ) {
			std::stringstream ss;
			ss << "Attempted to set GPA " << std::hex << std::showbase << guestAddress
				<< " " << ( read ? "r" : "-" ) << ( write ? "w" : "-" )
				<< ( execute ? "x" : "-" );

			logHelper_->error( ss.str() );
		}

		return false;
	}

	if ( read && !write && !execute )
		memaccess = XENMEM_access_r;

	else if ( !read && write && !execute )
		memaccess = XENMEM_access_w;

	else if ( !read && !write && execute )
		memaccess = XENMEM_access_x;

	else if ( read && write && !execute )
		memaccess = XENMEM_access_rw;

	else if ( read && !write && execute )
		memaccess = XENMEM_access_rx;

	else if ( !read && write && execute )
		memaccess = XENMEM_access_wx;

	else if ( read && write && execute )
		memaccess = XENMEM_access_rwx;

	unsigned long gfn = paddr_to_pfn( guestAddress );

	{
		std::lock_guard<std::mutex> guard( memAccessCacheMutex_ );

		memAccessCache_[gfn] = memaccess;

		if ( !useAltP2m_ ) {
#ifdef XENMEM_access_op_set_access_multi
			delayedMemAccessWrite_[gfn] = memaccess;
#else
#warning "XENMEM_access_op_set_access_multi is not available!"
			xc_set_mem_access( xci_, domain_, memaccess, gfn, 1 );
#endif
		} else {
#ifdef HVMOP_altp2m_set_mem_access_multi
			delayedMemAccessWrite_[gfn] = memaccess;
#else
#warning "HVMOP_altp2m_set_mem_access_multi is not available!"
			xc_altp2m_set_mem_access( xci_, domain_, altp2mViewId_, gfn, memaccess );
#endif
		}
	}

	return true;
}

void XenDriver::flushPageProtections()
{
	int rc = 0;

	std::lock_guard<std::mutex> guard( memAccessCacheMutex_ );

	if ( delayedMemAccessWrite_.empty() )
		return;

	std::vector<uint8_t> access;
	std::vector<uint64_t> gfns;

	for ( auto &&item : delayedMemAccessWrite_ ) {
		access.push_back( item.second );
		gfns.push_back( item.first );
	}

	StatsCollector::instance().incStat( "xcSetMemAccessMulti" );

	if ( !useAltP2m_ ) {
#ifdef XENMEM_access_op_set_access_multi
		rc = xc_set_mem_access_multi( xci_, domain_, &access[0], &gfns[0], gfns.size() );
#endif
	} else {
#ifdef HVMOP_altp2m_set_mem_access_multi
		rc = xc_altp2m_set_mem_access_multi( xci_, domain_, altp2mViewId_, &access[0], &gfns[0], gfns.size() );
#endif
	}

	if ( rc && logHelper_ )
		logHelper_->error( std::string( "xc_set_mem_access_multi() failed: " ) + strerror( errno ) );

	delayedMemAccessWrite_.clear();
}

bool XenDriver::getPageProtection( unsigned long long guestAddress, bool &read, bool &write, bool &execute )
{
	bool cached = false;
	xenmem_access_t memaccess;
	unsigned long gfn = paddr_to_pfn( guestAddress );

	{
		std::lock_guard<std::mutex> guard( memAccessCacheMutex_ );

		auto it = memAccessCache_.find( gfn );
		if ( it != memAccessCache_.end() ) {
			memaccess = it->second;
			cached = true;
		}
	}

	if ( !cached ) {
		StatsCollector::instance().incStat( "xcGetMemAccess" );

		if ( xc_get_mem_access( xci_, domain_, gfn, &memaccess ) ) {

			if ( logHelper_ )
				logHelper_->error( std::string( "xc_get_mem_access() failed: " ) + strerror( errno ) );

			return false;
		}
	}

	read = write = execute = false;

	switch ( memaccess ) {
		case XENMEM_access_r:
			read = true;
			break;

		case XENMEM_access_w:
			write = true;
			break;

		case XENMEM_access_rw:
			read = write = true;
			break;

		case XENMEM_access_x:
			execute = true;
			break;

		case XENMEM_access_rx:
			read = execute = true;
			break;

		case XENMEM_access_wx:
			write = execute = true;
			break;

		case XENMEM_access_rwx:
			read = write = execute = true;
			break;

		case XENMEM_access_rx2rw:      /* Page starts off as r-x, but automatically */
			read = execute = true; /* change to r-w on a write. */
			break;

		case XENMEM_access_n:
		default:
			break;
	}

	if ( !cached ) {
		std::lock_guard<std::mutex> guard( memAccessCacheMutex_ );

		memAccessCache_[gfn] = memaccess;
	}

	return true;
}

bool XenDriver::registers( unsigned short vcpu, Registers &regs ) const
{
	std::lock_guard<std::mutex> lock( regsCache_.mutex_ );

	if ( regsCache_.valid_ && regsCache_.vcpu_ == static_cast<int>( vcpu ) ) {
		regs = regsCache_.registers_;

		if ( !getPAT( vcpu, regs.msr_pat ) )
			return false;

		return true;
	}

	StatsCollector::instance().incStat( "partialContext" );
	StatsCollector::instance().incStat( "partialCpu" );

	struct hvm_hw_cpu hwCpu;

	if ( xc_domain_hvm_getcontext_partial( xci_, domain_, HVM_SAVE_CODE( CPU ), vcpu, &hwCpu, sizeof( hwCpu ) ) !=
	     0 ) {

		if ( logHelper_ ) {
			std::stringstream ss;
			ss << "xc_domain_hvm_getcontext_partial() (vcpu = " << vcpu << ") failed: " << strerror( errno );

			int savedErrno = errno;
			logHelper_->error( ss.str() );

			EventHandler *h = handler();

			if ( savedErrno == EINVAL && h )
				h->handleFatalError();
		}

		return false;
	}

	if ( !getPAT( vcpu, regs.msr_pat ) )
		return false;

	regs.sysenter_cs = hwCpu.sysenter_cs;
	regs.sysenter_esp = hwCpu.sysenter_esp;
	regs.sysenter_eip = hwCpu.sysenter_eip;
	regs.msr_efer = hwCpu.msr_efer;
	regs.msr_star = hwCpu.msr_star;
	regs.msr_lstar = hwCpu.msr_lstar;
	regs.msr_cstar = hwCpu.msr_cstar;
	regs.fs_base = hwCpu.fs_base;
	regs.gs_base = hwCpu.gs_base;
	regs.idtr_base = hwCpu.idtr_base;
	regs.idtr_limit = hwCpu.idtr_limit;
	regs.gdtr_base = hwCpu.gdtr_base;
	regs.gdtr_limit = hwCpu.gdtr_limit;
	regs.rflags = hwCpu.rflags;
	regs.rax = hwCpu.rax;
	regs.rcx = hwCpu.rcx;
	regs.rdx = hwCpu.rdx;
	regs.rbx = hwCpu.rbx;
	regs.rsp = hwCpu.rsp;
	regs.rbp = hwCpu.rbp;
	regs.rsi = hwCpu.rsi;
	regs.rdi = hwCpu.rdi;
	regs.r8 = hwCpu.r8;
	regs.r9 = hwCpu.r9;
	regs.r10 = hwCpu.r10;
	regs.r11 = hwCpu.r11;
	regs.r12 = hwCpu.r12;
	regs.r13 = hwCpu.r13;
	regs.r14 = hwCpu.r14;
	regs.r15 = hwCpu.r15;
	regs.rip = hwCpu.rip;
	regs.cr0 = hwCpu.cr0;
	regs.cr2 = hwCpu.cr2;
	regs.cr3 = hwCpu.cr3;
	regs.cr4 = hwCpu.cr4;
	regs.cr8 = 0; // can't get this with Xen / userspace
	regs.cs_arbytes = hwCpu.cs_arbytes;

	regs.cs_base = hwCpu.cs_base;
	regs.cs_limit = hwCpu.cs_limit;
	regs.cs_sel = hwCpu.cs_sel;
	regs.ss_base = hwCpu.ss_base;
	regs.ss_limit = hwCpu.ss_limit;
	regs.ss_sel = hwCpu.ss_sel;
	regs.ss_arbytes = hwCpu.ss_arbytes;
	regs.ds_base = hwCpu.ds_base;
	regs.ds_limit = hwCpu.ds_limit;
	regs.ds_sel = hwCpu.ds_sel;
	regs.ds_arbytes = hwCpu.ds_arbytes;
	regs.es_base = hwCpu.es_base;
	regs.es_limit = hwCpu.es_limit;
	regs.es_sel = hwCpu.es_sel;
	regs.es_arbytes = hwCpu.es_arbytes;
	regs.fs_limit = hwCpu.fs_limit;
	regs.fs_sel = hwCpu.fs_sel;
	regs.fs_arbytes = hwCpu.fs_arbytes;
	regs.gs_limit = hwCpu.gs_limit;
	regs.gs_sel = hwCpu.gs_sel;
	regs.gs_arbytes = hwCpu.gs_arbytes;
	regs.shadow_gs = hwCpu.shadow_gs;

	int32_t x86Mode = guestX86Mode( regs );

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

	if ( regsCache_.vcpu_ == static_cast<int>( vcpu ) ) {

		if ( delayedWrite_.pending_ ) {
			regs.rax = delayedWrite_.registers_.rax;
			regs.rcx = delayedWrite_.registers_.rcx;
			regs.rdx = delayedWrite_.registers_.rdx;
			regs.rbx = delayedWrite_.registers_.rbx;
			regs.rsp = delayedWrite_.registers_.rsp;
			regs.rbp = delayedWrite_.registers_.rbp;
			regs.rsi = delayedWrite_.registers_.rsi;
			regs.rdi = delayedWrite_.registers_.rdi;

			regs.r8 = delayedWrite_.registers_.r8;
			regs.r9 = delayedWrite_.registers_.r9;
			regs.r10 = delayedWrite_.registers_.r10;
			regs.r11 = delayedWrite_.registers_.r11;
			regs.r12 = delayedWrite_.registers_.r12;
			regs.r13 = delayedWrite_.registers_.r13;
			regs.r14 = delayedWrite_.registers_.r14;
			regs.r15 = delayedWrite_.registers_.r15;

			regs.rflags = delayedWrite_.registers_.rflags;
			regs.rip = delayedWrite_.registers_.rip;
		}

		regsCache_.registers_ = regs;
		regsCache_.valid_ = true;
	}

	return true;
}

bool XenDriver::setRegisters( unsigned short vcpu, const Registers &regs, bool setEip, bool delay )
{
	std::lock_guard<std::mutex> lock( regsCache_.mutex_ );

	if ( !delay ) {
		vcpu_guest_context_any_t ctxt;

		StatsCollector::instance().incStat( "xcGetVcpuContext" );

		if ( xc_vcpu_getcontext( xci_, domain_, vcpu, &ctxt ) != 0 ) {

			if ( logHelper_ )
				logHelper_->error( std::string( "xc_vcpu_getcontext() failed: " ) + strerror( errno ) );

			return false;
		}

		if ( guestWidth_ == 4 ) {

			ctxt.x32.user_regs.eax = regs.rax;
			ctxt.x32.user_regs.ecx = regs.rcx;
			ctxt.x32.user_regs.edx = regs.rdx;
			ctxt.x32.user_regs.ebx = regs.rbx;
			ctxt.x32.user_regs.esp = regs.rsp;
			ctxt.x32.user_regs.ebp = regs.rbp;
			ctxt.x32.user_regs.esi = regs.rsi;
			ctxt.x32.user_regs.edi = regs.rdi;
			ctxt.x32.user_regs.eflags = regs.rflags;

			if ( setEip )
				ctxt.x32.user_regs.eip = regs.rip;

		} else {

			ctxt.x64.user_regs.rax = regs.rax;
			ctxt.x64.user_regs.rcx = regs.rcx;
			ctxt.x64.user_regs.rdx = regs.rdx;
			ctxt.x64.user_regs.rbx = regs.rbx;
			ctxt.x64.user_regs.rsp = regs.rsp;
			ctxt.x64.user_regs.rbp = regs.rbp;
			ctxt.x64.user_regs.rsi = regs.rsi;
			ctxt.x64.user_regs.rdi = regs.rdi;
			ctxt.x64.user_regs.r8 = regs.r8;
			ctxt.x64.user_regs.r9 = regs.r9;
			ctxt.x64.user_regs.r10 = regs.r10;
			ctxt.x64.user_regs.r11 = regs.r11;
			ctxt.x64.user_regs.r12 = regs.r12;
			ctxt.x64.user_regs.r13 = regs.r13;
			ctxt.x64.user_regs.r14 = regs.r14;
			ctxt.x64.user_regs.r15 = regs.r15;
			ctxt.x64.user_regs.rflags = regs.rflags;

			if ( setEip )
				ctxt.x64.user_regs.eip = regs.rip;
		}

		StatsCollector::instance().incStat( "xcSetContext" );

		if ( xc_vcpu_setcontext( xci_, domain_, vcpu, &ctxt ) == -1 ) {

			if ( logHelper_ )
				logHelper_->error( std::string( "xc_vcpu_setcontext() failed: " ) + strerror( errno ) );

			return false;
		}
	} else {
		delayedWrite_.registers_ = regs;

		if ( !setEip )
			delayedWrite_.registers_.rip = regs.rip + 3; // 3 is the size of the VMCALL opcodes
				// ( ( guestWidth_ == 4 ) ? ctxt.x32.user_regs.eip : ctxt.x64.user_regs.eip );

		delayedWrite_.pending_ = true;
	}

	if ( regsCache_.valid_ && regsCache_.vcpu_ == static_cast<int>( vcpu ) ) {
		regsCache_.registers_.rax = regs.rax;
		regsCache_.registers_.rcx = regs.rcx;
		regsCache_.registers_.rdx = regs.rdx;
		regsCache_.registers_.rbx = regs.rbx;
		regsCache_.registers_.rsp = regs.rsp;
		regsCache_.registers_.rbp = regs.rbp;
		regsCache_.registers_.rsi = regs.rsi;
		regsCache_.registers_.rdi = regs.rdi;

		regsCache_.registers_.r8 = regs.r8;
		regsCache_.registers_.r9 = regs.r9;
		regsCache_.registers_.r10 = regs.r10;
		regsCache_.registers_.r11 = regs.r11;
		regsCache_.registers_.r12 = regs.r12;
		regsCache_.registers_.r13 = regs.r13;
		regsCache_.registers_.r14 = regs.r14;
		regsCache_.registers_.r15 = regs.r15;

		regsCache_.registers_.rflags = regs.rflags;

		if ( setEip )
			regsCache_.registers_.rip = regs.rip;
	}

	return true;
}

bool XenDriver::writeToPhysAddress( unsigned long long address, void *buffer, size_t /*length*/ )
{
	unsigned long gfn = paddr_to_pfn( address );
	unsigned long mfn = paddr_to_pfn( ( unsigned long )buffer );

	StatsCollector::instance().incStat( "xcCopyPage" );

	// Copy the whole page - can't find another way to do it with libxc.
	if ( xc_copy_to_domain_page( xci_, domain_, gfn, ( const char * )mfn ) ) {

		if ( logHelper_ )
			logHelper_->error( std::string( "xc_copy_to_domain_page() failed: " ) + strerror( errno ) );

		return false;
	}

	return true;
}

bool XenDriver::shutdown()
{
	if ( xc_domain_shutdown( xci_, domain_, SHUTDOWN_poweroff ) ) {

		if ( logHelper_ )
			logHelper_->error( std::string( "xc_domain_shutdown() failed: " ) + strerror( errno ) );

		return false;
	}

	return true;
}

void XenDriver::init( domid_t domain, bool hvmOnly )
{
	xci_ = xc_interface_open( nullptr, nullptr, 0 );

	if ( !xci_ ) {
		cleanup();
		throw std::runtime_error( "xc_interface_open() failed" );
	}

	xc_dominfo_t info;

	StatsCollector::instance().incStat( "xcDomainInfo" );

	if ( xc_domain_getinfo( xci_, domain, 1, &info ) != 1 ) {
		cleanup();
		throw std::runtime_error( "xc_domain_getinfo() failed" );
	}

	std::stringstream ss;

	if ( hvmOnly && !info.hvm ) {
		cleanup();
		ss << "Domain " << domain << " is not a HVM guest";
		throw std::runtime_error( ss.str() );
	}

	// xc_domain_set_cores_per_socket( xci_, domain, 10 );

	xen_capabilities_info_t caps;

	if ( xc_version( xci_, XENVER_capabilities, &caps /*, sizeof( caps ) */ ) != 0 ) {
		cleanup();
		throw std::runtime_error( "Could not get Xen capabilities" );
	}

	long xenVersion = xc_version( xci_, XENVER_version, nullptr );
	xenVersionMajor_ = xenVersion >> 16;
	xenVersionMinor_ = xenVersion & 0xFF;

	guestWidth_ = strstr( caps, "x86_64" ) ? 8 : 4;

	if ( !xsh_ ) {
		xsh_ = xs_open( 0 );

		if ( !xsh_ ) {
			cleanup();
			throw std::runtime_error( "xs_open() failed" );
		}
	}

	pageCache_.init( xci_, domain );

	unsigned int size;

	ss.str( "" );
	ss << "/local/domain/" << domain_ << "/vm";

	char *path = static_cast<char *>( xs_read_timeout( xsh_, XBT_NULL, ss.str().c_str(), &size, 1 ) );

	if ( path && path[0] != '\0' ) {
		ss.str( "" );
		ss << path << "/uuid";

		free( path );
		size = 0;

		path = static_cast<char *>( xs_read_timeout( xsh_, XBT_NULL, ss.str().c_str(), &size, 1 ) );

		if ( path && path[0] != '\0' )
			uuid_ = path;
	}

	free( path );

	/*
	xen_pfn_t max_gpfn = 0;

	xc_domain_maximum_gpfn( xci_, domain_, &max_gpfn );

	if ( logHelper_ ) {
		ss.str("");
		ss << "maximum_gpfn: 0x" << std::hex << max_gpfn;
		logHelper_->debug(ss.str());
	}
	*/

	if ( useAltP2m_ ) {
		if ( xc_altp2m_set_domain_state( xci_, domain_, 1 ) < 0 ) {
			cleanup();
			throw std::runtime_error( std::string( "[ALTP2M] could not enable altp2m on domain: " ) +
			                          strerror( errno ) );
		}

		if ( xc_altp2m_create_view( xci_, domain_, XENMEM_access_rwx, &altp2mViewId_ ) < 0 ) {
			cleanup();
			throw std::runtime_error( "[ALTP2M] could not create altp2m view" );
		}

		xen_pfn_t max_gpfn = 0;

		xc_domain_maximum_gpfn( xci_, domain_, &max_gpfn );

		for ( xen_pfn_t gfn = 0; gfn < max_gpfn; ++gfn )
			xc_altp2m_set_mem_access( xci_, domain_, altp2mViewId_, gfn, XENMEM_access_rwx );

		if ( xc_altp2m_switch_to_view( xci_, domain_, altp2mViewId_ ) < 0 ) {
			cleanup();
			throw std::runtime_error( "[ALTP2M] could not switch to altp2m view" );
		}
	}
}

void XenDriver::cleanup()
{
	if ( useAltP2m_ ) {
		if ( altp2mViewId_ ) {
			xc_altp2m_switch_to_view( xci_, domain_, 0 );
			xc_altp2m_destroy_view( xci_, domain_, altp2mViewId_ );
		}

		xc_altp2m_set_domain_state( xci_, domain_, 0 );
	}

	if ( xci_ ) {
		xc_interface_close( xci_ );
		xci_ = nullptr;
	}

	if ( xsh_ ) {
		xs_close( xsh_ );
		xsh_ = nullptr;
	}
}

domid_t XenDriver::getDomainId( const std::string &uuid )
{
	domid_t domainId = 0;

	if ( !xsh_ ) {
		xsh_ = xs_open( 0 );

		if ( !xsh_ ) {
			cleanup();
			throw std::runtime_error( "xs_open() failed" );
		}
	}

	unsigned int size = 0;
	char **domains = xs_directory( xsh_, XBT_NULL, "/local/domain", &size );

	if ( size == 0 ) {
		cleanup();
		throw std::runtime_error( std::string( "Failed to retrieve domain ID by UUID [" ) + uuid + "]: " +
		                          strerror( errno ) );
	}

	for ( unsigned int i = 0; i < size; ++i ) {

		std::string tmp = std::string( "/local/domain/" ) + domains[i] + "/vm";

		char *path = static_cast<char *>( xs_read_timeout( xsh_, XBT_NULL, tmp.c_str(), nullptr, 1 ) );

		if ( path && path[0] != '\0' ) {
			tmp = std::string( path ) + "/uuid";

			char *tmpUuid = static_cast<char *>( xs_read_timeout( xsh_, XBT_NULL, tmp.c_str(), nullptr, 1 ) );

			if ( tmpUuid && uuid == tmpUuid ) {
				domainId = atoi( domains[i] );
				free( tmpUuid );
				free( path );
				break;
			}

			free( tmpUuid );
		}

		free( path );
	}

	free( domains );

	return domainId;
}

MapReturnCode XenDriver::mapPhysMemToHost( unsigned long long address, size_t length, uint32_t /*flags*/,
                                           void *&pointer )
{
	// one-page limit
	if ( ( address & XC_PAGE_MASK ) != ( ( address + length - 1 ) & XC_PAGE_MASK ) )
		return MAP_INVALID_PARAMETER;

	pointer = nullptr;
	unsigned long gfn = paddr_to_pfn( address );

	try {

		void *mapped = nullptr;

#ifdef DISABLE_PAGE_CACHE
		StatsCollector::instance().incStat( "xcMapPage" );

		mapped = xc_map_foreign_range( xci_, domain_, XC_PAGE_SIZE, PROT_READ | PROT_WRITE, gfn );

		/*
		if ( !mapped && logHelper_ ) {

		        std::stringstream ss;
		        ss << "xc_map_foreign_range(0x" << std::setfill( '0' ) << std::setw( 16 ) << std::hex << gfn
		           << ") failed: " << strerror( errno );

		        logHelper_->error( ss.str() );
		}
		*/

		if ( mapped && !check_page( mapped ) ) {
			munmap( mapped, XC_PAGE_SIZE );
			return MAP_PAGE_NOT_PRESENT;
		}
#else
		MapReturnCode mrc = pageCache_.update( gfn, mapped );

		if ( mrc != MAP_SUCCESS )
			return mrc;
#endif

		if ( !mapped ) {

			if ( logHelper_ ) {
				std::stringstream ss;
				ss << "address: 0x" << std::setfill( '0' ) << std::setw( 16 ) << std::hex << address
				   << ", length: " << length;

				logHelper_->error( ss.str() );
			}

			return MAP_FAILED_GENERIC;
		}

		pointer = static_cast<char *>( mapped ) + ( address & ~XC_PAGE_MASK );
	} catch ( ... ) {
		return MAP_FAILED_GENERIC;
	}

	return MAP_SUCCESS;
}

bool XenDriver::unmapPhysMem( void *hostPtr )
{
	void *map = hostPtr;
	map = ( void * )( ( long int )map & XC_PAGE_MASK );

#ifdef DISABLE_PAGE_CACHE
	munmap( map, XC_PAGE_SIZE );
#else
	pageCache_.release( map );
#endif

	return true;
}

MapReturnCode XenDriver::mapVirtMemToHost( unsigned long long address, size_t length, uint32_t /* flags */,
                                           unsigned short vcpu, void *&pointer )
{
	// one-page limit
	if ( ( address & XC_PAGE_MASK ) != ( ( address + length - 1 ) & XC_PAGE_MASK ) )
		return MAP_INVALID_PARAMETER;

	unsigned long gfn;
	pointer = nullptr;

	try {
		gfn = xc_translate_foreign_address( xci_, domain_, vcpu, address );

		if ( gfn == 0 ) {

			if ( logHelper_ && errno && errno != EADDRNOTAVAIL ) {
				std::stringstream ss;

				ss << "xc_translate_foreign_address(0x" << std::setfill( '0' )
				   << std::setw( 16 ) << std::hex << address << ") (vcpu = " << vcpu
				   << ") failed: " << strerror( errno );

				logHelper_->error( ss.str() );
			}

			return MAP_FAILED_GENERIC;
		}

		void *mapped = nullptr;

#ifdef DISABLE_PAGE_CACHE
		StatsCollector::instance().incStat( "xcMapPage" );

		mapped = xc_map_foreign_range( xci_, domain_, XC_PAGE_SIZE, PROT_READ | PROT_WRITE, gfn );

		if ( mapped && !check_page( mapped ) ) {
			munmap( mapped, XC_PAGE_SIZE );
			return MAP_PAGE_NOT_PRESENT;
		}
#else
		MapReturnCode mrc = pageCache_.update( gfn, mapped );

		if ( mrc != MAP_SUCCESS )
			return mrc;
#endif

		if ( !mapped ) {

			if ( logHelper_ ) {
				std::stringstream ss;
				ss << "address: 0x" << std::setfill( '0' ) << std::setw( 16 ) << std::hex << address
				   << ", length: " << length;

				logHelper_->error( ss.str() );
			}

			return MAP_FAILED_GENERIC;
		}

		pointer = static_cast<char *>( mapped ) + ( address & ~XC_PAGE_MASK );
	} catch ( ... ) {
		return MAP_FAILED_GENERIC;
	}

	return MAP_SUCCESS;
}

bool XenDriver::unmapVirtMem( void *hostPtr )
{
	return unmapPhysMem( hostPtr );
}

bool XenDriver::requestPageFault( int vcpu, uint64_t /* addressSpace */, uint64_t virtualAddress,
                                  uint32_t errorCode )
{
	// It is assumed that the guest is in user-mode and in the proper
	// address space for "vcpu" here - otherwise things will likely
	// explode. If something does explode here, check that those
	// conditions hold HV-side.
	if ( xc_hvm_inject_trap( xci_, domain_, vcpu, TRAP_page_fault, X86_EVENTTYPE_HW_EXCEPTION, errorCode, 0,
	                         virtualAddress /*, addressSpace */ ) != 0 ) {
		if ( logHelper_ )
			logHelper_->error( std::string( "xc_hvm_inject_trap() failed: " ) + strerror( errno ) );

		return false;
	}

	pendingInjections_[vcpu] = true;

	return true;
}

bool XenDriver::setRepOptimizations( bool enable )
{
#ifdef XEN_DOMCTL_MONITOR_OP_EMULATE_EACH_REP
	if ( xc_monitor_emulate_each_rep( xci_, domain_, enable ? 0 : 1 ) != 0 ) {
		if ( logHelper_ )
			logHelper_->error( std::string( "xc_monitor_emulate_each_rep() failed: " ) +
			                   strerror( errno ) );

		return false;
	}

	return true;
#else
	return false;
#endif
}

bool XenDriver::pause()
{
	if ( xc_domain_pause( xci_, domain_ ) != 0 ) {

		if ( logHelper_ )
			logHelper_->error( std::string( "xc_domain_pause() failed: " ) + strerror( errno ) );

		return false;
	}

	return true;
}

bool XenDriver::unpause()
{
	if ( xc_domain_unpause( xci_, domain_ ) != 0 ) {

		if ( logHelper_ )
			logHelper_->error( std::string( "xc_domain_unpause() failed: " ) + strerror( errno ) );

		return false;
	}

	update_ = true;

	return true;
}

bool XenDriver::update()
{
	if ( !update_ )
		return true;

	std::stringstream ss;
	ss << "/local/domain/" << domain_ << "/data/updated";

	xs_write( xsh_, XBT_NULL, ss.str().c_str(), "now", 3 );

	update_ = false;

	return true;
}

bool XenDriver::setPageCacheLimit( size_t limit )
{
	return pageCache_.setLimit( limit );
}

bool XenDriver::getPAT( unsigned short vcpu, uint64_t &pat ) const
{
	if ( patInitialized_ ) {
		pat = msrPat_;
		return true;
	}

	StatsCollector::instance().incStat( "partialContext" );
	StatsCollector::instance().incStat( "partialMtrr" );

	struct hvm_hw_mtrr hwMtrr;

	if ( xc_domain_hvm_getcontext_partial( xci_, domain_, HVM_SAVE_CODE( MTRR ),
                                               vcpu, &hwMtrr, sizeof( hwMtrr ) ) != 0 ) {
		if ( logHelper_ ) {
			std::stringstream ss;
			ss << "xc_domain_hvm_getcontext_partial() (vcpu = " << vcpu << ") failed: "
				<< strerror( errno );

			int savedErrno = errno;
			logHelper_->error( ss.str() );

			EventHandler *h = handler();

			if ( savedErrno == EINVAL && h )
				h->handleFatalError();
		}

		return false;
	}

	pat = msrPat_ = hwMtrr.msr_pat_cr;
	patInitialized_ = true;

	return true;
}

bool XenDriver::getXCR0( unsigned short vcpu, uint64_t &xcr0 ) const
{
	int ret = xc_domain_pause( xci_, domain_ );

	if ( ret < 0 )
		return false;

	// Get buffer length (0 argument)
	ret = xc_domain_hvm_getcontext( xci_, domain_, 0, 0 );

	if ( ret < 0 ) {
		xc_domain_unpause( xci_, domain_ );
		return false;
	}

	uint32_t len = ret;
	std::vector<uint8_t> buf( len );

	ret = xc_domain_hvm_getcontext( xci_, domain_, &buf[0], len );

	if ( ret < 0 ) {
		if ( logHelper_ )
			logHelper_->error( std::string( "xc_domain_hvm_getcontext() failed: " ) + strerror( errno ) );
		xc_domain_unpause( xci_, domain_ );
		return false;
	}

	uint32_t off = 0;
	bool found = false;

	while ( off < len ) {
		struct hvm_save_descriptor *descriptor = ( struct hvm_save_descriptor * )( &buf[0] + off );

		off += sizeof( struct hvm_save_descriptor );

		if ( descriptor->typecode == HVM_SAVE_CODE( END ) )
			break;

		if ( descriptor->typecode == CPU_XSAVE_CODE && descriptor->instance == vcpu ) {
			struct hvm_hw_cpu_xsave *hwCpuXSAVE = ( struct hvm_hw_cpu_xsave * )( &buf[0] + off );
			xcr0 = hwCpuXSAVE->xcr0;
			found = true;
		}

		off += descriptor->length;
	}

	xc_domain_unpause( xci_, domain_ );

	return found;
}

#define XCR0_X87 0x00000001 /* x87 FPU/MMX state */
#define XCR0_SSE 0x00000002 /* SSE state */

bool XenDriver::getXSAVESize( unsigned short vcpu, size_t &size )
{
	uint64_t featureMask = 0;
	unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
	uint32_t localSize = 512 + 64;

	if ( !getXCR0( vcpu, featureMask ) ) {
		if ( logHelper_ )
			logHelper_->error( "could not query XCR0, can't get the XSAVE size" );

		return false;
	}

	size = 0;

	// Get the supported features bit mask.
	__cpuid_count( 0xD, 0, eax, ebx, ecx, edx );

	// Clear out mandatory bits - XCR0_X87 and XCR0_SSE.
	// Also, clear out any invalid/unsupported bit.
	featureMask &= ~( XCR0_X87 | XCR0_SSE ) & ( ( ( uint64_t )edx << 32 ) | ( uint64_t )eax );

	for ( unsigned int i = 0; i < 64; ++i ) {

		if ( ( featureMask & ( 0x1 << i ) ) == 0 )
			continue;

		eax = ebx = edx = ecx = 0;

		__cpuid_count( 0xD, i, eax, ebx, ecx, edx );

		if ( ( uint32_t )eax + ( uint32_t )ebx > localSize )
			localSize = ( uint32_t )eax + ( uint32_t )ebx;
	}

	size = localSize;

	return true;
}

void XenDriver::enableCache( unsigned short vcpu )
{
	std::lock_guard<std::mutex> lock( regsCache_.mutex_ );
	regsCache_.vcpu_ = vcpu;
	regsCache_.valid_ = false;
}

void XenDriver::disableCache()
{
	std::lock_guard<std::mutex> lock( regsCache_.mutex_ );
	regsCache_.vcpu_ = -1;
	regsCache_.valid_ = false;
}

bool XenDriver::pendingInjection( unsigned short vcpu ) const
{
	auto i = pendingInjections_.find( vcpu );

	if ( i == pendingInjections_.end() )
		return false;

	return i->second;
}

void XenDriver::clearInjection( unsigned short vcpu )
{
	pendingInjections_[vcpu] = false;
}

uint32_t XenDriver::startTime()
{
	if ( startTime_ != ( uint32_t )-1 )
		return startTime_;

	unsigned int size = 0;
	std::stringstream ss;

	ss << "/local/domain/" << domain_ << "/vm";

	char *path = static_cast<char *>( xs_read_timeout( xsh_, XBT_NULL, ss.str().c_str(), &size, 1 ) );

	if ( path && path[0] != '\0' ) {
		ss.str( "" );
		ss << path << "/start_time";

		std::string path1 = ss.str();

		ss.str( "" );
		ss << path << "/domains/" << domain_ << "/create-time";

		std::string path2 = ss.str();

		free( path );
		size = 0;

		path = static_cast<char *>( xs_read_timeout( xsh_, XBT_NULL, path1.c_str(), &size, 1 ) );

		if ( path  && path[0] != '\0' )
			startTime_ = strtoul( path, nullptr, 10 );

		free( path );
		path = nullptr;
		size = 0;

		if ( startTime_ == ( uint32_t )-1 ) // XenServer
			path = static_cast<char *>( xs_read_timeout( xsh_, XBT_NULL, path2.c_str(), &size, 1 ) );

		if ( path  && path[0] != '\0' )
			startTime_ = strtoul( path, nullptr, 10 );
	}

	free( path );

	return startTime_;
}

} // namespace bdvmi
