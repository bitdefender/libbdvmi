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

#include "bdvmi/eventhandler.h"
#include <bdvmi/logger.h>
#include "bdvmi/statscollector.h"
#include "utils.h"
#include "xcwrapper.h"
#include "xendriver.h"
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <stdexcept>
#include <vector>
#include <sys/mman.h>
#include <sys/resource.h>
#include <cpuid.h>

// #define DISABLE_PAGE_CACHE

#define X86_CR0_PE 0x00000001    /* Enable Protected Mode    (RW) */
#define X86_EFLAGS_VM 0x00020000 /* Virtual Mode */
#define _EFER_LMA 10             /* Long mode active (read-only) */
#define EFER_LMA ( 1 << _EFER_LMA )

#define CS_AR_BYTES_L ( 1 << 9 )
#define CS_AR_BYTES_D ( 1 << 10 )

#define MTRR_PHYSMASK_VALID_BIT 11
#define MTRR_PHYSMASK_SHIFT 12
#define MTRR_PHYSBASE_TYPE_MASK 0xff

#define TRAP_page_fault 14
#define X86_EVENTTYPE_HW_EXCEPTION 3 /* hardware exception */

namespace bdvmi {

#ifdef DISABLE_PAGE_CACHE
static bool check_page( void *addr )
{
	unsigned char vec[1] = {};

	// The page is not present or otherwise unavailable
	if ( mincore( addr, XC::pageSize, vec ) < 0 || !( vec[0] & 0x01 ) )
		return false;

	return true;
}
#endif

using namespace std::placeholders;

XenDriver::XenDriver( domid_t domain, bool altp2m, bool hvmOnly )
    : domain_{ domain }, pageCache_{ this }, altp2mState_{ xc_, domain, altp2m }
{
	getMemAccess_ = [this]( unsigned long long gpa, xenmem_access_t *access, unsigned short ) {
		return xc_.getMemAccess( domain_, gpa, access );
	};

	if ( altp2mState_ ) {
		setMemAccess_ = [this]( const MemAccessMap &map, unsigned short view ) {
			return xc_.altp2mSetMemAccess( domain_, view, map );
		};

		if ( xc_.altp2mGetMemAccess )
			getMemAccess_ = [this]( unsigned long long gpa, xenmem_access_t *access, unsigned short view ) {
				return xc_.altp2mGetMemAccess( domain_, view, gpa, access );
			};
	} else {
		setMemAccess_ = [this]( const MemAccessMap &map, unsigned short ) {
			return xc_.setMemAccess( domain_, map );
		};
	}

	init( domain, hvmOnly );
}

XenDriver::XenDriver( const std::string &uuid, bool altp2m, bool hvmOnly )
    : XenDriver{ XenDriver::getDomainId( uuid ), altp2m, hvmOnly }
{
}

XenDriver::~XenDriver()
{
	// We need this here because pageCache will be destroyed _after_ XenDriver, but
	// PageCache::reset() still makes use of its driver_ pointer. So reset() here instead,
	// then clear the pointer.
	pageCache_.reset();
	pageCache_.driver( nullptr );
}

#define hvm_long_mode_enabled( regs ) ( regs.msr_efer & EFER_LMA )

int32_t XenDriver::guestX86Mode( const Registers &regs )
{
	if ( !( regs.cr0 & X86_CR0_PE ) )
		return 2;

	if ( regs.rflags & X86_EFLAGS_VM )
		return 2;

	if ( hvm_long_mode_enabled( regs ) && ( regs.cs_arbytes & CS_AR_BYTES_L ) )
		return 8;

	return ( ( regs.cs_arbytes & CS_AR_BYTES_D ) ? 4 : 2 );
}

bool XenDriver::cpuCount( unsigned int &count ) const
{
	XenDomainInfo info;

	StatsCounter counter( "xcDomainInfo" );

	if ( xc_.domainGetInfo( domain_, info ) != 1 ) {
		logger << ERROR << "xc_domain_getinfo() failed: " << strerror( errno ) << std::flush;
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

	StatsCounter counter( "xcTscInfo" );

	if ( xc_.domainGetTscInfo( domain_, &tsc_mode, &elapsed_nsec, &gtsc_khz, &incarnation ) != 0 ) {
		logger << ERROR << "xc_domain_get_tsc_info() failed: " << strerror( errno ) << std::flush;
		return false;
	}

	// Convert to Hz (ticks / second)
	speed = gtsc_khz * 1000;
	return true;
}

bool XenDriver::setPageProtectionImpl( const MemAccessMap &accessMap, unsigned short view )
{
	if ( accessMap.empty() )
		return true;

	if ( setMemAccess_( accessMap, view ) ) {
		logger << ERROR << "XenDriver::setPageProtectionImpl() failed: " << strerror( errno ) << std::flush;
		return false;
	}

	return true;
}

bool XenDriver::getPageProtectionImpl( unsigned long long guestAddress, bool &read, bool &write, bool &execute,
                                       unsigned short view )
{
	xenmem_access_t memaccess;
	unsigned long   gfn = gpa_to_gfn( guestAddress );

	StatsCounter counter( "xcGetMemAccess" );

	if ( getMemAccess_( gfn, &memaccess, view ) ) {
		if ( errno != ESRCH )
			logger << ERROR << "xc_get_mem_access() failed: " << strerror( errno ) << std::flush;
		return false;
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

	return true;
}

bool XenDriver::registers( unsigned short vcpu, Registers &regs ) const
{
	std::lock_guard<std::mutex> lock( regsCache_.mutex_ );

	regs = Registers(); // Fill it up with default values.

	if ( regsCache_.valid_ && regsCache_.vcpu_ == static_cast<int>( vcpu ) ) {
		regs = regsCache_.registers_;

		if ( !getPAT( vcpu, regs.msr_pat ) )
			return false;

		return true;
	}

	StatsCounter ctxCounter( "partialContext" );
	StatsCounter cpuCounter( "partialCpu" );

	struct hvm_hw_cpu hwCpu;

	if ( xc_.domainHvmGetContextPartial( domain_, HVM_SAVE_CODE( CPU ), vcpu, &hwCpu, sizeof( hwCpu ) ) != 0 ) {
		EventHandler *h          = handler();
		int           savedErrno = errno;

		logger << ERROR << "xc_domain_hvm_getcontext_partial() (vcpu = " << vcpu
		       << ") failed: " << strerror( errno ) << std::flush;

		if ( savedErrno == EINVAL && h )
			h->handleFatalError();

		// If errno is ENODATA, it means that the VCPU is offline (Xen convention), so no data could
		// be retrieved for it. Introcore insists that it wants to be able to query data for offline
		// (but valid) VCPUs as well, and Xen insists that this query should not be allowed, hence
		// this compromise: in that case, serve some default values.
		return savedErrno == ENODATA;
	}

	if ( !getPAT( vcpu, regs.msr_pat ) )
		return false;

	regs.sysenter_cs  = hwCpu.sysenter_cs;
	regs.sysenter_esp = hwCpu.sysenter_esp;
	regs.sysenter_eip = hwCpu.sysenter_eip;
	regs.msr_efer     = hwCpu.msr_efer;
	regs.msr_star     = hwCpu.msr_star;
	regs.msr_lstar    = hwCpu.msr_lstar;
	regs.msr_cstar    = hwCpu.msr_cstar;
	regs.fs_base      = hwCpu.fs_base;
	regs.gs_base      = hwCpu.gs_base;
	regs.idtr_base    = hwCpu.idtr_base;
	regs.idtr_limit   = hwCpu.idtr_limit;
	regs.gdtr_base    = hwCpu.gdtr_base;
	regs.gdtr_limit   = hwCpu.gdtr_limit;
	regs.rflags       = hwCpu.rflags;
	regs.rax          = hwCpu.rax;
	regs.rcx          = hwCpu.rcx;
	regs.rdx          = hwCpu.rdx;
	regs.rbx          = hwCpu.rbx;
	regs.rsp          = hwCpu.rsp;
	regs.rbp          = hwCpu.rbp;
	regs.rsi          = hwCpu.rsi;
	regs.rdi          = hwCpu.rdi;
	regs.r8           = hwCpu.r8;
	regs.r9           = hwCpu.r9;
	regs.r10          = hwCpu.r10;
	regs.r11          = hwCpu.r11;
	regs.r12          = hwCpu.r12;
	regs.r13          = hwCpu.r13;
	regs.r14          = hwCpu.r14;
	regs.r15          = hwCpu.r15;
	regs.rip          = hwCpu.rip;
	regs.cr0          = hwCpu.cr0;
	regs.cr2          = hwCpu.cr2;
	regs.cr3          = hwCpu.cr3;
	regs.cr4          = hwCpu.cr4;
	regs.cs_arbytes   = hwCpu.cs_arbytes;

	regs.cs_base    = hwCpu.cs_base;
	regs.cs_limit   = hwCpu.cs_limit;
	regs.cs_sel     = hwCpu.cs_sel;
	regs.ss_base    = hwCpu.ss_base;
	regs.ss_limit   = hwCpu.ss_limit;
	regs.ss_sel     = hwCpu.ss_sel;
	regs.ss_arbytes = hwCpu.ss_arbytes;
	regs.ds_base    = hwCpu.ds_base;
	regs.ds_limit   = hwCpu.ds_limit;
	regs.ds_sel     = hwCpu.ds_sel;
	regs.ds_arbytes = hwCpu.ds_arbytes;
	regs.es_base    = hwCpu.es_base;
	regs.es_limit   = hwCpu.es_limit;
	regs.es_sel     = hwCpu.es_sel;
	regs.es_arbytes = hwCpu.es_arbytes;
	regs.fs_limit   = hwCpu.fs_limit;
	regs.fs_sel     = hwCpu.fs_sel;
	regs.fs_arbytes = hwCpu.fs_arbytes;
	regs.gs_limit   = hwCpu.gs_limit;
	regs.gs_sel     = hwCpu.gs_sel;
	regs.gs_arbytes = hwCpu.gs_arbytes;
	regs.shadow_gs  = hwCpu.shadow_gs;

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

			regs.r8  = delayedWrite_.registers_.r8;
			regs.r9  = delayedWrite_.registers_.r9;
			regs.r10 = delayedWrite_.registers_.r10;
			regs.r11 = delayedWrite_.registers_.r11;
			regs.r12 = delayedWrite_.registers_.r12;
			regs.r13 = delayedWrite_.registers_.r13;
			regs.r14 = delayedWrite_.registers_.r14;
			regs.r15 = delayedWrite_.registers_.r15;

			regs.rflags = delayedWrite_.registers_.rflags;
			regs.rip    = delayedWrite_.registers_.rip;
		}

		regsCache_.registers_ = regs;
		regsCache_.valid_     = true;
	}

	return true;
}

bool XenDriver::setRegisters( unsigned short vcpu, const Registers &regs, bool setEip, bool delay )
{
	std::lock_guard<std::mutex> lock( regsCache_.mutex_ );

	if ( !delay ) {
		if ( xc_.vcpuSetRegisters( domain_, vcpu, regs, setEip ) != 0 ) {
			logger << ERROR << "xc_vcpu_set_context failed" << strerror( errno ) << std::flush;
			return false;
		}
	} else {
		delayedWrite_.registers_ = regs;

		if ( !setEip )
			delayedWrite_.registers_.rip = regs.rip + 3; // 3 is the size of the VMCALL opcodes

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

		regsCache_.registers_.r8  = regs.r8;
		regsCache_.registers_.r9  = regs.r9;
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

bool XenDriver::shutdown()
{
	if ( xc_.domainShutdown( domain_, XC::shutdownPoweroff ) ) {
		logger << ERROR << "xc_domain_shutdown() failed: " << strerror( errno ) << std::flush;
		return false;
	}

	return true;
}

void XenDriver::init( domid_t domain, bool hvmOnly )
{
	XenDomainInfo info;
	XenDomctlInfo domctlInfo;

	StatsCounter counter( "xcDomainInfo" );

	if ( xc_.domainGetInfo( domain_, info ) != 1 && xc_.domainGetInfoList( domain_, domctlInfo ) != 1 )
		throw std::runtime_error( "xc_domain_getinfo() failed" );

	if ( hvmOnly && !info.hvm )
		throw std::runtime_error( "Domain " + std::to_string( domain ) + " is not a HVM guest" );

	if ( domctlInfo.pvh )
		throw std::runtime_error( "Domain " + std::to_string( domain ) + " is a PVH guest" );

	// xc_.domainSetCoresPerSocket( domain, 10 );

	if ( info.shutdown || info.dying )
		throw std::runtime_error( "Domain " + std::to_string( domain ) +
		                          " is shutting down / dying, won't hook it" );

	uuid_ = queryUuid( xs_, std::to_string( domain_ ) );

	if ( altp2mState_ ) {
		if ( altp2mState_.createView( XENMEM_access_rwx, altp2mViewId_ ) < 0 )
			throw std::runtime_error( "[ALTP2M] could not create altp2m view" );

		if ( altp2mState_.switchToView( altp2mViewId_ ) < 0 )
			throw std::runtime_error( "[ALTP2M] could not switch to altp2m view" );
	}

	physAddr_ = 36;

	if ( cpuid_eax( 0x80000000 ) >= 0x80000008 )
		physAddr_ = ( uint8_t )cpuid_eax( 0x80000008 );

	maxGPFN_ = info.max_memkb >> ( XC::pageShift - 10 );

	logger << DEBUG << "max_memkb: " << info.max_memkb << ", maxGPFN: " << std::hex << std::showbase
		<< maxGPFN_ << std::dec << std::flush;
}

domid_t XenDriver::getDomainId( const std::string &uuid )
{
	domid_t                  domainId = 0;
	XS                       xs;
	std::vector<std::string> domains;

	if ( !xs.directory( XS::xbtNull, "/local/domain", domains ) )
		throw std::runtime_error( "Failed to retrieve domain ID by UUID [" + uuid + "]: " + strerror( errno ) );

	for ( auto &&domain : domains ) {
		std::string tmpUuid = queryUuid( xs, domain );

		if ( uuid == tmpUuid ) {
			domainId = std::stoi( domain );
			break;
		}
	}

	return domainId;
}

std::string XenDriver::queryUuid( XS &xs, const std::string &domain )
{
	constexpr size_t PREFIX_SIZE = 4;
	unsigned int     size        = 0;
	std::string      key         = "/local/domain/" + domain + "/vm";
	std::string      ret;

	CUniquePtr<char> path( xs.readTimeout( XS::xbtNull, key, &size, 1 ) );

	if ( path && size > PREFIX_SIZE )
		ret = path.get() + PREFIX_SIZE; // Get rid of "/vm/"

	return ret;
}

MapReturnCode XenDriver::mapPhysMemToHost( unsigned long long address, size_t length, uint32_t /*flags*/,
                                           void *&pointer )
{
	// one-page limit
	if ( ( address & XC::pageMask ) != ( ( address + length - 1 ) & XC::pageMask ) )
		return MAP_INVALID_PARAMETER;

	pointer           = nullptr;
	unsigned long gfn = gpa_to_gfn( address );

	try {

		void *mapped = nullptr;

#ifdef DISABLE_PAGE_CACHE
		mapped = mapGuestPageImpl( gfn );

		if ( mapped && !check_page( mapped ) ) {
			munmap( mapped, XC::pageSize );
			return MAP_PAGE_NOT_PRESENT;
		}
#else
		MapReturnCode mrc = pageCache_.update( gfn, mapped );

		if ( mrc != MAP_SUCCESS )
			return mrc;
#endif

		if ( !mapped ) {
			logger << ERROR << "address: 0x" << std::setfill( '0' ) << std::setw( 16 ) << std::hex
			       << address << ", length: " << length << std::flush;
			return MAP_FAILED_GENERIC;
		}

		pointer = static_cast<char *>( mapped ) + ( address & ~XC::pageMask );
	} catch ( ... ) {
		return MAP_FAILED_GENERIC;
	}

	return MAP_SUCCESS;
}

bool XenDriver::unmapPhysMem( void *hostPtr )
{
	void *map = hostPtr;
	map       = ( void * )( ( long int )map & XC::pageMask );

#ifdef DISABLE_PAGE_CACHE
	munmap( map, XC::pageSize );
#else
	pageCache_.release( map );
#endif

	return true;
}

bool XenDriver::requestPageFault( int vcpu, uint64_t /* addressSpace */, uint64_t virtualAddress, uint32_t errorCode )
{
	// It is assumed that the guest is in user-mode and in the proper
	// address space for "vcpu" here - otherwise things will likely
	// explode. If something does explode here, check that those
	// conditions hold HV-side.
	if ( xc_.hvmInjectTrap( domain_, vcpu, TRAP_page_fault, X86_EVENTTYPE_HW_EXCEPTION, errorCode, 0,
	                        virtualAddress /*, addressSpace */ ) != 0 ) {
		logger << ERROR << "xc_hvm_inject_trap() failed: " << strerror( errno ) << std::flush;
		return false;
	}

	pendingInjections_[vcpu] = true;

	return true;
}

bool XenDriver::setRepOptimizations( bool enable )
{
	if ( !xc_.monitorEmulateEachRep )
		return false;

	if ( xc_.monitorEmulateEachRep( domain_, !enable ) != 0 ) {
		logger << ERROR << "xc_monitor_emulate_each_rep() failed: " << strerror( errno ) << std::flush;
		return false;
	}

	return true;
}

bool XenDriver::pause()
{
	if ( xc_.domainPause( domain_ ) != 0 ) {
		logger << ERROR << "xc_domain_pause() failed: " << strerror( errno ) << std::flush;
		return false;
	}

	return true;
}

bool XenDriver::unpause()
{
	flushPageProtections();

	if ( xc_.domainUnpause( domain_ ) != 0 ) {
		logger << ERROR << "xc_domain_unpause() failed: " << strerror( errno ) << std::flush;
		return false;
	}

	update_ = true;

	return true;
}

bool XenDriver::update()
{
	if ( !update_ )
		return true;

	std::string key = "/local/domain/" + std::to_string( domain_ ) + "/data/updated";

	xs_.write( XS::xbtNull, key, "now", 3 );

	update_ = false;

	return true;
}

size_t XenDriver::setPageCacheLimit( size_t limit )
{
	return pageCache_.setLimit( limit );
}

bool XenDriver::getPAT( unsigned short vcpu, uint64_t &pat ) const
{
	if ( patInitialized_ ) {
		pat = msrPat_;
		return true;
	}

	StatsCounter ctxCounter( "partialContext" );
	StatsCounter mtrrCounter( "partialMtrr" );

	struct hvm_hw_mtrr hwMtrr;

	if ( xc_.domainHvmGetContextPartial( domain_, HVM_SAVE_CODE( MTRR ), vcpu, &hwMtrr, sizeof( hwMtrr ) ) != 0 ) {
		EventHandler *h          = handler();
		int           savedErrno = errno;

		logger << ERROR << "xc_domain_hvm_getcontext_partial() (vcpu = " << vcpu
		       << ") failed: " << strerror( errno ) << std::flush;

		if ( savedErrno == EINVAL && h )
			h->handleFatalError();

		return false;
	}

	pat = msrPat_   = hwMtrr.msr_pat_cr;
	patInitialized_ = true;

	return true;
}

bool XenDriver::getXSAVEInfo( unsigned short vcpu, struct hvm_hw_cpu_xsave &xsaveInfo ) const
{
	int ret = xc_.domainPause( domain_ );

	if ( ret < 0 )
		return false;

	// Get buffer length (0 argument)
	ret = xc_.domainHvmGetContext( domain_, 0, 0 );

	if ( ret < 0 ) {
		xc_.domainUnpause( domain_ );
		return false;
	}

	uint32_t             len = ret;
	std::vector<uint8_t> buf( len );

	ret = xc_.domainHvmGetContext( domain_, &buf[0], len );

	if ( ret < 0 ) {
		logger << ERROR << "xc_domain_hvm_getcontext() failed: " << strerror( errno ) << std::flush;
		xc_.domainUnpause( domain_ );
		return false;
	}

	uint32_t off   = 0;
	bool     found = false;

	while ( off < len ) {
		struct hvm_save_descriptor *descriptor = ( struct hvm_save_descriptor * )( &buf[0] + off );

		off += sizeof( struct hvm_save_descriptor );

		if ( descriptor->typecode == HVM_SAVE_CODE( END ) )
			break;

		if ( descriptor->typecode == CPU_XSAVE_CODE && descriptor->instance == vcpu ) {
			xsaveInfo = *( struct hvm_hw_cpu_xsave * )( &buf[0] + off );
			found     = true;
			break;
		}

		off += descriptor->length;
	}

	xc_.domainUnpause( domain_ );

	return found;
}

bool XenDriver::getXCR0( unsigned short vcpu, uint64_t &xcr0 ) const
{
	struct hvm_hw_cpu_xsave xsaveInfo;

	if ( getXSAVEInfo( vcpu, xsaveInfo ) ) {
		xcr0 = xsaveInfo.xcr0;
		return true;
	}

	return false;
}

#define XCR0_X87 0x00000001 /* x87 FPU/MMX state */
#define XCR0_SSE 0x00000002 /* SSE state */

bool XenDriver::getXSAVESize( unsigned short vcpu, size_t &size )
{
	uint64_t     featureMask = 0;
	unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
	uint32_t     localSize = 512 + 64;

	if ( !getXCR0( vcpu, featureMask ) ) {
		logger << ERROR << "could not query XCR0, can't get the XSAVE size" << std::flush;
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

bool XenDriver::getXSAVEArea( unsigned short vcpu, void *buffer, size_t bufSize )
{
	struct hvm_hw_cpu_xsave xsaveInfo;

	if ( getXSAVEInfo( vcpu, xsaveInfo ) ) {
		memcpy( buffer, &xsaveInfo.save_area, std::min( bufSize, sizeof( xsaveInfo ) ) );
		return true;
	}

	logger << ERROR << "could not query XSAVE area" << std::flush;

	return false;
}

void XenDriver::getMtrrRange( uint64_t base_msr, uint64_t mask_msr, uint64_t &base, uint64_t &end ) const
{
	uint32_t mask_lo = ( uint32_t )mask_msr;
	uint32_t mask_hi = ( uint32_t )( mask_msr >> 32 );
	uint32_t base_lo = ( uint32_t )base_msr;
	uint32_t base_hi = ( uint32_t )( base_msr >> 32 );

	if ( ( mask_lo & 0x800 ) == 0 ) {
		/* Invalid (i.e. free) range */
		base = 0;
		end  = 0;
		return;
	}

	uint32_t size_or_mask = ~( ( 1 << ( physAddr_ - XC::pageShift ) ) - 1 );

	/* Work out the shifted address mask. */
	mask_lo = ( size_or_mask | ( mask_hi << ( 32 - XC::pageShift ) ) | ( mask_lo >> XC::pageShift ) );

	/* This works correctly if size is a power of two (a contiguous range). */
	uint32_t size = -mask_lo;
	base          = base_hi << ( 32 - XC::pageShift ) | base_lo >> XC::pageShift;
	end           = base + size - 1;
}

bool XenDriver::isVarMtrrOverlapped( const struct hvm_hw_mtrr &hwMtrr ) const
{
	uint64_t phys_base, phys_mask, base_pre, end_pre, base, end;
	uint8_t  num_var_ranges = ( uint8_t )hwMtrr.msr_mtrr_cap;

	for ( int32_t i = 0; i < num_var_ranges; ++i ) {

		uint64_t phys_base_pre = ( ( uint64_t * )hwMtrr.msr_mtrr_var )[i * 2];
		uint64_t phys_mask_pre = ( ( uint64_t * )hwMtrr.msr_mtrr_var )[i * 2 + 1];

		getMtrrRange( phys_base_pre, phys_mask_pre, base_pre, end_pre );

		for ( int32_t seg = i + 1; seg < num_var_ranges; ++seg ) {

			phys_base = ( ( uint64_t * )hwMtrr.msr_mtrr_var )[seg * 2];
			phys_mask = ( ( uint64_t * )hwMtrr.msr_mtrr_var )[seg * 2 + 1];

			getMtrrRange( phys_base, phys_mask, base, end );

			if ( ( ( base_pre != end_pre ) && ( base != end ) ) ||
			     ( ( base >= base_pre ) && ( base <= end_pre ) ) ||
			     ( ( end >= base_pre ) && ( end <= end_pre ) ) ||
			     ( ( base_pre >= base ) && ( base_pre <= end ) ) ||
			     ( ( end_pre >= base ) && ( end_pre <= end ) ) ) {

				/* MTRR is overlapped. */
				return true;
			}
		}
	}

	return false;
}

unsigned int XenDriver::cpuid_eax( unsigned int op ) const
{
	unsigned int eax = 0;
	unsigned int ebx = 0;
	unsigned int ecx = 0;
	unsigned int edx = 0;

	__get_cpuid( op, &eax, &ebx, &ecx, &edx );

	return eax;
}

bool XenDriver::mtrrType( unsigned long long guestAddress, uint8_t &type ) const
{
	const uint8_t MTRR_TYPE_UNCACHABLE = 0;
	const uint8_t MTRR_TYPE_WRTHROUGH  = 4;

	int32_t seg, index;
	uint8_t overlap_mtrr = 0, overlap_mtrr_pos = 0;

	static bool               hwMtrrInit = false;
	static struct hvm_hw_mtrr hwMtrr;

	if ( !hwMtrrInit ) {
		StatsCounter partialCounter( "partialContext" );
		StatsCounter mtrrCounter( "partialMtrr" );
		if ( xc_.domainHvmGetContextPartial( domain_, HVM_SAVE_CODE( MTRR ), 0, &hwMtrr, sizeof( hwMtrr ) ) !=
		     0 ) {
			logger << ERROR << "xc_domain_hvm_getcontext_partial() failed: " << strerror( errno )
			       << std::flush;
			return false;
		} else
			hwMtrrInit = true;
	}

	uint8_t  def_type = hwMtrr.msr_mtrr_def_type & 0xff;
	uint8_t  enabled  = hwMtrr.msr_mtrr_def_type >> 10;
	uint8_t *u8_fixed = ( uint8_t * )hwMtrr.msr_mtrr_fixed;

	if ( !( enabled & 0x2 ) ) {
		type = MTRR_TYPE_UNCACHABLE;
		return true;
	}

	if ( ( guestAddress < 0x100000 ) && ( enabled & 1 ) ) {

		/* Fixed range MTRR takes effective */
		int32_t addr = ( uint32_t )guestAddress;

		if ( addr < 0x80000 ) {
			seg  = ( addr >> 16 );
			type = u8_fixed[seg];
		} else if ( addr < 0xc0000 ) {
			seg   = ( addr - 0x80000 ) >> 14;
			index = ( seg >> 3 ) + 1;
			seg &= 7; /* select 0-7 segments */
			type = u8_fixed[index * 8 + seg];
		} else {
			/* 0xC0000 --- 0x100000 */
			seg   = ( addr - 0xc0000 ) >> 12;
			index = ( seg >> 3 ) + 3;
			seg &= 7; /* select 0-7 segments */
			type = u8_fixed[index * 8 + seg];
		}

		return true;
	}

	uint8_t num_var_ranges = hwMtrr.msr_mtrr_cap & 0xff;
	bool    overlapped     = isVarMtrrOverlapped( hwMtrr );

	for ( seg = 0; seg < num_var_ranges; ++seg ) {
		uint64_t phys_base = hwMtrr.msr_mtrr_var[seg * 2];
		uint64_t phys_mask = hwMtrr.msr_mtrr_var[seg * 2 + 1];

		if ( phys_mask & ( 1 << MTRR_PHYSMASK_VALID_BIT ) ) {
			if ( ( ( uint64_t )guestAddress & phys_mask ) >> MTRR_PHYSMASK_SHIFT ==
			     ( phys_base & phys_mask ) >> MTRR_PHYSMASK_SHIFT ) {

				if ( overlapped ) {
					overlap_mtrr |= 1 << ( phys_base & MTRR_PHYSBASE_TYPE_MASK );
					overlap_mtrr_pos = phys_base & MTRR_PHYSBASE_TYPE_MASK;
				} else
					return phys_base & MTRR_PHYSBASE_TYPE_MASK;
			}
		}
	}

	if ( overlap_mtrr == 0 ) {
		type = def_type;
		return true;
	}

	if ( !( overlap_mtrr & ~( ( ( uint8_t )1 ) << overlap_mtrr_pos ) ) ) {
		type = overlap_mtrr_pos;
		return true;
	}

	if ( overlap_mtrr & 0x1 ) {
		/* Two or more match, one is UC. */
		type = MTRR_TYPE_UNCACHABLE;
		return true;
	}

	if ( !( overlap_mtrr & 0xaf ) ) {
		/* Two or more match, WT and WB. */
		type = MTRR_TYPE_WRTHROUGH;
		return true;
	}

	/* Behaviour is undefined, but return the last overlapped type. */
	type = overlap_mtrr_pos;
	return true;
}

bool XenDriver::maxGPFN( unsigned long long &gfn )
{
	gfn = maxGPFN_;

	// xen_pfn_t xpfn = 0;

	// if ( xc_.domainMaximumGpfn( domain_, &xpfn ) < 0 )
	// 	return false;

	// gfn = xpfn + 1;

	return true;
}

bool XenDriver::getEPTPageConvertible( unsigned short index, unsigned long long address, bool &convertible )
{
	if ( !altp2mState_ )
		return false;

	int rc = altp2mState_.getSuppressVE( index, gpa_to_gfn( address ), convertible );

	if ( rc < 0 ) {
		logger << ERROR << "Failed to read the convertible bit: " << strerror( -rc ) << std::flush;
		return false;
	}

	return true;
}

bool XenDriver::setPageConvertibleImpl( const ConvertibleMap &convMap, unsigned short view )
{
	if ( !altp2mState_ )
		return false;

	for ( auto &&item : convMap ) {
		int rc = altp2mState_.setSuppressVE( view, item.first, item.second );

		if ( rc < 0 ) {
			logger << ERROR << "Failed to write the convertible bit: " << strerror( -rc ) << std::flush;
			return false;
		}
	}

	return true;
}

bool XenDriver::createEPT( unsigned short &index )
{
	if ( !altp2mState_ )
		return false;

	uint16_t viewId = 0;

	if ( altp2mState_.createView( XENMEM_access_rwx, viewId ) < 0 )
		return false;

	index = viewId;

	return true;
}

bool XenDriver::destroyEPT( unsigned short index )
{
	if ( !altp2mState_ )
		return false;

	return altp2mState_.destroyView( index ) >= 0;
}

bool XenDriver::switchEPT( unsigned short index )
{
	if ( !altp2mState_ )
		return false;

	if ( altp2mState_.switchToView( index ) >= 0 ) {
		altp2mViewId_ = index;
		return true;
	}

	return false;
}

bool XenDriver::setVEInfoPage( unsigned short vcpu, unsigned long long gpa )
{
	if ( !altp2mState_ )
		return false;

	int rc = altp2mState_.setVEInfoPage( vcpu, gpa_to_gfn( gpa ) );

	if ( rc < 0 ) {
		logger << ERROR << "Failed to set the VE page: " << strerror( -rc ) << std::flush;
		return false;
	}

	return true;
}

bool XenDriver::disableVE( unsigned short vcpu )
{
	if ( !altp2mState_ )
		return false;

	int rc = altp2mState_.disableVE( vcpu );

	if ( rc < 0 ) {
		logger << ERROR << "Failed to disable VE: " << strerror( -rc ) << std::flush;
		return false;
	}

	return true;
}

void XenDriver::enableCache( unsigned short vcpu )
{
	std::lock_guard<std::mutex> lock( regsCache_.mutex_ );
	regsCache_.vcpu_  = vcpu;
	regsCache_.valid_ = false;
}

void XenDriver::disableCache()
{
	std::lock_guard<std::mutex> lock( regsCache_.mutex_ );
	regsCache_.vcpu_  = -1;
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
	std::string  key  = "/local/domain/" + std::to_string( domain_ ) + "/vm";

	CUniquePtr<char> path( xs_.readTimeout( XS::xbtNull, key, &size, 1 ) );

	if ( path && *path.get() != '\0' ) {
		std::string path1 = std::string( path.get() ) + "/start_time";
		std::string path2 =
		        std::string( path.get() ) + "/domains/" + std::to_string( domain_ ) + "/create-time";

		size = 0;

		path.reset( static_cast<char *>( xs_.readTimeout( XS::xbtNull, path1, &size, 1 ) ) );

		if ( path && *path.get() != '\0' )
			startTime_ = strtoul( path.get(), nullptr, 10 );

		path.reset();
		size = 0;

		if ( startTime_ == static_cast<uint32_t>( -1 ) ) // XenServer
			path.reset( static_cast<char *>( xs_.readTimeout( XS::xbtNull, path2, &size, 1 ) ) );

		if ( path && *path.get() != '\0' )
			startTime_ = strtoul( path.get(), nullptr, 10 );
	}

	return startTime_;
}

void *XenDriver::mapGuestPageImpl( unsigned long long gfn )
{
	StatsCounter counter( "xcMapPage" );

	return xc_.mapForeignRange( domain_, XC::pageSize, PROT_READ | PROT_WRITE, gfn );
}

void XenDriver::unmapGuestPageImpl( void *hostPtr, unsigned long long /* gfn */ )
{
	munmap( hostPtr, XC::pageSize );
}

bool XenDriver::isMsrCached( uint64_t msr ) const
{
	return msr != MSR_SHADOW_GS_BASE;
}

} // namespace bdvmi
