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

#include "bdvmi/logger.h"
#include "bdvmi/statscollector.h"
#include "kvmdriver.h"
#include "kvmdomainwatcher.h"
#include <cstring>
#include <fstream>
#include <cerrno>
#include <iomanip>
#include <unistd.h>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>

namespace {

constexpr uint64_t COMPAT_KVMI_MSG_SIZE        = ( 4096 - sizeof( struct kvmi_msg_hdr ) );
constexpr uint64_t MAX_PAGE_ACCESS_VECTOR_SIZE = COMPAT_KVMI_MSG_SIZE - sizeof( struct kvmi_set_page_access );
constexpr uint64_t MAX_PAGE_ACCESS_ENTRIES     = MAX_PAGE_ACCESS_VECTOR_SIZE / sizeof( struct kvmi_page_access_entry );

unsigned int makeArBytes( const struct kvm_segment &s )
{
	unsigned int ar;

	if ( s.unusable || !s.present )
		ar = 1 << 16;
	else {
		ar = s.type & 15;
		ar |= ( s.s & 1 ) << 4;
		ar |= ( s.dpl & 3 ) << 5;
		ar |= ( s.present & 1 ) << 7;
		ar |= ( s.avl & 1 ) << 12;
		ar |= ( s.l & 1 ) << 13;
		ar |= ( s.db & 1 ) << 14;
		ar |= ( s.g & 1 ) << 15;
	}

	return ar;
}

std::string accessString( int access )
{
	std::string str;

	str += ( access & KVMI_PAGE_ACCESS_R ) ? 'r' : '-';
	str += ( access & KVMI_PAGE_ACCESS_W ) ? 'w' : '-';
	str += ( access & KVMI_PAGE_ACCESS_X ) ? 'x' : '-';

	return str;
}

} // namespace

namespace bdvmi {

KvmDriver::BatchMessages::BatchMessages( void *dom, KvmDriver *driver )
    : driver_{ driver }
{
	grp_ = kvmi_batch_alloc( dom );
	if ( !grp_ )
		logger << ERROR << "kvmi_batch_alloc() => " << strerror( errno ) << std::flush;
}

KvmDriver::BatchMessages::~BatchMessages()
{
	kvmi_batch_free( grp_ );
}

bool KvmDriver::BatchMessages::commit()
{
	if ( kvmi_batch_commit( grp_ ) < 0 ) {
		logger << ERROR << "kvmi_batch_commit() => " << strerror( errno ) << std::flush;
		return false;
	}

	return true;
}

bool KvmDriver::BatchMessages::addPauseVcpu( unsigned short vcpu ) const
{
	if ( kvmi_queue_pause_vcpu( grp_, vcpu ) < 0 ) {
		logger << ERROR << "kvmi_queue_pause_vcpu(" << vcpu << ") => " << strerror( errno ) << std::flush;
		return false;
	}

	logger << TRACE << "kvmi_queue_pause_vcpu(" << vcpu << ")" << std::flush;
	return true;
}

KvmDriver::KvmDriver( const std::string &domain, bool useVE )
    : domain_{ domain }
    , pageCache_{ this }
{
	domCtx_ = KvmDomainWatcher::domainContext( domain );
	if ( !domCtx_ )
		throw std::runtime_error( std::string( "No connection for this domain: " ) + domain );

	if ( kvmi_memory_mapping( domCtx_, true ) < 0 )
		throw std::runtime_error( std::string( "No memory mapping, no introspection" ) + domain );

	batch_ = std::make_unique<BatchMessages>( domCtx_, this );

	std::string traceFile = "/tmp/" + domain_ + ".trace";

	struct stat traceInfo;
	if ( stat( traceFile.c_str(), &traceInfo ) == 0 )
		logger.trace( true );

	startTime_ = kvmi_get_starttime( domCtx_ );

	logger << TRACE << "kvmi_get_starttime() => " << static_cast<int64_t>( startTime_ ) << " ms "
	       << static_cast<uint32_t>( startTime_ / 1000 ) << " secs" << std::flush;

	if ( useVE ) {
		kvmi_eptp_support( domCtx_, &eptpSupported_ );

		if ( eptpSupported_ )
			kvmi_ve_support( domCtx_, &veSupported_ );

		if ( veSupported_ ) {
			if ( !getNextAvailableView( untrustedView_ ) )
				throw std::runtime_error( std::string( "All EPT views are in use for this domain: " ) +
				                          domain );
		}
	}
}

KvmDriver::~KvmDriver()
{
	logger << DEBUG << "Unmap all" << std::flush;

	if ( isConnected() )
		pageCache_.reset();

	pageCache_.driver( nullptr );

	kvmi_memory_mapping( domCtx_, false );

	// We must shutdown the socket on suspend (bdmid/parent will notice it).
	// We must shutdown the socket on any error.
	// We must not close the socket (the file descriptor) on retry (Introcore).
	// In all the other cases calling kvmi_domain_close (with suspending=0) is optional
	// because the file descriptor is closed when the process exits and bdmid/parent
	// just have to notice when the other side (kernel/QEMU) shuts down the socket.
	if ( suspending_ || !isConnected() ) {
		logger << DEBUG << "Close the socket" << std::flush;
		kvmi_domain_close( domCtx_, true );
	}
}

bool KvmDriver::cpuCount( unsigned int &count ) const
{
	int err;

	{
		StatsCounter counter( "kvmi_get_vcpu_count" );
		err = kvmi_get_vcpu_count( domCtx_, &count );
	}

	if ( err < 0 )
		logger << ERROR << "kvmi_get_vcpu_count() has failed: " << strerror( errno ) << std::flush;
	else {
		vcpuCount_ = count;

		logger << TRACE << "kvmi_get_vcpu_count() => " << count << std::flush;
	}

	return !err;
}

bool KvmDriver::tscSpeed( unsigned long long &speed ) const
{
	int err;

	{
		StatsCounter counter( "kvmi_get_tsc_speed" );
		err = kvmi_get_tsc_speed( domCtx_, &speed );
	}

	if ( err < 0 )
		logger << ERROR << "kvmi_get_tsc_speed() has failed: " << strerror( errno ) << std::flush;
	else
		logger << TRACE << "kvmi_get_tsc_speed() => " << speed << std::flush;

	return !err;
}

bool KvmDriver::BatchMessages::addPageAccess( unsigned long long int &gpa, unsigned char &access, unsigned short count,
                                              unsigned short view ) const
{
	int err;

	err = kvmi_queue_page_access( grp_, &gpa, &access, count, view );

	if ( err < 0 ) {
		logger << ERROR << "kvmi_queue_page_access() has failed: " << strerror( errno ) << std::flush;
	} else {
		for ( int i = 0; i < count; i++ )
			logger << TRACE << "kvmi_queue_page_access(gpa=" << HEXLOG( ( &gpa )[i] )
			       << ", access=" << accessString( ( &access )[i] ) << ", view=" << view << ")"
			       << std::flush;
	}

	return !err;
}

bool KvmDriver::mtrrType( unsigned long long guestAddress, uint8_t &type ) const
{
	int err;

	{
		StatsCounter counter( "kvmi_get_mtrr_type" );
		err = kvmi_get_mtrr_type( domCtx_, guestAddress, &type );
	}

	if ( err < 0 )
		logger << ERROR << "kvmi_get_mtrr_type() has failed: " << strerror( errno ) << std::flush;
	else
		logger << TRACE << "kvmi_get_mtrr_type(gpa=" << HEXLOG( guestAddress ) << ") => "
		       << static_cast<unsigned>( type ) << std::flush;

	return !err;
}

bool KvmDriver::setPageProtectionImpl( const MemAccessMap &accessMap, unsigned short view )
{
	if ( accessMap.empty() )
		return true;

	unsigned short chunk;
	uint64_t       offset = 0;

	std::vector<unsigned char>          access;
	std::vector<unsigned long long int> gpa;

	for ( auto &&item : accessMap ) {
		unsigned char acc = ( ( item.second & PAGE_READ ) ? KVMI_PAGE_ACCESS_R : 0 ) |
		    ( ( item.second & PAGE_WRITE ) ? KVMI_PAGE_ACCESS_W : 0 ) |
		    ( ( item.second & PAGE_EXECUTE ) ? KVMI_PAGE_ACCESS_X : 0 );
		access.push_back( acc );
		gpa.push_back( gfn_to_gpa( item.first ) );
	}

	const uint64_t size = gpa.size();

	while ( offset < size ) {
		chunk = std::min( size - offset, MAX_PAGE_ACCESS_ENTRIES );

		if ( !batch_->addPageAccess( gpa[offset], access[offset], chunk, view ) )
			return false;

		offset += chunk;
	}

	return true;
}

bool KvmDriver::getPageProtectionImpl( unsigned long long /* guestAddress */, bool &read, bool &write, bool &execute,
                                       unsigned short /* view */ )
{
	return read = write = execute = true;
}

bool KvmDriver::registers( unsigned short vcpu, Registers &regs ) const
{
	{
		std::lock_guard<std::mutex> lock( regsCache_.mutex_ );

		if ( regsCache_.valid( vcpu ) ) {
			regs = regsCache_.registers_;
			return true;
		}
	}

	struct kvm_regs kregs {
	};
	struct kvm_sregs sregs {
	};
	char                  buf[sizeof( struct kvm_msrs ) + 9 * sizeof( struct kvm_msr_entry )] = {};
	struct kvm_msrs *     msrs    = ( struct kvm_msrs * )buf;
	struct kvm_msr_entry *entries = msrs->entries;
	unsigned int          mode    = 0;
	int                   err;

	msrs->nmsrs      = 9;
	entries[0].index = MSR_IA32_SYSENTER_CS;
	entries[1].index = MSR_IA32_SYSENTER_ESP;
	entries[2].index = MSR_IA32_SYSENTER_EIP;
	entries[3].index = MSR_EFER;
	entries[4].index = MSR_STAR;
	entries[5].index = MSR_LSTAR;
	entries[6].index = MSR_CSTAR;
	entries[7].index = MSR_IA32_CR_PAT;
	entries[8].index = MSR_SHADOW_GS_BASE;

	{
		StatsCounter counter( "kvmi_get_registers" );
		err = kvmi_get_registers( domCtx_, vcpu, &kregs, &sregs, msrs, &mode );
	}

	if ( err < 0 && errno != EAGAIN )
		logger << ERROR << "kvmi_get_registers() has failed: " << strerror( errno ) << std::flush;
	else {
		regs.sysenter_cs  = entries[0].data;
		regs.sysenter_esp = entries[1].data;
		regs.sysenter_eip = entries[2].data;
		regs.msr_efer     = entries[3].data;
		regs.msr_star     = entries[4].data;
		regs.msr_lstar    = entries[5].data;
		regs.msr_cstar    = entries[6].data;
		regs.msr_pat      = entries[7].data;
		regs.shadow_gs    = entries[8].data;

		regs.cs_base    = sregs.cs.base;
		regs.cs_limit   = sregs.cs.limit;
		regs.cs_sel     = sregs.cs.selector;
		regs.cs_arbytes = makeArBytes( sregs.cs );

		regs.ss_base    = sregs.ss.base;
		regs.ss_limit   = sregs.ss.limit;
		regs.ss_sel     = sregs.ss.selector;
		regs.ss_arbytes = makeArBytes( sregs.ss );

		regs.ds_base    = sregs.ds.base;
		regs.ds_limit   = sregs.ds.limit;
		regs.ds_sel     = sregs.ds.selector;
		regs.ds_arbytes = makeArBytes( sregs.ds );

		regs.es_base    = sregs.es.base;
		regs.es_limit   = sregs.es.limit;
		regs.es_sel     = sregs.es.selector;
		regs.es_arbytes = makeArBytes( sregs.es );

		regs.fs_base    = sregs.fs.base;
		regs.fs_limit   = sregs.fs.limit;
		regs.fs_sel     = sregs.fs.selector;
		regs.fs_arbytes = makeArBytes( sregs.fs );

		regs.gs_base    = sregs.gs.base;
		regs.gs_limit   = sregs.gs.limit;
		regs.gs_sel     = sregs.gs.selector;
		regs.gs_arbytes = makeArBytes( sregs.gs );

		regs.idtr_base  = sregs.idt.base;
		regs.idtr_limit = sregs.idt.limit;

		regs.gdtr_base  = sregs.gdt.base;
		regs.gdtr_limit = sregs.gdt.limit;

		regs.rax    = kregs.rax;
		regs.rbx    = kregs.rbx;
		regs.rcx    = kregs.rcx;
		regs.rdx    = kregs.rdx;
		regs.rsi    = kregs.rsi;
		regs.rdi    = kregs.rdi;
		regs.rsp    = kregs.rsp;
		regs.rbp    = kregs.rbp;
		regs.r8     = kregs.r8;
		regs.r9     = kregs.r9;
		regs.r10    = kregs.r10;
		regs.r11    = kregs.r11;
		regs.r12    = kregs.r12;
		regs.r13    = kregs.r13;
		regs.r14    = kregs.r14;
		regs.r15    = kregs.r15;
		regs.rip    = kregs.rip;
		regs.rflags = kregs.rflags;

		regs.cr0 = sregs.cr0;
		regs.cr2 = sregs.cr2;
		regs.cr3 = sregs.cr3;
		regs.cr4 = sregs.cr4;

		switch ( mode ) {
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

		err = 0;

		logger << TRACE << "kvmi_get_registers(vcpu=" << vcpu << ")" << std::flush;
	}

	return !err;
}

bool KvmDriver::setRegisters( unsigned short vcpu, const Registers &regs, bool /* setEip */, bool delay )
{
	if ( delay ) {
		std::lock_guard<std::mutex> lock( regsCache_.mutex_ );

		if ( regsCache_.valid( vcpu ) ) {
			regsCache_.registers_ = regs;
			regsCache_.dirty_     = true;
			return true;
		}
	}

	int             err;
	struct kvm_regs kregs;

	memset( &kregs, 0, sizeof( kregs ) );

	kregs.rax    = regs.rax;
	kregs.rbx    = regs.rbx;
	kregs.rcx    = regs.rcx;
	kregs.rdx    = regs.rdx;
	kregs.rsi    = regs.rsi;
	kregs.rdi    = regs.rdi;
	kregs.rsp    = regs.rsp;
	kregs.rbp    = regs.rbp;
	kregs.r8     = regs.r8;
	kregs.r9     = regs.r9;
	kregs.r10    = regs.r10;
	kregs.r11    = regs.r11;
	kregs.r12    = regs.r12;
	kregs.r13    = regs.r13;
	kregs.r14    = regs.r14;
	kregs.r15    = regs.r15;
	kregs.rflags = regs.rflags;
	kregs.rip    = regs.rip;

	{
		StatsCounter counter( "kvmi_set_registers" );
		err = kvmi_set_registers( domCtx_, vcpu, &kregs );
	}

	if ( err < 0 )
		logger << ERROR << "kvmi_set_registers() has failed: " << strerror( errno ) << std::flush;
	else
		logger << TRACE << "kvmi_set_registers(vcpu=" << vcpu << ")" << std::flush;

	return !err;
}

MapReturnCode KvmDriver::mapPhysMemToHost( unsigned long long address, size_t length, uint32_t flags, void *&pointer )
{
	if ( ( address & PAGE_MASK ) != ( ( address + length - 1 ) & PAGE_MASK ) ) {
		logger << ERROR << "invalid parameter" << std::flush;
		return MAP_INVALID_PARAMETER;
	}

	pointer           = nullptr;
	unsigned long gfn = gpa_to_gfn( address );

	try {
		void *mapped = nullptr;

		// Because the introspection engine attempts to map uncached the same gfn
		// multiple times, something that is not supported by KVM, we work around
		// it by simply removing the flag
		flags &= ~PHYSMAP_NO_CACHE;

#ifdef DISABLE_PAGE_CACHE
		mapped = mapGuestPageImpl( gfn );
#else
		if ( flags & PHYSMAP_NO_CACHE )
			mapped = mapGuestPageImpl( gfn );
		else {
			MapReturnCode mrc = pageCache_.update( gfn, mapped );

			if ( mrc != MAP_SUCCESS )
				return mrc;
		}
#endif

		if ( !mapped )
			return MAP_FAILED_GENERIC;

		pointer = static_cast<char *>( mapped ) + ( address & ~PAGE_MASK );
	} catch ( const std::exception &e ) {
		logger << ERROR << "mapPhysMemToHost has failed: " << e.what() << std::flush;
		return MAP_FAILED_GENERIC;
	}

	return MAP_SUCCESS;
}

bool KvmDriver::unmapPhysMem( void *hostPtr )
{
	void *map = ( void * )( ( uintptr_t )hostPtr & PAGE_MASK );

#ifdef DISABLE_PAGE_CACHE
#ifdef DISABLE_PAGE_MAP
	unsigned long long gfn =
	    *( ( unsigned long long * )map + ( PAGE_SIZE + PAGE_SIZE / 2 ) / sizeof( unsigned long long ) );

	unmapGuestPageImpl( map, gfn );
#else
	unmapGuestPageImpl( map, ~0ull );
#endif
#else
	if ( !pageCache_.release( map ) )
		unmapGuestPageImpl( map, ~0ull );
#endif

	return true;
}

bool KvmDriver::injectTrap( unsigned short vcpu, uint8_t trapNumber, uint32_t errorCode, uint64_t cr2 )
{
	int err;

	{
		StatsCounter counter( "kvmi_inject_exception" );
		err = kvmi_inject_exception( domCtx_, vcpu, cr2, errorCode, trapNumber );
	}

	if ( err < 0 )
		logger << ERROR << "kvmi_inject_exception() has failed: " << strerror( errno ) << std::flush;
	else
		logger << TRACE << "kvmi_inject_exception(vcpu=" << vcpu << ", cr2=" << HEXLOG( cr2 )
		       << ", exception=" << HEXLOG( int( trapNumber ) ) << ", error=" << HEXLOG( errorCode ) << ")"
		       << std::flush;

	return !err;
}

bool KvmDriver::setRepOptimizations( bool enable )
{
	if ( enable )
		flags_ |= KVMI_REP_OPTIMIZATIONS_FLAG;
	else
		flags_ &= ~KVMI_REP_OPTIMIZATIONS_FLAG;

	return true;
}

bool KvmDriver::getRepOptimizations() const
{
	if ( flags_ & KVMI_REP_OPTIMIZATIONS_FLAG )
		return true;

	return false;
}

bool KvmDriver::shutdown()
{
	flags_ |= KVMI_SHUTDOWN_GUEST_FLAG;

	return true;
}

bool KvmDriver::testShutdown()
{
	if ( flags_ & KVMI_SHUTDOWN_GUEST_FLAG ) {
		flags_ &= ~KVMI_SHUTDOWN_GUEST_FLAG;
		return true;
	}

	return false;
}

bool KvmDriver::pause()
{
	{
		std::lock_guard<std::mutex> guard( pauseMutex_ );

		if ( pauseCount_++ )
			return true;
	}

	// We block KvmEventManager from reading new events
	// because it will unpause vCPU-s.

	eventProcessingMutex_.lock();

	return pauseAllVcpus();
}

bool KvmDriver::kickAllVcpus()
{
	StatsCounter counter( "kickAllVcpus" );

	BatchMessages grp( domCtx_, this );

	const unsigned int count = vcpuCount_;
	for ( unsigned short vcpu = 0; vcpu < count; vcpu++ )
		if ( !grp.addPauseVcpu( vcpu ) )
			return false;

	{
		std::lock_guard<std::mutex> guard( pauseMutex_ );
		// If this function is called from another thread,
		// pauseEventReceived() could try to decrement pendingPauseEvents_
		// before we can have a chance to increment it.

		if ( !grp.commit() )
			return false;

		pendingPauseEvents_ += count;
	}

	return true;
}

bool KvmDriver::unpause()
{
	std::lock_guard<std::mutex> guard( pauseMutex_ );

	if ( pauseCount_ == 0 )
		logger << ERROR << "Pause/unpause mismatch" << std::flush;
	else {
		pauseCount_--;
		if ( pauseCount_ == 0 )
			eventProcessingMutex_.unlock();
	}

	return true;
}

bool KvmDriver::pauseAllVcpus()
{
	unsigned int count = vcpuCount_;
	int          err;

	std::lock_guard<std::mutex> guard( pauseMutex_ );
	// If this function is called from another thread,
	// pauseEventReceived() could try to decrement pendingPauseEvents_
	// before we can have a chance to increment it.

	{
		StatsCounter counter( "kvmi_pause_all_vcpus" );
		err = kvmi_pause_all_vcpus( domCtx_, count );
	}

	if ( err ) {
		logger << ERROR << "kvmi_pause_all_vcpus(" << count << ") has failed: " << strerror( errno )
		       << std::flush;
		return false;
	}

	logger << TRACE << "kvmi_pause_all_vcpus(" << count << ")" << std::flush;

	pendingPauseEvents_ += count;

	return true;
}

size_t KvmDriver::setPageCacheLimit( size_t limit )
{
	return pageCache_.setLimit( limit );
}

#define DEFAULT_XSAVE_SIZE XSAVE_HDR_SIZE + XSAVE_HDR_OFFSET
#define XSAVE_HDR_SIZE     64
#define XSAVE_HDR_OFFSET   FXSAVE_SIZE
#define FXSAVE_SIZE        512

bool KvmDriver::getXSAVESize( unsigned short vcpu, size_t &size )
{
	unsigned int eax, ebx, ecx, edx;
	int          err;

	{
		StatsCounter counter( "kvmi_get_cpuid" );
		err = kvmi_get_cpuid( domCtx_, vcpu, 0xD, 0, &eax, &ebx, &ecx, &edx );
	}

	size = DEFAULT_XSAVE_SIZE;
	if ( err < 0 || !ebx )
		logger << ERROR << "kvmi_get_cpuid() has failed: " << strerror( errno ) << std::flush;
	else {
		size = ebx;

		logger << TRACE << "kvmi_get_cpuid(vcpu=" << vcpu << ") => eax=" << HEXLOG( eax )
		       << " ebx=" << HEXLOG( ebx ) << " ecx=" << HEXLOG( ecx ) << " edx=" << HEXLOG( edx )
		       << " size=" << HEXLOG( size ) << std::flush;
	}

	// cpuid might not reflect the state of kvm in the future; as a precaution, the underlying layers
	// will not see this call failing and the default size value will be returned instead; the default
	// value DEFAULT_XSAVE_SIZE is the size for the mandatory entries, therefore XSAVE operation will
	// not corrupt memory
	return true;
}

bool KvmDriver::getXSAVEArea( unsigned short vcpu, void *buffer, size_t bufSize )
{
	int err;

	{
		StatsCounter counter( "kvmi_get_xsave" );
		err = kvmi_get_xsave( domCtx_, vcpu, buffer, bufSize );
	}

	if ( err < 0 )
		logger << ERROR << "kvmi_get_xsave() has failed: " << strerror( errno ) << std::flush;
	else
		logger << TRACE << "kvmi_get_xsave(vcpu=" << vcpu << ")" << std::flush;

	return !err;
}

bool KvmDriver::update()
{
	return true;
}

std::string KvmDriver::uuid() const
{
	return domain_;
}

unsigned int KvmDriver::id() const
{
	return -1;
}

void KvmDriver::enableVcpuCache( unsigned short vcpu, unsigned short view, const Registers &regs )
{
	std::lock_guard<std::mutex> lock( regsCache_.mutex_ );

	regsCache_.vcpu_      = vcpu;
	regsCache_.valid_     = true;
	regsCache_.dirty_     = false;
	regsCache_.registers_ = regs;
	regsCache_.view_      = view;
}

void KvmDriver::updateVcpuCache( unsigned short view )
{
	regsCache_.view_ = view;
}

void KvmDriver::enablePendingVcpusCache()
{
	vcpuPendingSwitchCount_ = vcpuCount_;

	std::lock_guard<std::mutex> lock( pendingCache_.mutex_ );

	unsigned short vcpu;

	for ( vcpu = 0; vcpu < vcpuCount_; vcpu++ )
		pendingCache_.pendingVcpus_.insert( vcpu );
}

void KvmDriver::disablePendingVcpusCache( unsigned short vcpu )
{
	std::lock_guard<std::mutex> lock( pendingCache_.mutex_ );

	pendingCache_.pendingVcpus_.erase( vcpu );
}

bool KvmDriver::isPendingVcpusCacheEnabled( unsigned short vcpu ) const
{
	// Avoid using the mutex if all vcpus have already switched from
	// view #0 to the untrusted view. This way, the only lock that
	// remains in use in KvmDriver::eptpIndex() belongs to regsCache_.

	// NOTE: there is a potential check miss on the last vcpu, see
	// initialViewSetup(). In this case, the critical region below
	// is still executed. This might happen only once for a VM.
	// All other further calls of this method will be short
	// circuited here.

	if ( !vcpuPendingSwitchCount_ )
		return false;

	std::lock_guard<std::mutex> lock( pendingCache_.mutex_ );

	if ( pendingCache_.pendingVcpus_.find( vcpu ) == pendingCache_.pendingVcpus_.end() )
		return false;

	return true;
}

void KvmDriver::disableCache()
{
	std::lock_guard<std::mutex> lock( regsCache_.mutex_ );

	regsCache_.vcpu_  = -1;
	regsCache_.valid_ = false;
	regsCache_.view_  = 0;
}

bool KvmDriver::isViewCacheEnabled( unsigned short vcpu, unsigned short &view ) const
{
	std::lock_guard<std::mutex> lock( regsCache_.mutex_ );

	if ( !regsCache_.valid( vcpu ) )
		return false;

	view = regsCache_.view_;

	return true;
}

void *KvmDriver::mapGuestPageImpl( unsigned long long gfn )
{
	void *addr = nullptr;

#ifndef DISABLE_PAGE_MAP
	{
		StatsCounter counter( "kvmi_map_physical_page" );
		addr = kvmi_map_physical_page( domCtx_, gfn_to_gpa( gfn ) );
	}

	if ( addr == MAP_FAILED ) {
		if ( errno != EFAULT ) {
			logger << WARNING << "kvmi_map_physical_page() for gfn " << std::hex << std::showbase << gfn
			       << " has failed: " << strerror( errno ) << std::flush;
		}
		return nullptr;
	}
	logger << TRACE << "kvmi_map_physical_page(gfn=" << HEXLOG( gfn ) << ") => " << addr << std::flush;
#else
	if ( posix_memalign( &addr, PAGE_SIZE, 2 * PAGE_SIZE ) ) {
		logger << ERROR << "posix_memalign() has failed" << std::flush;
		return nullptr;
	}

	if ( kvmi_read_physical( domCtx_, gfn_to_gpa( gfn ), addr, PAGE_SIZE ) < 0 ) {
		logger << ERROR << "kvmi_read_physical() has failed" << std::flush;
		free( addr );
		return nullptr;
	}

	*( ( unsigned long long * )addr + ( PAGE_SIZE + PAGE_SIZE / 2 ) / sizeof( unsigned long long ) ) = gfn;
#endif

	return addr;
}

#ifndef DISABLE_PAGE_MAP
void KvmDriver::unmapGuestPageImpl( void *hostPtr, unsigned long long gfn )
{
	int err;

	{
		StatsCounter counter( "kvmi_unmap_physical_page" );
		err = kvmi_unmap_physical_page( domCtx_, hostPtr );
	}

	if ( err < 0 )
		logger << ERROR << "kvmi_unmap_physical_page() of " << hostPtr << " has failed: " << strerror( errno )
		       << std::flush;
	else
		logger << TRACE << "kvmi_unmap_physical_page(gfn=" << HEXLOG( gfn ) << ", addr=" << hostPtr << ")"
		       << std::flush;
#else
void KvmDriver::unmapGuestPageImpl( void *hostPtr, unsigned long long gfn )
{
	if ( kvmi_write_physical( domCtx_, gfn_to_gpa( gfn ), hostPtr, PAGE_SIZE ) < 0 )
		logger << ERROR << "kvmi_write_physical() has failed" << std::flush;

	memset( hostPtr, 0, 2 * PAGE_SIZE );
	free( hostPtr );
#endif
}

void KvmDriver::skipInstruction( const short instructionSize )
{
	std::lock_guard<std::mutex> lock( regsCache_.mutex_ );

	regsCache_.registers_.rip += instructionSize;
	regsCache_.dirty_ = true;
}

unsigned long long KvmDriver::getNextRip() const
{
	std::lock_guard<std::mutex> lock( regsCache_.mutex_ );

	return regsCache_.registers_.rip;
}

bool KvmDriver::getEventMsg( struct kvmi_dom_event *&event, int ms, bool &abort )
{
	int err = kvmi_wait_event( domCtx_, ms );

	if ( err < 0 ) {
		if ( errno == ETIMEDOUT )
			return false;
		if ( errno == ENOTCONN ) {
			logger << INFO << "Connection closed (reboot/poweroff?)" << std::flush;
			abort = true;
			return false;
		}
		throw std::runtime_error( std::string( "kvmi_wait_event() has failed: " ) + strerror( errno ) );
	}

	if ( kvmi_pop_event( domCtx_, &event ) )
		return false;

	return true;
}

bool KvmDriver::BatchMessages::addEventReply( EventReply &reply ) const
{
	int err;

	if ( driver_->testShutdown() )
		reply.reply_.common_.action = KVMI_EVENT_ACTION_CRASH;

	err = kvmi_queue_reply_event( grp_, reply.seq_, &reply.reply_, reply.size_ );
	if ( err < 0 )
		logger << ERROR << "kvmi_queue_reply_event() has failed: " << strerror( errno ) << std::flush;

	return !err;
}

bool KvmDriver::registerVMEvent( unsigned int id, bool enable ) const
{
	int err;

	{
		StatsCounter counter( "kvmi_control_vm_events" );
		err = kvmi_control_vm_events( domCtx_, id, enable );
	}

	if ( err < 0 )
		logger << ERROR << "kvmi_control_vm_events(" << id << ", " << enable
		       << ") has failed: " << strerror( errno ) << std::flush;
	else
		logger << TRACE << "kvmi_control_vm_events(" << id << ", " << enable << ")" << std::flush;

	return !err;
}

bool KvmDriver::registerEvent( unsigned short vcpu, unsigned int id, bool enable ) const
{
	int err;

	{
		StatsCounter counter( "kvmi_control_events" );
		err = kvmi_control_events( domCtx_, vcpu, id, enable );
	}

	if ( err < 0 )
		logger << ERROR << "kvmi_control_events(vcpu=" << vcpu << ", id=" << id << ", enable=" << enable
		       << ") has failed: " << strerror( errno ) << std::flush;
	else
		logger << TRACE << "kvmi_control_events(vcpu=" << vcpu << ", id=" << id << ", enable=" << enable << ")"
		       << std::flush;

	return !err;
}

bool KvmDriver::registerMSREvents( unsigned short vcpu, unsigned int msr, bool enable ) const
{
	int err;

	{
		StatsCounter counter( "kvmi_control_msr" );
		err = kvmi_control_msr( domCtx_, vcpu, msr, enable );
	}

	if ( err < 0 )
		logger << ERROR << "kvmi_control_msr(vcpu=" << vcpu << ", msr=" << HEXLOG( msr )
		       << ", enable=" << enable << ") failed: " << strerror( errno ) << std::flush;
	else
		logger << TRACE << "kvmi_control_msr(vcpu=" << vcpu << ", msr=" << HEXLOG( msr )
		       << ", enable=" << enable << ")" << std::flush;

	return !err;
}

bool KvmDriver::registerCREvents( unsigned short vcpu, unsigned int cr, bool enable ) const
{
	int err;

	{
		StatsCounter counter( "kvmi_control_cr" );
		err = kvmi_control_cr( domCtx_, vcpu, cr, enable );
	}

	if ( err < 0 )
		logger << ERROR << "kvmi_control_cr() has failed: " << strerror( errno ) << std::flush;
	else
		logger << TRACE << "kvmi_control_cr(vcpu=" << vcpu << ", cr=" << cr << ", enable=" << enable << ")"
		       << std::flush;

	return !err;
}

void KvmDriver::loadRegisters( Registers &regs, const struct kvmi_event &eventCommon ) const
{
	const struct kvmi_event_arch &event = eventCommon.arch;

	regs.sysenter_cs  = event.msrs.sysenter_cs;
	regs.sysenter_esp = event.msrs.sysenter_esp;
	regs.sysenter_eip = event.msrs.sysenter_eip;
	regs.msr_efer     = event.msrs.efer;
	regs.msr_star     = event.msrs.star;
	regs.msr_lstar    = event.msrs.lstar;
	regs.msr_cstar    = event.msrs.cstar;
	regs.msr_pat      = event.msrs.pat;
	regs.shadow_gs    = event.msrs.shadow_gs;

	regs.cs_base    = event.sregs.cs.base;
	regs.cs_limit   = event.sregs.cs.limit;
	regs.cs_sel     = event.sregs.cs.selector;
	regs.cs_arbytes = makeArBytes( event.sregs.cs );

	regs.ss_base    = event.sregs.ss.base;
	regs.ss_limit   = event.sregs.ss.limit;
	regs.ss_sel     = event.sregs.ss.selector;
	regs.ss_arbytes = makeArBytes( event.sregs.ss );

	regs.ds_base    = event.sregs.ds.base;
	regs.ds_limit   = event.sregs.ds.limit;
	regs.ds_sel     = event.sregs.ds.selector;
	regs.ds_arbytes = makeArBytes( event.sregs.ds );

	regs.es_base    = event.sregs.es.base;
	regs.es_limit   = event.sregs.es.limit;
	regs.es_sel     = event.sregs.es.selector;
	regs.es_arbytes = makeArBytes( event.sregs.es );

	regs.fs_base    = event.sregs.fs.base;
	regs.fs_limit   = event.sregs.fs.limit;
	regs.fs_sel     = event.sregs.fs.selector;
	regs.fs_arbytes = makeArBytes( event.sregs.fs );

	regs.gs_base    = event.sregs.gs.base;
	regs.gs_limit   = event.sregs.gs.limit;
	regs.gs_sel     = event.sregs.gs.selector;
	regs.gs_arbytes = makeArBytes( event.sregs.gs );

	regs.idtr_base  = event.sregs.idt.base;
	regs.idtr_limit = event.sregs.idt.limit;

	regs.gdtr_base  = event.sregs.gdt.base;
	regs.gdtr_limit = event.sregs.gdt.limit;

	regs.rax    = event.regs.rax;
	regs.rbx    = event.regs.rbx;
	regs.rcx    = event.regs.rcx;
	regs.rdx    = event.regs.rdx;
	regs.rsi    = event.regs.rsi;
	regs.rdi    = event.regs.rdi;
	regs.rsp    = event.regs.rsp;
	regs.rbp    = event.regs.rbp;
	regs.r8     = event.regs.r8;
	regs.r9     = event.regs.r9;
	regs.r10    = event.regs.r10;
	regs.r11    = event.regs.r11;
	regs.r12    = event.regs.r12;
	regs.r13    = event.regs.r13;
	regs.r14    = event.regs.r14;
	regs.r15    = event.regs.r15;
	regs.rip    = event.regs.rip;
	regs.rflags = event.regs.rflags;

	regs.cr0 = event.sregs.cr0;
	regs.cr2 = event.sregs.cr2;
	regs.cr3 = event.sregs.cr3;
	regs.cr4 = event.sregs.cr4;

	switch ( event.mode ) {
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

bool KvmDriver::BatchMessages::addRegisters() const
{
	RegsCache &regsCache_ = driver_->regsCache_;

	if ( !regsCache_.dirty_ )
		return true;

	int             err;
	struct kvm_regs kregs;
	memset( &kregs, 0, sizeof( kregs ) );

	kregs.rax    = regsCache_.registers_.rax;
	kregs.rbx    = regsCache_.registers_.rbx;
	kregs.rcx    = regsCache_.registers_.rcx;
	kregs.rdx    = regsCache_.registers_.rdx;
	kregs.rsi    = regsCache_.registers_.rsi;
	kregs.rdi    = regsCache_.registers_.rdi;
	kregs.rsp    = regsCache_.registers_.rsp;
	kregs.rbp    = regsCache_.registers_.rbp;
	kregs.r8     = regsCache_.registers_.r8;
	kregs.r9     = regsCache_.registers_.r9;
	kregs.r10    = regsCache_.registers_.r10;
	kregs.r11    = regsCache_.registers_.r11;
	kregs.r12    = regsCache_.registers_.r12;
	kregs.r13    = regsCache_.registers_.r13;
	kregs.r14    = regsCache_.registers_.r14;
	kregs.r15    = regsCache_.registers_.r15;
	kregs.rip    = regsCache_.registers_.rip;
	kregs.rflags = regsCache_.registers_.rflags;

	err = kvmi_queue_registers( grp_, regsCache_.vcpu_, &kregs );

	if ( err < 0 )
		logger << ERROR << "kvmi_queue_set_registers() has failed: " << strerror( errno ) << std::flush;
	else
		logger << TRACE << "kvmi_queue_set_registers(vcpu=" << regsCache_.vcpu_ << ")" << std::flush;

	return !err;
}

bool KvmDriver::initialViewSetup( unsigned short vcpu )
{
	// Nothing to do if all vCPUs have already switched to
	// untrustedView_
	if ( !vcpuPendingSwitchCount_ )
		return true;

	if ( regsCache_.view_ != 0 )
		return true;

	if ( !controlEPTview( vcpu, untrustedView_, true ) )
		return false;

	if ( !vcpuSwitchView( vcpu, untrustedView_ ) )
		return false;

	// Update the view cache for the current vcpu before clearing
	// the vcpu in pendingCache_
	updateVcpuCache( untrustedView_ );

	// At this point, it's safe to remove the current vcpu from
	// pendingCache_; any future call of eptpIndex(vcpu) will use the
	// view cache, if still valid
	disablePendingVcpusCache( vcpu );

	--vcpuPendingSwitchCount_;

	return true;
}

bool KvmDriver::flushCtrlEvents( unsigned short vcpu, const std::set<unsigned int> &enabledCrs,
                                 const std::set<unsigned int> &enabledMsrs )
{
	if ( vcpu >= vcpuCount_ ) {
		logger << ERROR << "Out of range vcpu idx: 0x" << std::setfill( '0' ) << std::setw( 4 ) << std::hex
		       << vcpu << std::flush;
		return false;
	}

	if ( !vcpuEvents_[vcpu].dirty_ )
		return true;

	if ( !initialViewSetup( vcpu ) )
		return false;

	if ( !flushEvents( vcpu ) )
		return false;

	if ( !flushCREvents( vcpu, enabledCrs ) )
		return false;

	if ( !flushMSREvents( vcpu, enabledMsrs ) )
		return false;

	vcpuEvents_[vcpu].dirty_ = false;

	return true;
}

bool KvmDriver::flushEvents( unsigned short vcpu )
{
	const auto currentEvents = vcpuEvents_[vcpu].enabled_;
	const auto newEvents     = enabledEvents_;
	auto       changed       = ( currentEvents ^ newEvents );

	if ( changed.any() ) {
		for ( unsigned int id = 0; id < changed.size(); id++ )
			if ( changed.test( id ) )
				registerEvent( vcpu, id, newEvents.test( id ) );

		vcpuEvents_[vcpu].enabled_ = newEvents;
	}

	return true;
}

bool KvmDriver::flushCREvents( unsigned short vcpu, const std::set<unsigned int> &enabledCrs )
{
	for ( auto i = enabledCrs.begin(); i != enabledCrs.end(); ++i ) {
		if ( vcpuEvents_[vcpu].enabledCrs_.find( *i ) == vcpuEvents_[vcpu].enabledCrs_.end() ) {
			if ( !registerCREvents( vcpu, *i, true ) )
				return false;
			vcpuEvents_[vcpu].enabledCrs_.insert( *i );
		}
	}

	for ( auto j = vcpuEvents_[vcpu].enabledCrs_.begin(); j != vcpuEvents_[vcpu].enabledCrs_.end(); ++j ) {
		if ( enabledCrs.find( *j ) == enabledCrs.end() ) {
			if ( !registerCREvents( vcpu, *j, false ) )
				return false;
			vcpuEvents_[vcpu].enabledCrs_.erase( *j );
		}
	}

	return true;
}

bool KvmDriver::flushMSREvents( unsigned short vcpu, const std::set<unsigned int> &enabledMsrs )
{
	for ( auto i = enabledMsrs.begin(); i != enabledMsrs.end(); ++i ) {
		if ( vcpuEvents_[vcpu].enabledMsrs_.find( *i ) == vcpuEvents_[vcpu].enabledMsrs_.end() ) {
			if ( !registerMSREvents( vcpu, *i, true ) )
				return false;
			vcpuEvents_[vcpu].enabledMsrs_.insert( *i );
		}
	}

	for ( auto j = vcpuEvents_[vcpu].enabledMsrs_.begin(); j != vcpuEvents_[vcpu].enabledMsrs_.end(); ++j ) {
		if ( enabledMsrs.find( *j ) == enabledMsrs.end() ) {
			if ( !registerMSREvents( vcpu, *j, false ) )
				return false;
			vcpuEvents_[vcpu].enabledMsrs_.erase( *j );
		}
	}

	return true;
}

uint32_t KvmDriver::startTime()
{
	if ( !startTime_ )
		return static_cast<uint32_t>( -1 );

	int64_t secs = startTime_ / 1000; // from milliseconds

	return static_cast<uint32_t>( secs );
}

void KvmDriver::pauseEventReceived()
{
	std::lock_guard<std::mutex> guard( pauseMutex_ );

	if ( pendingPauseEvents_ )
		pendingPauseEvents_--;
	else
		logger << ERROR << "Pause event without a pause command?" << std::flush;
}

bool KvmDriver::isMsrCached( uint64_t /* msr */ ) const
{
	return true;
}

bool KvmDriver::isConnected()
{
	return kvmi_domain_is_connected( domCtx_ );
}

void KvmDriver::suspending( bool value )
{
	suspending_ = value;
}

bool KvmDriver::suspending() const
{
	return suspending_;
}

void KvmDriver::beginEvent( Registers &regs, const struct kvmi_event &event )
{
	loadRegisters( regs, event );

	enableVcpuCache( event.vcpu, event.arch.view, regs );
}

bool KvmDriver::replyEvent( EventReply &reply )
{
	flushPageProtections();

	if ( !batch_->addRegisters() )
		return false;

	if ( !batch_->addEventReply( reply ) )
		return false;

	disableCache();

	if ( !batch_->commit() )
		return false;

	batch_ = std::make_unique<BatchMessages>( domCtx_, this );

	return true;
}

void KvmDriver::setVcpuVectorSize()
{
	vcpuEvents_.resize( vcpuCount_ );
}

void KvmDriver::setVcpuEventsDirty()
{
	for ( auto &&i : vcpuEvents_ )
		i.dirty_ = true;
}

bool KvmDriver::updateVcpuCount()
{
	unsigned int count;

	if ( cpuCount( count ) )
		setVcpuVectorSize();
	else
		return false;

	return true;
}

void KvmDriver::setVcpuEventsLater( unsigned int id )
{
	enabledEvents_.set( id );
	setVcpuEventsDirty();
}

bool KvmDriver::setVcpuEvents( unsigned int id )
{
	enabledEvents_.set( id );
	setVcpuEventsDirty();

	return kickAllVcpus();
}

bool KvmDriver::clearVcpuEvents( unsigned int id )
{
	enabledEvents_.reset( id );
	setVcpuEventsDirty();

	return kickAllVcpus();
}

bool KvmDriver::clearVcpuEvents()
{
	enabledEvents_.reset();
	setVcpuEventsDirty();

	return kickAllVcpus();
}

bool KvmDriver::maxGPFNImpl( unsigned long long &gfn )
{
	int err;

	{
		StatsCounter counter( "kvmi_get_maximum_gfn" );
		err = kvmi_get_maximum_gfn( domCtx_, &gfn );
	}

	if ( err < 0 )
		logger << ERROR << "kvmi_get_maximum_gfn() has failed: " << strerror( errno ) << std::flush;
	else
		logger << TRACE << "kvmi_get_maximum_gfn() => " << HEXLOG( gfn ) << std::flush;

	// introcore expects to receive the last accesible GFN, see
	// introspection/introcore/guests.c (hvmi.git)
	gfn = gfn - 1;

	return !err;
}

unsigned short KvmDriver::eptpIndex( unsigned short vcpu ) const
{
	unsigned short view = 0;
	int            err;

	if ( !eptpSupported_ )
		return view;

	if ( isPendingVcpusCacheEnabled( vcpu ) )
		return untrustedView_;

	if ( isViewCacheEnabled( vcpu, view ) )
		return view;

	{
		StatsCounter counter( "kvmi_get_ept_view" );
		err = kvmi_get_ept_view( domCtx_, vcpu, &view );
	}

	if ( err )
		logger << ERROR << "kvmi_get_ept_view(vcpu=" << vcpu << ") failed: " << strerror( errno ) << std::flush;
	else
		logger << TRACE << "kvmi_get_ept_view(vcpu=" << vcpu << ") => " << view << std::flush;

	return view;
}

bool KvmDriver::setVEInfoPage( unsigned short vcpu, unsigned long long gpa )
{
	int err;

	{
		StatsCounter counter( "kvmi_set_ve_info_page" );
		err = kvmi_set_ve_info_page( domCtx_, vcpu, gpa );
	}

	if ( err < 0 )
		logger << ERROR << "kvmi_set_ve_info_page(vcpu=" << vcpu << ", gpa=" << HEXLOG( gpa )
		       << ") has failed: " << strerror( errno ) << std::flush;
	else
		logger << TRACE << "kvmi_set_ve_info_page(vcpu=" << vcpu << ", gpa=" << HEXLOG( gpa ) << ")"
		       << std::flush;

	return !err;
}

bool KvmDriver::getNextAvailableView( unsigned short &index )
{
	unsigned short view;

	// Never use EPT view #0 as every change propagates to all other
	// views
	for ( view = 1; view < guestVisibleEPTviews_.size(); view++ )
		if ( !guestVisibleEPTviews_[view] ) {
			guestVisibleEPTviews_[view] = true;
			index                       = view;
			return true;
		}

	return false;
}

bool KvmDriver::controlEPTview( unsigned short vcpu, unsigned short view, bool visible )
{
	int rc;

	{
		StatsCounter counter( "kvmi_control_ept_view" );
		rc = kvmi_control_ept_view( domCtx_, vcpu, view, visible );
	}

	if ( rc ) {
		logger << ERROR << "kvmi_control_ept_view(vcpu=" << vcpu << ", view=" << view
		       << ", visible=" << std::boolalpha << visible << ") failed: " << strerror( errno ) << std::flush;
		return false;
	}

	logger << TRACE << "kvmi_control_ept_view(vcpu=" << vcpu << ", view=" << view << ", visible=" << std::boolalpha
	       << visible << ") => 0" << std::flush;

	return true;
}

bool KvmDriver::createEPT( unsigned short &index )
{
	unsigned short vcpu;

	if ( !getNextAvailableView( index ) ) {
		logger << ERROR << "All EPT views are in use!" << std::flush;
		return false;
	}

	// Make the view visible to all vCPUs

	for ( vcpu = 0; vcpu < vcpuCount_; vcpu++ )
		if ( !controlEPTview( vcpu, index, true ) )
			return false;

	return true;
}

bool KvmDriver::destroyEPT( unsigned short index )
{
	unsigned short vcpu;

	// Avoid destroying default EPT view #0
	if ( !index || index >= guestVisibleEPTviews_.size() )
		return false;

	if ( !guestVisibleEPTviews_[index] )
		return false;

	// Restrict the view for all vCPUs

	for ( vcpu = 0; vcpu < vcpuCount_; vcpu++ )
		if ( !controlEPTview( vcpu, index, false ) )
			return false;

	guestVisibleEPTviews_[index] = false;

	return true;
}

bool KvmDriver::vcpuSwitchView( unsigned short vcpu, unsigned short index )
{
	int rc;

	{
		StatsCounter counter( "kvmi_switch_ept_view" );
		rc = kvmi_switch_ept_view( domCtx_, vcpu, index );
	}

	if ( rc ) {
		logger << ERROR << "kvmi_switch_ept_view(vcpu=" << vcpu << ", index=" << index
		       << ") failed: " << strerror( errno ) << std::flush;
		return false;
	}

	logger << TRACE << "kvmi_switch_ept_view(vcpu=" << vcpu << ", index=" << index << ") succeeded" << std::flush;

	return true;
}

bool KvmDriver::switchEPT( unsigned short index )
{
	unsigned short vcpu;

	for ( vcpu = 0; vcpu < vcpuCount_; vcpu++ )
		if ( !vcpuSwitchView( vcpu, index ) )
			return false;

	return true;
}

bool KvmDriver::getEPTPageConvertible( unsigned short index, unsigned long long address, bool &convertible )
{
	int err;

	{
		StatsCounter counter( "kvmi_get_ept_page_conv" );
		err = kvmi_get_ept_page_conv( domCtx_, index, address, &convertible );
	}

	if ( err < 0 )
		logger << ERROR << "kvmi_get_ept_page_conv(index= " << index << ", gpa= " << HEXLOG( address )
		       << ") failed: " << strerror( errno ) << std::flush;
	else
		logger << TRACE << "kvmi_get_ept_page_conv(index= " << index << ", gpa= " << HEXLOG( address )
		       << ") => " << std::boolalpha << convertible << std::flush;

	return !err;
}

bool KvmDriver::setPageConvertibleImpl( const ConvertibleMap &convMap, unsigned short view )
{
	uint64_t gpa;
	bool     sve;
	int      err;
	int      rc = 0;

	for ( auto &&item : convMap ) {
		gpa = gfn_to_gpa( item.first );
		sve = item.second;

		{
			StatsCounter counter( "kvmi_set_ept_page_conv" );
			err = kvmi_set_ept_page_conv( domCtx_, view, gpa, sve );
			rc |= err;
		}

		if ( err )
			logger << ERROR << "kvmi_set_ept_page_conv(view= " << view << ", gpa= " << HEXLOG( gpa )
			       << ", sve= " << std::boolalpha << sve << ") failed: " << strerror( errno ) << std::flush;
		else
			logger << TRACE << "kvmi_set_ept_page_conv(view= " << view << ", gpa= " << HEXLOG( gpa )
			       << ", sve= " << std::boolalpha << sve << ")" << std::flush;
	}

	return !rc;
}

bool KvmDriver::disableVE( unsigned short vcpu )
{
	int err;

	{
		StatsCounter counter( "kvmi_disable_ve" );
		err = kvmi_disable_ve( domCtx_, vcpu );
	}

	if ( err )
		logger << ERROR << "kvmi_disable_ve(vcpu=" << vcpu << ") failed: " << strerror( errno ) << std::flush;
	else
		logger << TRACE << "kvmi_disable_ve(vcpu=" << vcpu << ") => true" << std::flush;

	return !err;
}

}; // namespace bdvmi
