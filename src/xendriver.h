// Copyright (c) 2015-2021 Bitdefender SRL, All rights reserved.
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

#ifndef __BDVMIXENDRIVER_H_INCLUDED__
#define __BDVMIXENDRIVER_H_INCLUDED__

#include <list>
#include <set>
#include <string>
#include <unordered_map>
#include <mutex>

#include "bdvmi/driver.h"
#include "bdvmi/pagecache.h"

#include "xcwrapper.h"
#include "xenaltp2m.h"
#include "xswrapper.h"

namespace bdvmi {

class XenDriver : public Driver {

	struct RegsCache {
		Registers  registers_;
		int        vcpu_{ -1 };
		bool       valid_{ false };
		std::mutex mutex_;
	};

public:
	struct DelayedWrite {
		Registers registers_;
		bool      pending_{ false };
	};

public:
	// Create a XenDriver object with the domain name
	XenDriver( const std::string &uuid, bool altp2m, bool hvmOnly = true );

	// Create a XenDriver object with the domain ID (# xl list)
	XenDriver( domid_t domain, bool altp2m, bool hvmOnly = true );

	~XenDriver();

public:
	bool cpuCount( unsigned int &count ) const override;

	bool tscSpeed( unsigned long long &speed ) const override;

	bool mtrrType( unsigned long long guestAddress, uint8_t &type ) const override;

	bool registers( unsigned short vcpu, Registers &regs ) const override;

	bool setRegisters( unsigned short vcpu, const Registers &regs, bool setEip, bool delay ) override;

	MapReturnCode mapPhysMemToHost( unsigned long long address, size_t length, uint32_t flags,
	                                void *&pointer ) override;

	bool unmapPhysMem( void *hostPtr ) override;

	bool injectTrap( unsigned short vcpu, uint8_t trapNumber, uint32_t errorCode, uint64_t cr2 ) override;

	bool setRepOptimizations( bool enable ) override;

	bool shutdown() override;

	bool pause() override;

	bool unpause() override;

	size_t setPageCacheLimit( size_t limit ) override;

	bool getXSAVESize( unsigned short vcpu, size_t &size ) override;

	bool getXSAVEArea( unsigned short vcpu, void *buffer, size_t bufSize ) override;

	bool getEPTPageConvertible( unsigned short index, unsigned long long address, bool &convertible ) override;

	bool createEPT( unsigned short &index ) override;

	bool destroyEPT( unsigned short index ) override;

	bool switchEPT( unsigned short index ) override;

	bool setVEInfoPage( unsigned short vcpu, unsigned long long gpa ) override;

	bool disableVE( unsigned short vcpu ) override;

	unsigned short eptpIndex( unsigned short vcpu ) const override;

	bool update() override;

	std::string uuid() const override
	{
		return uuid_;
	}

	unsigned int id() const override
	{
		return domain_;
	}

	void enableCache( unsigned short vcpu ) override;

	void disableCache() override;

	void enableP2mIdxCache( unsigned short vcpu, unsigned short idx );

	void disableP2mIdxCache( unsigned short vcpu );

	uint32_t startTime() override;

	bool isMsrCached( uint64_t msr ) const override;

	// Does this driver support altp2m #VE?
	bool veSupported() const override
	{
		return !!altp2mState_;
	}

	// Does this driver support altp2m VMFUNC?
	bool vmfuncSupported() const override
	{
		return !!altp2mState_;
	}

	// Does this driver support Intel SPP?
	bool sppSupported() const override
	{
		return false;
	}

	bool dtrEventsSupported() const override
	{
		return !!xc_.monitorDescriptorAccess && xc_.version >= Version( 4, 11 );
	}

	bool getXCR0( unsigned short vcpu, uint64_t &xcr0 ) const override;

private:
	void *mapGuestPageImpl( unsigned long long gfn ) override;

	void unmapGuestPageImpl( void *hostPtr, unsigned long long gfn ) override;

	bool setPageProtectionImpl( const MemAccessMap &accessMap, unsigned short view ) override;

	bool getPageProtectionImpl( unsigned long long guestAddress, bool &read, bool &write, bool &execute,
	                            unsigned short view ) override;

	bool setPageConvertibleImpl( const ConvertibleMap &convMap, unsigned short view ) override;

public: // Xen specific-stuff
	XC &nativeHandle() const
	{
		return xc_;
	}

public:
	static int32_t guestX86Mode( const Registers &regs );

	DelayedWrite &delayedWrite()
	{
		return delayedWrite_;
	}

	bool pendingInjection( unsigned short vcpu ) const;

	void clearInjection( unsigned short vcpu );

	bool altp2mEnabled() const
	{
		return !!altp2mState_;
	}

public:
	// Don't allow copying for these objects (class has xci_)
	XenDriver( const XenDriver & ) = delete;

	// Don't allow copying for these objects (class has xci_)
	XenDriver &operator=( const XenDriver & ) = delete;

private:
	void init( domid_t domain, bool hvmOnly );

	static domid_t getDomainId( const std::string &domainName );

	bool getXSAVEInfo( unsigned short vcpu, struct hvm_hw_cpu_xsave &xsaveInfo ) const;

	bool getPAT( unsigned short vcpu, uint64_t &pat ) const;

	bool isVarMtrrOverlapped( const struct hvm_hw_mtrr &hwMtrr ) const;

	void getMtrrRange( uint64_t base_msr, uint64_t mask_msr, uint64_t &base, uint64_t &end ) const;

	unsigned int cpuid_eax( unsigned int op ) const;

	static std::string queryUuid( XS &xs, const std::string &domain );

	bool maxGPFNImpl( unsigned long long &gfn, bool &trustworthy ) override;

private:
	mutable XS        xs_;
	mutable XC        xc_;
	domid_t           domain_;
	PageCache         pageCache_;
	std::string       uuid_;
	mutable RegsCache regsCache_;
	bool              update_{ false };
	DelayedWrite      delayedWrite_;
	std::unordered_map<unsigned short, bool> pendingInjections_;
	uint32_t             startTime_{ static_cast<uint32_t>( -1 ) };
	mutable bool         patInitialized_{ false };
	mutable uint64_t     msrPat_{ 0 };
	unsigned long long   maxGPFN_{ 0 };
	XenAltp2mDomainState altp2mState_;
	std::function<int( const MemAccessMap &, unsigned short )> setMemAccess_;
	std::function<int( unsigned long long, xenmem_access_t *, unsigned short )> getMemAccess_;
	unsigned int physAddr_{ 0 };
};

} // namespace bdvmi

#endif // __BDVMIXENDRIVER_H_INCLUDED__
