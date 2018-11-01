// Copyright (c) 2015-2018 Bitdefender SRL, All rights reserved.
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
#include <map>
#include <mutex>

#include "bdvmi/driver.h"
#include "bdvmi/pagecache.h"

#include "xcwrapper.h"
#include "xenaltp2m.h"
#include "xswrapper.h"

namespace bdvmi {

class LogHelper;

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
	XenDriver( const std::string &uuid, LogHelper *logHelper = nullptr, bool hvmOnly = true,
	           bool useAltP2m = false );

	// Create a XenDriver object with the domain ID (# xm list)
	XenDriver( domid_t domain, LogHelper *logHelper = nullptr, bool hvmOnly = true, bool useAltP2m = false );

public:
	bool cpuCount( unsigned int &count ) const override;

	bool tscSpeed( unsigned long long &speed ) const override;

	bool registers( unsigned short vcpu, Registers &regs ) const override;

	bool setRegisters( unsigned short vcpu, const Registers &regs, bool setEip, bool delay ) override;

	bool writeToPhysAddress( unsigned long long address, void *buffer, size_t length ) override;

	MapReturnCode mapPhysMemToHost( unsigned long long address, size_t length, uint32_t flags,
	                                void *&pointer ) override;

	bool unmapPhysMem( void *hostPtr ) override;

	MapReturnCode mapVirtMemToHost( unsigned long long address, size_t length, uint32_t flags, unsigned short vcpu,
	                                void *&pointer ) override;

	bool unmapVirtMem( void *hostPtr ) override;

	bool requestPageFault( int vcpu, uint64_t addressSpace, uint64_t virtualAddress, uint32_t errorCode ) override;

	bool setRepOptimizations( bool enable ) override;

	bool shutdown() override;

	bool pause() override;

	bool unpause() override;

	size_t setPageCacheLimit( size_t limit ) override;

	bool getXSAVESize( unsigned short vcpu, size_t &size ) override;

	bool getXSAVEArea( unsigned short vcpu, void *buffer, size_t bufSize ) override;

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

	uint32_t startTime() override;

	bool isMsrCached( uint64_t msr ) const override;

private:
	void *mapGuestPageImpl( unsigned long long gfn ) override;

	void unmapGuestPageImpl( void *hostPtr, unsigned long long gfn ) override;

	bool setPageProtectionImpl( const MemAccessMap &accessMap ) override;

	bool getPageProtectionImpl( unsigned long long guestAddress, bool &read, bool &write, bool &execute ) override;

public: // Xen specific-stuff
	XC &nativeHandle() const
	{
		return xc_;
	}

	uint16_t altp2mViewId() const
	{
		return altp2mViewId_;
	}

public:
	static int32_t guestX86Mode( const Registers &regs );

	DelayedWrite &delayedWrite()
	{
		return delayedWrite_;
	}

	bool pendingInjection( unsigned short vcpu ) const;

	void clearInjection( unsigned short vcpu );

private:
	// Don't allow copying for these objects (class has xci_)
	XenDriver( const XenDriver & );

	// Don't allow copying for these objects (class has xci_)
	XenDriver &operator=( const XenDriver & );

private:
	void init( domid_t domain, bool hvmOnly );

	static domid_t getDomainId( const std::string &domainName );

	bool getXSAVEInfo( unsigned short vcpu, struct hvm_hw_cpu_xsave &xsaveInfo ) const;

	bool getXCR0( unsigned short vcpu, uint64_t &xcr0 ) const;

	bool getPAT( unsigned short vcpu, uint64_t &pat ) const;

private:
	mutable XS        xs_;
	mutable XC        xc_;
	domid_t           domain_;
	PageCache         pageCache_;
	std::string       uuid_;
	uint16_t          altp2mViewId_{ 0 };
	mutable RegsCache regsCache_;
	bool              update_{ false };
	DelayedWrite      delayedWrite_;
	std::map<unsigned short, bool> pendingInjections_;
	uint32_t                                   startTime_{ static_cast<uint32_t>(-1) };
	mutable bool                               patInitialized_{ false };
	mutable uint64_t                           msrPat_{ 0 };
	std::unique_ptr<XenAltp2mDomainState>      altp2mState_;
	std::function<int( const MemAccessMap & )> setMemAccess_;
};

} // namespace bdvmi

#endif // __BDVMIXENDRIVER_H_INCLUDED__
