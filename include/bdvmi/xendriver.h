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

#ifndef __BDVMIXENDRIVER_H_INCLUDED__
#define __BDVMIXENDRIVER_H_INCLUDED__

#include <list>
#include <set>
#include <string>
#include <sstream>
#include <map>
#include <mutex>

#include "driver.h"
#include "xencache.h"

extern "C" {
#include <xenstore.h>
#include <xenctrl.h>
#include <xen/hvm/save.h>
}

namespace bdvmi {

class LogHelper;

class XenDriver : public Driver {

	struct RegsCache {
		RegsCache() : vcpu_( -1 ), valid_( false )
		{
		}

		Registers registers_;
		int vcpu_;
		bool valid_;
		std::mutex mutex_;
	};

public:
	struct DelayedWrite {
		DelayedWrite() : pending_( false )
		{
		}

		Registers registers_;
		bool pending_;
	};

public:
	// Create a XenDriver object with the domain name
	XenDriver( const std::string &domainName, LogHelper *logHelper = NULL, bool hvmOnly = true,
	           bool useAltP2m = false );

	// Create a XenDriver object with the domain ID (# xm list)
	XenDriver( domid_t domain, LogHelper *logHelper = NULL, bool hvmOnly = true, bool useAltP2m = false );

	virtual ~XenDriver();

public:
	virtual bool cpuCount( unsigned int &count ) const;

	virtual bool tscSpeed( unsigned long long &speed ) const;

	virtual bool mtrrType( unsigned long long guestAddress, uint8_t &type ) const;

	virtual bool setPageProtection( unsigned long long guestAddress, bool read, bool write, bool execute );

	virtual bool getPageProtection( unsigned long long guestAddress, bool &read, bool &write, bool &execute );

	virtual bool registers( unsigned short vcpu, Registers &regs ) const;

	virtual bool mtrrs( unsigned short vcpu, Mtrrs &m ) const;

	virtual bool setRegisters( unsigned short vcpu, const Registers &regs, bool setEip, bool delay );

	virtual bool writeToPhysAddress( unsigned long long address, void *buffer, size_t length );

	virtual bool enableMsrExit( unsigned int msr, bool &oldValue );

	virtual bool disableMsrExit( unsigned int msr, bool &oldValue );

	virtual bool isMsrEnabled( unsigned int msr, bool &enabled ) const
	{
		enabled = msrs_.find( msr ) != msrs_.end();
		return true;
	}

	virtual MapReturnCode mapPhysMemToHost( unsigned long long address, size_t length, uint32_t flags,
	                                        void *&pointer );

	virtual bool unmapPhysMem( void *hostPtr );

	virtual MapReturnCode mapVirtMemToHost( unsigned long long address, size_t length, uint32_t flags,
	                                        unsigned short vcpu, void *&pointer );

	virtual bool unmapVirtMem( void *hostPtr );

	virtual bool cacheGuestVirtAddr( unsigned long long addr );

	virtual bool requestPageFault( int vcpu, uint64_t addressSpace, uint64_t virtualAddress,
	                               uint32_t errorCode );

	virtual bool disableRepOptimizations();

	virtual bool shutdown();

	virtual bool pause();

	virtual bool unpause();

	virtual bool setPageCacheLimit( size_t limit );

	virtual bool getXSAVESize( unsigned short vcpu, size_t &size );

	virtual bool update();

	virtual std::string uuid() const
	{
		return uuid_;
	}

	virtual unsigned int id() const
	{
		return domain_;
	}

	virtual void enableCache( unsigned short vcpu );

	virtual void disableCache();

	virtual void flushPageProtections();

	uint32_t startTime();

public: // Xen specific-stuff
	xc_interface *nativeHandle() const
	{
		return xci_;
	}

	uint16_t altp2mViewId() const
	{
		return altp2mViewId_;
	}

public:
	static int32_t guestX86Mode( const Registers &regs );

	DelayedWrite &delayedWrite() { return delayedWrite_; }

	bool pendingInjection( unsigned short vcpu ) const;

	void clearInjection( unsigned short vcpu );

	int xenVersionMajor() const { return xenVersionMajor_; }

	int xenVersionMinor() const { return xenVersionMinor_; }

private:
	// Don't allow copying for these objects (class has xci_)
	XenDriver( const XenDriver & );

	// Don't allow copying for these objects (class has xci_)
	XenDriver &operator=( const XenDriver & );

private:
	void init( domid_t domain, bool hvmOnly );

	void cleanup();

	domid_t getDomainId( const std::string &domainName );

	unsigned int cpuid_eax( unsigned int op ) const;

	bool isVarMtrrOverlapped( const struct hvm_hw_mtrr &hwMtrr ) const;

	void getMtrrRange( uint64_t base_msr, uint64_t mask_msr, uint64_t &base, uint64_t &end ) const;

	bool getXCR0( unsigned short vcpu, uint64_t &xcr0 ) const;

private:
	xc_interface *xci_;
	xs_handle *xsh_;
	domid_t domain_;
	unsigned int physAddr_;
	std::set<unsigned int> msrs_;
	XenPageCache pageCache_;
	std::map<unsigned long long, unsigned long> addressCache_;
	int guestWidth_;
	LogHelper *logHelper_;
	std::string uuid_;
	bool useAltP2m_;
	uint16_t altp2mViewId_;
	mutable RegsCache regsCache_;
	bool update_;
	DelayedWrite delayedWrite_;
	std::map<unsigned long, xenmem_access_t> memAccessCache_;
	std::map<unsigned long, xenmem_access_t> delayedMemAccessWrite_;
	std::map<unsigned short, bool> pendingInjections_;
	std::mutex memAccessCacheMutex_;
	int xenVersionMajor_;
	int xenVersionMinor_;
	uint32_t startTime_;
};

} // namespace bdvmi

#endif // __BDVMIXENDRIVER_H_INCLUDED__
