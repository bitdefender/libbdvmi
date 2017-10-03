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
	XenDriver( const std::string &uuid, LogHelper *logHelper = nullptr, bool hvmOnly = true,
	           bool useAltP2m = false );

	// Create a XenDriver object with the domain ID (# xm list)
	XenDriver( domid_t domain, LogHelper *logHelper = nullptr, bool hvmOnly = true, bool useAltP2m = false );

	virtual ~XenDriver();

public:
	virtual bool cpuCount( unsigned int &count ) const;

	virtual bool tscSpeed( unsigned long long &speed ) const;

	virtual bool setPageProtection( unsigned long long guestAddress, bool read, bool write, bool execute );

	virtual bool getPageProtection( unsigned long long guestAddress, bool &read, bool &write, bool &execute );

	virtual bool registers( unsigned short vcpu, Registers &regs ) const;

	virtual bool setRegisters( unsigned short vcpu, const Registers &regs, bool setEip, bool delay );

	virtual bool writeToPhysAddress( unsigned long long address, void *buffer, size_t length );

	virtual MapReturnCode mapPhysMemToHost( unsigned long long address, size_t length, uint32_t flags,
	                                        void *&pointer );

	virtual bool unmapPhysMem( void *hostPtr );

	virtual MapReturnCode mapVirtMemToHost( unsigned long long address, size_t length, uint32_t flags,
	                                        unsigned short vcpu, void *&pointer );

	virtual bool unmapVirtMem( void *hostPtr );

	virtual bool requestPageFault( int vcpu, uint64_t addressSpace, uint64_t virtualAddress,
	                               uint32_t errorCode );

	virtual bool setRepOptimizations( bool enable );

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

	bool getXCR0( unsigned short vcpu, uint64_t &xcr0 ) const;

	bool getPAT( unsigned short vcpu, uint64_t &pat ) const;

private:
	xc_interface *xci_;
	xs_handle *xsh_;
	domid_t domain_;
	XenPageCache pageCache_;
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
	mutable bool patInitialized_;
	mutable uint64_t msrPat_;
};

} // namespace bdvmi

#endif // __BDVMIXENDRIVER_H_INCLUDED__
