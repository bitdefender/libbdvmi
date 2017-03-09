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

#ifndef __BDVMIDRIVER_H_INCLUDED__
#define __BDVMIDRIVER_H_INCLUDED__

#include <stdint.h>
#include <cstdlib>
#include <cstring>
#include <string>

namespace bdvmi {

struct Registers {

	enum GuestX86Mode { ERROR, CS_TYPE_16, CS_TYPE_32, CS_TYPE_64 };

	Registers()
	{
		memset( this, 0, sizeof( Registers ) );
	}

	uint64_t sysenter_cs;
	uint64_t sysenter_esp;
	uint64_t sysenter_eip;
	uint64_t msr_efer;
	uint64_t msr_star;
	uint64_t msr_lstar;

	uint64_t cs_base;
	uint64_t cs_limit;
	uint64_t cs_sel;
	uint64_t ss_base;
	uint64_t ss_limit;
	uint64_t ss_sel;
	uint64_t ss_arbytes;
	uint64_t ds_base;
	uint64_t ds_limit;
	uint64_t ds_sel;
	uint64_t ds_arbytes;
	uint64_t es_base;
	uint64_t es_limit;
	uint64_t es_sel;
	uint64_t es_arbytes;
	uint64_t fs_limit;
	uint64_t fs_sel;
	uint64_t fs_arbytes;
	uint64_t gs_limit;
	uint64_t gs_sel;
	uint64_t gs_arbytes;

	uint64_t fs_base;
	uint64_t gs_base;
	uint64_t idtr_base;
	uint64_t idtr_limit;
	uint64_t gdtr_base;
	uint64_t gdtr_limit;

	uint64_t rax;
	uint64_t rcx;
	uint64_t rdx;
	uint64_t rbx;
	uint64_t rsp;
	uint64_t rbp;
	uint64_t rsi;
	uint64_t rdi;
	uint64_t r8;
	uint64_t r9;
	uint64_t r10;
	uint64_t r11;
	uint64_t r12;
	uint64_t r13;
	uint64_t r14;
	uint64_t r15;
	uint64_t rflags;
	uint64_t rip;
	uint64_t cr0;
	uint64_t cr2;
	uint64_t cr3;
	uint64_t cr4;
	uint64_t cr8;

	uint32_t cs_arbytes;

	GuestX86Mode guest_x86_mode;
};

struct Mtrrs {

	Mtrrs()
	{
		memset( this, 0, sizeof( Mtrrs ) );
	}

	uint64_t pat;
	uint64_t cap;
	uint64_t def_type;
};

enum MapReturnCode { MAP_SUCCESS, MAP_FAILED_GENERIC, MAP_PAGE_NOT_PRESENT, MAP_INVALID_PARAMETER };

class EventHandler;

/*
 * The functions a driver implements are not allowed to throw exceptions,
 * because they will be called from ms_abi (WINAPI) functions, and GCC
 * has issues with that: http://gcc.gnu.org/bugzilla/show_bug.cgi?id=49146
 *
 * Hence, the throw() guarantee.
 */
class Driver {

public:
	Driver( EventHandler *handler = NULL ) : handler_( handler )
	{
	}

	// base class => virtual destructor
	virtual ~Driver()
	{
	}

public:
	void handler( EventHandler *h )
	{
		handler_ = h;
	}

	EventHandler * handler() const
	{
		return handler_;
	}

public:
	// Get VCPU count
	virtual bool cpuCount( unsigned int &count ) const throw() = 0;

	// Get TSC speed
	virtual bool tscSpeed( unsigned long long &speed ) const throw() = 0;

	// Get MTRR type for guestAddress
	virtual bool mtrrType( unsigned long long guestAddress, uint8_t &type ) const throw() = 0;

	// Set guest page protection
	virtual bool setPageProtection( unsigned long long guestAddress, bool read, bool write,
	                                bool execute ) throw() = 0;

	// Get guest page protection
	virtual bool getPageProtection( unsigned long long guestAddress, bool &read, bool &write, bool &execute )
	                                throw() = 0;

	// Get registers
	virtual bool registers( unsigned short vcpu, Registers &regs ) const throw() = 0;

	// Get Mtrrs
	virtual bool mtrrs( unsigned short vcpu, Mtrrs &m ) const throw() = 0;

	// Set registers
	virtual bool setRegisters( unsigned short vcpu, const Registers &regs, bool setEip, bool delay ) throw() = 0;

	// Write to physical address
	virtual bool writeToPhysAddress( unsigned long long address, void *buffer, size_t length ) throw() = 0;

	// Enable monitoring for changes at this MSR address
	virtual bool enableMsrExit( unsigned int msr, bool &oldValue ) throw() = 0;

	// Disable monitoring for changes at this MSR address
	virtual bool disableMsrExit( unsigned int msr, bool &oldValue ) throw() = 0;

	// Should we have the introengine look at this MSR address?
	virtual bool isMsrEnabled( unsigned int msr, bool &enabled ) const throw() = 0;

	virtual MapReturnCode mapPhysMemToHost( unsigned long long address, size_t length, uint32_t flags,
	                                        void *&pointer ) throw() = 0;

	virtual bool unmapPhysMem( void *hostPtr ) throw() = 0;

	virtual MapReturnCode mapVirtMemToHost( unsigned long long address, size_t length, uint32_t flags,
	                                        unsigned short vcpu, void *&pointer ) throw() = 0;

	virtual bool cacheGuestVirtAddr( unsigned long long addr ) throw() = 0;

	virtual bool unmapVirtMem( void *hostPtr ) throw() = 0;

	virtual bool requestPageFault( int vcpu, uint64_t addressSpace, uint64_t virtualAddress,
	                               uint32_t errorCode ) throw() = 0;

	virtual bool disableRepOptimizations() throw() = 0;

	virtual bool shutdown() throw() = 0;

	virtual bool pause() throw() = 0;

	virtual bool unpause() throw() = 0;

	virtual bool setPageCacheLimit( size_t limit ) throw() = 0;

	virtual bool getXSAVESize( unsigned short vcpu, size_t &size ) throw() = 0;

	virtual bool update() throw() = 0;

	virtual std::string uuid() const throw() = 0;

	virtual unsigned int id() const throw() = 0;

	virtual void enableCache( unsigned short vcpu ) = 0;

	virtual void disableCache() = 0;

	virtual void flushPageProtections() = 0;

	virtual uint32_t startTime() = 0;

private:
	EventHandler *handler_;
};

} // namespace bdvmi

#endif // __BDVMIDRIVER_H_INCLUDED__
