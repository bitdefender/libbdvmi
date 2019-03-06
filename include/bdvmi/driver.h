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

#ifndef __BDVMIDRIVER_H_INCLUDED__
#define __BDVMIDRIVER_H_INCLUDED__

#include <stdint.h>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <string>

#define PAGE_SHIFT 12
#define PAGE_SIZE ( 1UL << PAGE_SHIFT )
#define PAGE_MASK ( ~( PAGE_SIZE - 1 ) )

#define gpa_to_gfn( pa ) ( ( unsigned long )( ( pa ) >> PAGE_SHIFT ) )
#define gfn_to_gpa( fn ) ( ( unsigned long )( ( fn ) << PAGE_SHIFT ) )

/* From xen/include/asm-x86/msr-index.h */
#define MSR_IA32_SYSENTER_CS 0x00000174
#define MSR_IA32_SYSENTER_ESP 0x00000175
#define MSR_IA32_SYSENTER_EIP 0x00000176
#define MSR_IA32_CR_PAT 0x00000277
#define MSR_IA32_MISC_ENABLE 0x000001a0
#define MSR_IA32_MC0_CTL 0x00000400

#define MSR_EFER 0xc0000080           /* extended feature register */
#define MSR_STAR 0xc0000081           /* legacy mode SYSCALL target */
#define MSR_LSTAR 0xc0000082          /* long mode SYSCALL target */
#define MSR_CSTAR 0xc0000083          /* compat mode SYSCALL target */
#define MSR_FS_BASE 0xc0000100        /* 64bit FS base */
#define MSR_GS_BASE 0xc0000101        /* 64bit GS base */
#define MSR_SHADOW_GS_BASE 0xc0000102 /* SwapGS GS shadow */

namespace bdvmi {

class PageCache;

struct Registers {

	enum GuestX86Mode { ERROR, CS_TYPE_16, CS_TYPE_32, CS_TYPE_64 };

	uint64_t sysenter_cs{};
	uint64_t sysenter_esp{};
	uint64_t sysenter_eip{};
	uint64_t msr_efer{};
	uint64_t msr_star{};
	uint64_t msr_lstar{};
	uint64_t msr_pat{};
	uint64_t msr_cstar{};

	uint64_t cs_base{};
	uint64_t cs_limit{};
	uint64_t cs_sel{};
	uint64_t ss_base{};
	uint64_t ss_limit{};
	uint64_t ss_sel{};
	uint64_t ss_arbytes{};
	uint64_t ds_base{};
	uint64_t ds_limit{};
	uint64_t ds_sel{};
	uint64_t ds_arbytes{};
	uint64_t es_base{};
	uint64_t es_limit{};
	uint64_t es_sel{};
	uint64_t es_arbytes{};
	uint64_t fs_limit{};
	uint64_t fs_sel{};
	uint64_t fs_arbytes{};
	uint64_t gs_limit{};
	uint64_t gs_sel{};
	uint64_t gs_arbytes{};
	uint64_t shadow_gs{};

	uint64_t fs_base{};
	uint64_t gs_base{};
	uint64_t idtr_base{};
	uint64_t idtr_limit{};
	uint64_t gdtr_base{};
	uint64_t gdtr_limit{};

	uint64_t rax{};
	uint64_t rcx{};
	uint64_t rdx{};
	uint64_t rbx{};
	uint64_t rsp{};
	uint64_t rbp{};
	uint64_t rsi{};
	uint64_t rdi{};
	uint64_t r8{};
	uint64_t r9{};
	uint64_t r10{};
	uint64_t r11{};
	uint64_t r12{};
	uint64_t r13{};
	uint64_t r14{};
	uint64_t r15{};
	uint64_t rflags{};
	uint64_t rip{};
	uint64_t cr0{};
	uint64_t cr2{};
	uint64_t cr3{};
	uint64_t cr4{};

	uint32_t cs_arbytes{};

	GuestX86Mode guest_x86_mode{ ERROR };
};

enum MapReturnCode { MAP_SUCCESS, MAP_FAILED_GENERIC, MAP_PAGE_NOT_PRESENT, MAP_INVALID_PARAMETER };

class EventHandler;

class Driver {

public:
	enum PageRestriction { PAGE_READ = 1 << 0, PAGE_WRITE = 1 << 1, PAGE_EXECUTE = 1 << 2 };

	using MemAccessMap     = std::map<uint64_t, uint8_t>;
	using ViewMemAccessMap = std::map<uint16_t, MemAccessMap>;

public:
	Driver( EventHandler *handler = nullptr )
	    : handler_{ handler }
	{
	}

	// base class => virtual destructor
	virtual ~Driver() = default;

public:
	void handler( EventHandler *h )
	{
		handler_ = h;
	}

	EventHandler *handler() const
	{
		return handler_;
	}

public:
	// Get VCPU count
	virtual bool cpuCount( unsigned int &count ) const = 0;

	// Get TSC speed
	virtual bool tscSpeed( unsigned long long &speed ) const = 0;

	// Set guest page protection (_NOT_ virtual)
	bool setPageProtection( unsigned long long guestAddress, bool read, bool write, bool execute,
	                        unsigned short view = 0 );

	// Get guest page protection (_NOT_ virtual)
	bool getPageProtection( unsigned long long guestAddress, bool &read, bool &write, bool &execute,
	                        unsigned short view = 0 );

	// Flush page protections (_NOT_ virtual)
	void flushPageProtections();

	// Get registers
	virtual bool registers( unsigned short vcpu, Registers &regs ) const = 0;

	// Set registers
	virtual bool setRegisters( unsigned short vcpu, const Registers &regs, bool setEip, bool delay ) = 0;

	virtual MapReturnCode mapPhysMemToHost( unsigned long long address, size_t length, uint32_t flags,
	                                        void *&pointer ) = 0;

	virtual bool unmapPhysMem( void *hostPtr ) = 0;

	virtual bool requestPageFault( int vcpu, uint64_t addressSpace, uint64_t virtualAddress,
	                               uint32_t errorCode ) = 0;

	virtual bool setRepOptimizations( bool enable ) = 0;

	virtual bool shutdown() = 0;

	virtual bool pause() = 0;

	virtual bool unpause() = 0;

	virtual size_t setPageCacheLimit( size_t limit ) = 0;

	virtual bool getXSAVESize( unsigned short vcpu, size_t &size ) = 0;

	virtual bool getXSAVEArea( unsigned short vcpu, void *buffer, size_t bufSize ) = 0;

	virtual bool maxGPFN( unsigned long long &gfn ) = 0;

	virtual bool getEPTPageConvertible( unsigned short index, unsigned long long address, bool &convertible ) = 0;

	virtual bool setEPTPageConvertible( unsigned short index, unsigned long long address, bool convertible ) = 0;

	virtual bool createEPT( unsigned short &index ) = 0;

	virtual bool destroyEPT( unsigned short index ) = 0;

	virtual bool switchEPT( unsigned short index ) = 0;

	virtual bool setVEInfoPage( unsigned short vcpu, unsigned long long gpa ) = 0;

	virtual bool disableVE( unsigned short vcpu ) = 0;

	virtual unsigned short eptpIndex() const = 0;

	virtual bool update() = 0;

	virtual std::string uuid() const = 0;

	virtual unsigned int id() const = 0;

	virtual void enableCache( unsigned short vcpu ) = 0;

	virtual void disableCache() = 0;

	virtual uint32_t startTime() = 0;

	virtual bool isMsrCached( uint64_t msr ) const = 0;

	// Does this driver support altp2m #VE?
	virtual bool veSupported() const = 0;

	// Does this driver support altp2m VMFUNC?
	virtual bool vmfuncSupported() const = 0;

	// Does this driver support Intel SPP?
	virtual bool sppSupported() const = 0;

	// Does this driver support DTR events?
	virtual bool dtrEventsSupported() const = 0;

private:
	virtual void *mapGuestPageImpl( unsigned long long gfn ) = 0;

	virtual void unmapGuestPageImpl( void *hostPtr, unsigned long long gfn ) = 0;

	virtual bool setPageProtectionImpl( const MemAccessMap &accessMap, unsigned short view ) = 0;

	// Get guest page protection
	virtual bool getPageProtectionImpl( unsigned long long guestAddress, bool &read, bool &write, bool &execute,
	                                    unsigned short view ) = 0;

private:
	EventHandler *   handler_{ nullptr };
	ViewMemAccessMap memAccessCache_;
	ViewMemAccessMap delayedMemAccessWrite_;
	std::mutex       memAccessCacheMutex_;

	friend class PageCache;
};

} // namespace bdvmi

#endif // __BDVMIDRIVER_H_INCLUDED__
