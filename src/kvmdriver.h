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

#ifndef __BDVMIKVMDRIVER_H_INCLUDED__
#define __BDVMIKVMDRIVER_H_INCLUDED__

#include <string>
#include <memory>
#include <mutex>
#include <list>
#include <vector>
#include <set>
#include <bitset>
#include <unordered_map>
#include <atomic>
#include <libkvmi.h>
#include "bdvmi/driver.h"
#include "bdvmi/pagecache.h"

namespace bdvmi {

#define KVMI_SHUTDOWN_GUEST_FLAG ( 1 << 0 )
#define KVMI_REP_OPTIMIZATIONS_FLAG ( 1 << 1 )
#define KVMI_MAX_EPT_VIEWS 10

class KvmDriver : public Driver {
	using EventBitset = std::bitset<KVMI_NUM_EVENTS>;

public:
	struct RegsCache {
		Registers  registers_;
		int        vcpu_{ -1 };
		bool       valid_{ false };
		bool       dirty_{ false };
		uint16_t   view_{ 0 };
		std::mutex mutex_;
		bool       valid( unsigned short vcpu )
		{
			return valid_ && vcpu_ == static_cast<int>( vcpu );
		}
	};

	struct PendingVcpusCache {
		std::set<unsigned short> pendingVcpus_;
		std::mutex mutex_;
	};

	struct EventReply {
		explicit EventReply( const struct kvmi_dom_event *msg )
		{
			memset( &reply_, 0, sizeof( reply_ ) );
			reply_.vcpu_.vcpu     = msg->event.common.vcpu;
			reply_.common_.event  = msg->event.common.event;
			reply_.common_.action = KVMI_EVENT_ACTION_CONTINUE;
			seq_                  = msg->seq;
			size_                 = sizeof( reply_.vcpu_ ) + sizeof( reply_.common_ );
			switch ( reply_.common_.event ) {
				case KVMI_EVENT_CR:
					size_ += sizeof( reply_.event_.cr );
					break;
				case KVMI_EVENT_MSR:
					size_ += sizeof( reply_.event_.msr );
					break;
				case KVMI_EVENT_PF:
					size_ += sizeof( reply_.event_.pf );
					break;
			}
		}
		struct {
			struct kvmi_vcpu_hdr    vcpu_;
			struct kvmi_event_reply common_;
			union {
				struct kvmi_event_cr_reply  cr;
				struct kvmi_event_msr_reply msr;
				struct kvmi_event_pf_reply  pf;
			} event_;
		} reply_;
		unsigned int seq_;
		unsigned int size_;
	};

	KvmDriver( const std::string &domain, bool altp2m );

	virtual ~KvmDriver();

private:
	class BatchMessages {
	public:
		BatchMessages( void *dom, KvmDriver *driver );
		~BatchMessages();
		bool commit();
		bool addRegisters() const;
		bool addEventReply( EventReply &reply ) const;
		bool addPageAccess( unsigned long long int &gpa, unsigned char &access, unsigned short count,
		                    unsigned short view ) const;
		bool addPauseVcpu( unsigned short vcpu ) const;

	private:
		void *     grp_{ nullptr };
		KvmDriver *driver_;
	};

	friend class BatchMessages;

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

	bool getRepOptimizations() const;

	bool shutdown() override;

	bool testShutdown();

	bool pause() override;

	bool unpause() override;

	bool pauseAllVcpus();

	bool kickAllVcpus();

	size_t setPageCacheLimit( size_t limit ) override;

	unsigned short eptpIndex( unsigned short vcpu ) const override;

	bool getEPTPageConvertible( unsigned short index, unsigned long long address, bool &convertible ) override;

	bool initialViewSetup( unsigned short vcpu );

	bool controlEPTview( unsigned short vcpu, unsigned short view, bool visible);

	bool getNextAvailableView( unsigned short &index );

	bool createEPT( unsigned short &index ) override;

	bool destroyEPT( unsigned short index ) override;

	bool vcpuSwitchView( unsigned short vcpu, unsigned short index );

	bool switchEPT( unsigned short index ) override;

	bool setVEInfoPage( unsigned short vcpu, unsigned long long gpa ) override;

	bool disableVE( unsigned short vcpu ) override;

	bool getXSAVESize( unsigned short vcpu, size_t &size ) override;

	bool getXSAVEArea( unsigned short vcpu, void *buffer, size_t bufSize ) override;

	bool update() override;

	std::string uuid() const override;

	unsigned int id() const override;

	void enableCache( unsigned short /* vcpu */ ) override
	{
		// useless
	}

	void disableCache() override;

	bool registerVMEvent( unsigned int id, bool enable ) const;

	bool registerEvent( unsigned short vcpu, unsigned int id, bool enable ) const;

	bool registerMSREvents( unsigned short vcpu, unsigned int msr, bool enable ) const;

	bool registerCREvents( unsigned short vcpu, unsigned int cr, bool enable ) const;

	bool flushCtrlEvents( unsigned short vcpu, const std::set<unsigned int> &enabledCrs,
	                      const std::set<unsigned int> &enabledMsrs );

	bool flushEvents( unsigned short vcpu );

	bool flushCREvents( unsigned short vcpu, const std::set<unsigned int> &enabledCrs );

	bool flushMSREvents( unsigned short vcpu, const std::set<unsigned int> &enabledMsrs );

	uint32_t startTime() override;

	bool isMsrCached( uint64_t msr ) const override;

	// Does this driver support altp2m #VE?
	bool veSupported() const override
	{
		return veSupported_;
	}

	// Does this driver support altp2m VMFUNC?
	bool vmfuncSupported() const override
	{
		return eptpSupported_;
	}

	// Does this driver support Intel SPP?
	bool sppSupported() const override
	{
		return false;
	}

	// Does this driver support DTR events?
	bool dtrEventsSupported() const override
	{
		return true;
	}

	void skipInstruction( const short instructionSize );

	void loadRegisters( Registers &regs, const struct kvmi_event &event ) const;

	unsigned long long getNextRip() const;

	bool getEventMsg( struct kvmi_dom_event *&event, int ms, bool &abort );

	void pauseEventReceived();

	size_t pendingPauseEvents() const
	{
		return pendingPauseEvents_;
	}

	void waitForUnpause()
	{
		std::lock_guard<std::mutex> lock( eventProcessingMutex_ );
	}

	bool isConnected();

	void suspending( bool value );

	bool suspending() const;

	void beginEvent( Registers &regs, const struct kvmi_event &event );

	bool replyEvent( EventReply &reply );

	void setVcpuEventsDirty();

	void setVcpuVectorSize();

	bool updateVcpuCount();

	bool setVcpuEvents( unsigned int id );

	void setVcpuEventsLater( unsigned int id );

	bool clearVcpuEvents( unsigned int id );

	bool clearVcpuEvents();

	void enablePendingVcpusCache();

	bool getXCR0( unsigned short /* vcpu */, uint64_t & /* xcr0 */ ) const override
	{
		return false;
	}

private:
	void *mapGuestPageImpl( unsigned long long gfn ) override;

	void unmapGuestPageImpl( void *hostPtr, unsigned long long gfn ) override;

	bool setPageProtectionImpl( const MemAccessMap &accessMap, unsigned short view ) override;

	bool getPageProtectionImpl( unsigned long long guestAddress, bool &read, bool &write, bool &execute,
	                            unsigned short view ) override;

	bool setPageConvertibleImpl( const ConvertibleMap &convMap, unsigned short view ) override;

	bool isViewCacheEnabled( unsigned short vcpu, unsigned short &view ) const;

	void enableVcpuCache( unsigned short vcpu, unsigned short view, const Registers &regs );

	void updateVcpuCache( unsigned short view );

	bool isPendingVcpusCacheEnabled( unsigned short vcpu ) const;

	void disablePendingVcpusCache( unsigned short vcpu );

	bool maxGPFNImpl( unsigned long long &gfn, bool &trustworthy ) override;

private:
	KvmDriver( const KvmDriver & );

	KvmDriver &operator=( const KvmDriver & );

private:
	struct vcpuEvents {
		bool                   dirty_{ true };
		EventBitset            enabled_;
		std::set<unsigned int> enabledCrs_;
		std::set<unsigned int> enabledMsrs_;
	};

	int                               flags_{ KVMI_REP_OPTIMIZATIONS_FLAG };
	void *                            domCtx_;
	std::string                       domain_;
	int64_t                           startTime_;
	mutable RegsCache                 regsCache_;
	PageCache                         pageCache_;
	bool                              suspending_{ false };
	size_t                            pauseCount_{ 0 };
	std::mutex                        pauseMutex_;
	size_t                            pendingPauseEvents_{ 0 };
	std::mutex                        eventProcessingMutex_;
	mutable std::atomic<unsigned int> vcpuCount_{ 0 };
	std::vector<struct vcpuEvents>    vcpuEvents_;
	EventBitset                       enabledEvents_;
	std::unique_ptr<BatchMessages>    batch_;
	bool                              eptpSupported_{ false };
	bool                              veSupported_{ false };
	unsigned short                    untrustedView_{ 0 };
	mutable PendingVcpusCache         pendingCache_;
	unsigned short                    vcpuPendingSwitchCount_{ 0 };

	/* EPT views available for VMFUNC */
	std::array<bool, KVMI_MAX_EPT_VIEWS> guestVisibleEPTviews_{ };
};
} // namespace bdvmi

#endif // __BDVMIKVMDRIVER_H_INCLUDED__
