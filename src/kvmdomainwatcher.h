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

#ifndef __BDVMIKVMDOMAINWATCHER_H_INCLUDED__
#define __BDVMIKVMDOMAINWATCHER_H_INCLUDED__

#include <unordered_map>
#include <mutex>
#include <condition_variable>
#include <libkvmi.h>

#include "bdvmi/domainwatcher.h"

namespace bdvmi {

class KvmDomainWatcher : public DomainWatcher {
	class KvmDomain {
	private:
		void *ctx_{ nullptr };

		enum { NEW,
		       FORKED,
		       PARKED,
		       RESURRECTED,
		} state_ = { NEW };

		void close( bool shutdown )
		{
			if ( ctx_ ) {
				kvmi_domain_close( ctx_, shutdown );
				ctx_   = nullptr;
				state_ = NEW;
			}
		}

	public:
		void forgetWithShutdown()
		{
			close( true );
		}
		void forget()
		{
			close( false );
		}
		~KvmDomain()
		{
			// Called from parent (state_ != FORKED) and child ( state_ == FORKED )
			if ( state_ != FORKED )
				forgetWithShutdown();
		}
		std::string name() const
		{
			// libkvmi puts zero terminated string
			char buf[64] = {};

			kvmi_domain_name( ctx_, buf, sizeof( buf ) );
			return buf;
		}
		void *context() const
		{
			return ctx_;
		}
		void connect( void *ctx )
		{
			// guest time
			kvmi_control_vm_events( ctx, KVMI_EVENT_UNHOOK, true );
			ctx_ = ctx;
		}
		void fork()
		{
			state_ = FORKED;
		}
		void park()
		{
			state_ = PARKED;
		}
		bool resetSafely()
		{
			if ( !ctx_ )
				return true;

			if ( state_ == FORKED )
				return false;

			forgetWithShutdown();
			state_ = RESURRECTED;
			return true;
		}
		bool isNew() const
		{
			return ctx_ && state_ == NEW;
		}
		bool isResurrected() const
		{
			return ctx_ && state_ == RESURRECTED;
		}
		bool isParked() const
		{
			return ctx_ && state_ == PARKED;
		}
		bool getEvent( kvmi_dom_event **event )
		{
			if ( kvmi_wait_event( ctx_, KVMI_NOWAIT ) ) {
				if ( errno == ETIMEDOUT )
					errno = 0;
				return false;
			}

			return kvmi_pop_event( ctx_, event ) == 0;
		}
	};

public:
	explicit KvmDomainWatcher( sig_atomic_t &sigStop );

	virtual ~KvmDomainWatcher();

public:
	bool accessGranted() override;

	static void *domainContext( const std::string &name );

	void setAuthCookie( const std::string &authCookie ) override;

	// Merge with Xen
	bool ownUuid( std::string &uuid ) const override
	{
		uuid = ownUuid_;
		return true;
	}

private:
	bool waitForDomainsOrTimeout( std::list<DomainInfo> &domains, int ms ) override;

	void forkingHandler( const std::string &uuid ) override;

	void forkedHandler( const std::string &uuid, bool parent = true ) override;

	void diedHandler( const std::string &uuid ) override;

	KvmDomainWatcher( const KvmDomainWatcher & );

	KvmDomainWatcher &operator=( const KvmDomainWatcher & );

	bool queueConnection( const std::string &name, void *dom );

	void signalNewConnection();

	void handleDomainEvent( const struct kvmi_dom_event *ev, const std::string &uuid ) const;

	void getAuthCookie( std::string &authCookie ) const
	{
		std::lock_guard<std::mutex> guard( authCookieMutex_ );

		authCookie = authCookie_;
	}

	bool loadLibkvmiOnce();

	static void LogCallback( kvmi_log_level level, const char *s, void *ctx );

protected:
	static int newConnection( void *dom, unsigned char ( *uuid )[16], void *ctx );

	static int newHandshake( const void *qemu, void *intro, void *ctx );

private:
	using name2dom_t = std::unordered_map<std::string, KvmDomain>;

	void *kvmi_{ nullptr };

	std::mutex              mutexQueue_;
	std::condition_variable ringQueue_;

	static name2dom_t knownDomains_;

	mutable std::mutex authCookieMutex_;
	std::string        authCookie_;

	std::string ownUuid_;
};
} // namespace bdvmi

#endif // __BDVMIKVMDOMAINWATCHER_H_INCLUDED__
