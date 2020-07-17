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

#include "kvmdomainwatcher.h"
#include "kvmdriver.h"
#include "utils.h"
#include "bdvmi/logger.h"
#include <string.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <chrono>
#include <openssl/sha.h>
#include <fstream>
#include <algorithm>

namespace {

constexpr char UUID_PROVIDER[] = "/sys/devices/virtual/dmi/id/product_uuid";

bool getSvaUuid( std::string &uuid )
{
	std::ifstream in( UUID_PROVIDER );

	if ( in ) {
		in >> uuid;

		std::transform( std::begin( uuid ), std::end( uuid ), std::begin( uuid ), ::tolower );
	}

	return !!in;
}

} // namespace

namespace bdvmi {

KvmDomainWatcher::name2dom_t KvmDomainWatcher::knownDomains_;

std::string UuidToString( const unsigned char ( *uuid )[16] )
{
	char str[37] = {};

	uuid_unparse( *uuid, str );

	return str;
}

void KvmDomainWatcher::LogCallback( kvmi_log_level level, const char *s, void * /* ctx */ )
{
	// NOTE: (for alazar) - ctx is now unused, unless you want to reserve it for
	// something in the future it should probably be removed altogether now.

	switch ( level ) {
		case KVMI_LOG_LEVEL_DEBUG:
			logger << DEBUG << "KVMI: " << s << std::flush;
			break;
		case KVMI_LOG_LEVEL_INFO:
			logger << INFO << "KVMI: " << s << std::flush;
			break;
		case KVMI_LOG_LEVEL_WARNING:
			logger << WARNING << "KVMI: " << s << std::flush;
			break;
		case KVMI_LOG_LEVEL_ERROR:
			logger << ERROR << "KVMI: " << s << std::flush;
			break;
		default:
			logger << ERROR << "KVMI: UNKNOWN LEVEL: " << s << std::flush;
			break;
	}
}

bool KvmDomainWatcher::loadLibkvmiOnce()
{
	if ( kvmi_ )
		return true;

	kvmi_ = kvmi_init_vsock( 1234, newConnection, reinterpret_cast<kvmi_handshake_cb>( newHandshake ), this );

	return !!kvmi_;
}

KvmDomainWatcher::KvmDomainWatcher( sig_atomic_t &sigStop )
    : DomainWatcher{ sigStop }
{
	if ( !getSvaUuid( ownUuid_ ) )
		logger << ERROR << "Can't get our own UUID!" << std::flush;

	kvmi_set_log_cb( LogCallback, nullptr );

	if ( !loadLibkvmiOnce() ) {
		logger << WARNING << "kvmi_init failed: " << strerror( errno ) << std::flush;
		logger << INFO << "Waiting for libvirt credentials to enable vsock support" << std::flush;
	}
}

bool KvmDomainWatcher::accessGranted()
{
	return loadLibkvmiOnce();
}

KvmDomainWatcher::~KvmDomainWatcher()
{
	kvmi_uninit( kvmi_ );

	kvmi_set_log_cb( nullptr, nullptr );
}

// This is a callback invoked by libkvmi
int KvmDomainWatcher::newConnection( void *dom, unsigned char ( *uuid )[16], void *ctx )
{
	KvmDomainWatcher *kdw        = static_cast<KvmDomainWatcher *>( ctx );
	const std::string clientUuid = UuidToString( uuid );

	if ( !kdw->queueConnection( clientUuid, dom ) )
		return -1;

	kdw->signalNewConnection();

	return 0;
}

// This is a callback invoked by libkvmi
int KvmDomainWatcher::newHandshake( const void *_qemu, void *_intro, void *ctx )
{
	KvmDomainWatcher *kdw = static_cast<KvmDomainWatcher *>( ctx );

	const kvmi_qemu2introspector *qemu = static_cast<const kvmi_qemu2introspector *>( _qemu );
	const std::string             uuid = UuidToString( &qemu->uuid );

	if ( kdw->sigStop_ ) {
		logger << WARNING << "[" << uuid << "] New handshake refused" << std::flush;
		return -1;
	}

	std::string cookie;

	kdw->getAuthCookie( cookie );
	logger << DEBUG << "[" << uuid << "] Handshake authCookie: '" << cookie << "'" << std::flush;

	kvmi_introspector2qemu *intro = static_cast<kvmi_introspector2qemu *>( _intro );

	SHA_CTX sha;
	SHA1_Init( &sha );
	SHA1_Update( &sha, cookie.c_str(), cookie.size() );
	SHA1_Final( intro->cookie_hash, &sha );

	return 0;
}

void KvmDomainWatcher::signalNewConnection()
{
	ringQueue_.notify_one();
}

bool KvmDomainWatcher::queueConnection( const std::string &name, void *domCtx )
{
	std::unique_lock<std::mutex> lock( mutexQueue_ );

	auto found = knownDomains_.find( name );

	KvmDomainWatcher::KvmDomain *dom;

	if ( found != knownDomains_.end() ) {
		dom = &found->second;
		if ( !dom->resetSafely() ) {
			logger << WARNING << "[" << name
			       << "] Drop the connection. The child didn't finish the old one." << std::flush;
			lock.unlock();
			// Allow diedHandler() to park() the domain
			sleep( 1 ); // :D
			return false;
		}
	} else {
		auto res = knownDomains_.emplace( name, KvmDomain() );
		dom      = &res.first->second;
	}

	dom->connect( domCtx );

	return true;
}

void KvmDomainWatcher::handleDomainEvent( const struct kvmi_dom_event *ev, const std::string &uuid ) const
{
	uint32_t eventID = ev->event.common.event;

	if ( eventID != KVMI_EVENT_UNHOOK )
		logger << ERROR << "[" << uuid << "] We've got an unexpected event " << eventID << std::flush;
}

//
// We have 4 parties using/watching the socket and only a read() would detect
// if the other site closed the socket (both users from the other site
// closed the fd) or one of 4 called shutdown(socket,RW).
//
//     QEMU ------------------> hanshake <------------- bdmid/parent (KvmDomainWatcher)
//      \                                                 |
//       v                                                v
//      Kernel (shutdown) ----> introspection <-------- bdmid/child
//
// bdmid/parent holds the socket/connection and announce the new domain on every
// reconnection (the guest might have been restarted). Following the announcement,
// the child will be started and it will read from socket. Once the child dies
// (with the introspection disabled or crashed), the parent will read the socket
// and get either:
//    a) 0 bytes - the socket has been closed by kernel/QEMU
//         (the child doesn't call shutdown())
//    b) unexpected event => the parent will shutdown the socket
//         in order to catch this case before we pin release/1.0
//         (the child must ensure that the kernel won't send events
//          once the introspection is disabled)
// The child could:
//    a) crash while not hooked, hooking, hooked or unhooking
//    b) unhook and exit nicely (guest not supported, policy, signal
//       or Introcore detected the shutdown (future development))
//
// KvmDomainWatcher behaves like XenDomainWatcher:
//    a) every connection/reconnection means guest PowerOn/Resume or "bd start"
//          KvmDomain::FRESH/RESURRECTED, DomainInfo::STATE_NEW
//    b) every disconnect means guest PowerOff/Reboot/Suspend
//          following KvmDomain::PARKED (child died)
//            KvmDomain::FRESH, DomainInfo::STATE_FINISHED
//    b1) bugs in child/unhook
//            KvmDomain::FRESH, DomainInfo::STATE_FINISHED
//            the guest should be restarted
//
// TODO:
//    a) KvmDomainWatcher should watch PowerOn/Off events through libvirt
//    b) KvmDriver should start the accepting thread (kvmi_init())
//       (currenly, any connect()/handshake blocks the hooking of other guests).
//    c) Use the connection time as "Guest start time"
//       and drop kvmi_qemu2introspector.start_time
//
bool KvmDomainWatcher::waitForDomainsOrTimeout( std::list<DomainInfo> &domains, int ms )
{
	// First function used by the callers is this one or accessGranted().
	// The exception below has been moved here from constructor
	// in order to allow the callers to wait/loop until accessGranted() returns true.
	if ( !kvmi_ )
		throw std::runtime_error( "kvmi_init() has failed" );

	domains.clear();

	std::unique_lock<std::mutex> lock( mutexQueue_ );

	for ( auto &&known : knownDomains_ ) {
		const std::string &uuid = known.first;
		KvmDomain &        dom  = known.second;

		if ( ( dom.isNew() || dom.isResurrected() ) && uuid == ownUuid_ ) {
			dom.park();
		} else if ( dom.isNew() ) {
			domains.emplace_back( uuid, DomainInfo::STATE_NEW, dom.name() );

			dom.park();
		} else if ( dom.isResurrected() ) {
			domains.emplace_back( uuid, DomainInfo::STATE_FINISHED );
			domains.emplace_back( uuid, DomainInfo::STATE_NEW, dom.name() );

			dom.park();
		} else if ( dom.isParked() ) {
			CUniquePtr<kvmi_dom_event> evPtr;
			kvmi_dom_event *           ev       = nullptr;
			bool                       gotEvent = dom.getEvent( &ev );
			int                        err      = errno;

			evPtr.reset( ev );

			if ( gotEvent && uuid == ownUuid_ ) {
				logger << WARNING << "Detected pause, suspend, shutdown or migrate." << std::flush;
				handleDomainEvent( ev, uuid );
				suspendIntrospectorDomain_ = true;
				stop();
				return false;
			} else if ( gotEvent ) {
				handleDomainEvent( ev, uuid );

				domains.emplace_back( uuid, DomainInfo::STATE_FINISHED );

				dom.forgetWithShutdown();
			} else if ( err && uuid == ownUuid_ ) {
				logger << WARNING << "[" << uuid << "] Mother ship connection lost: (" << err << ") "
				       << strerror( err ) << std::flush;

				dom.forgetWithShutdown();
			} else if ( err ) {
				logger << WARNING << "[" << uuid << "] Connection closed (" << err << ") "
				       << strerror( err ) << std::flush;
				domains.emplace_back( uuid, DomainInfo::STATE_FINISHED );

				dom.forgetWithShutdown();
			}
		}
	}

	if ( !domains.empty() )
		return true;

	std::cv_status rc = ringQueue_.wait_for( lock, std::chrono::milliseconds( ms ) );

	return rc != std::cv_status::timeout;
}

void KvmDomainWatcher::forkingHandler( const std::string &uuid )
{
	std::unique_lock<std::mutex> lock( mutexQueue_ );

	auto found = knownDomains_.find( uuid );

	if ( found == knownDomains_.end() )
		logger << WARNING << "[" << uuid << "] Unknown domain." << std::flush;
	else
		found->second.fork();
}

void KvmDomainWatcher::forkedHandler( const std::string &name, bool parent )
{
	if ( !parent ) {
		auto dom = knownDomains_.begin();

		//
		// This is the child bdmid. Remove from the list of known domains
		// all but that which represents us. This frees up some memory while
		// also making sure we have no reference to the sockets corresponding
		// to other domains
		//
		while ( dom != knownDomains_.end() ) {
			if ( dom->first != name ) {
				dom->second.forget();
				knownDomains_.erase( dom );
				dom = knownDomains_.begin();
			} else
				++dom;
		}

		kvmi_close( kvmi_ );

		return;
	}
}

// This is invoked by child::KvmDriver (this is why knowDomains_ is static)
void *KvmDomainWatcher::domainContext( const std::string &name )
{
	const auto dom = knownDomains_.find( name );

	if ( dom == knownDomains_.end() )
		return nullptr;

	return dom->second.context();
}

void KvmDomainWatcher::setAuthCookie( const std::string &authCookie )
{
	std::lock_guard<std::mutex> guard( authCookieMutex_ );

	authCookie_ = authCookie;
}

void KvmDomainWatcher::diedHandler( const std::string &uuid )
{
	std::lock_guard<std::mutex> lock( mutexQueue_ );

	auto dom = knownDomains_.find( uuid );

	if ( dom != knownDomains_.end() ) {
		dom->second.park();
		logger << DEBUG << "[" << uuid << "] Parked" << std::flush;
	}
}

} // namespace bdvmi
