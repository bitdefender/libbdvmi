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

#include "bdvmi/logger.h"
#include "xcwrapper.h"
#include "xendomainwatcher.h"
#include "utils.h"
#include <errno.h>
#include <poll.h>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

namespace bdvmi {

constexpr char   XenDomainWatcher::TEMPORARY_UUID_SUFFIX[];
constexpr size_t XenDomainWatcher::PREFIX_SIZE;

XenDomainWatcher::XenDomainWatcher( sig_atomic_t &sigStop ) : DomainWatcher{ sigStop }, ownUuid_{ xc_.uuid }
{
	if ( !xs_.watch( "@introduceDomain", introduceToken_ ) )
		throw std::runtime_error( "xs_watch() failed" );

	if ( !xs_.watch( "@releaseDomain", releaseToken_ ) ) {
		xs_.unwatch( "@introduceDomain", introduceToken_ );
		throw std::runtime_error( "xs_watch() failed" );
	}

	// Retrieving the UUID can also be achieved under Linux by simply reading
	// /sys/hypervisor/uuid.
	logger << INFO << "SVA UUID: " << ownUuid_ << std::flush;
}

XenDomainWatcher::~XenDomainWatcher()
{
	xs_.unwatch( "@introduceDomain", introduceToken_ );
	xs_.unwatch( "@releaseDomain", releaseToken_ );

	if ( !controlXenStorePath_.empty() ) {
		xs_.unwatch( controlXenStorePath_, controlToken_ );
		xs_.rm( XS::xbtNull, controlXenStorePath_ );
	}
}

bool XenDomainWatcher::getNewDomains( std::list<DomainInfo> &domains )
{
	int           domid = 1;
	XenDomainInfo dominfo;
	int           err = -1;
	bool          ret = false;

	while ( ( err = xc_.domainGetInfo( domid, dominfo ) ) == 1 ) {

		domid = dominfo.domid + 1;

		std::string key = "/local/domain/" + std::to_string( dominfo.domid ) + "/vm-data/pre-resume";

		CUniquePtr<void> dummy( xs_.readTimeout( XS::xbtNull, key, nullptr, 1 ) );

		// Key exists, so the domain is pre-resuming. Wait until post-resume to
		// hook the domain, don't hook it immediately.
		if ( dummy ) {
			if ( preResumeDomains_.find( dominfo.domid ) == preResumeDomains_.end() ) {
				xs_.watch( key, postResumeToken_ );
				preResumeDomains_.insert( dominfo.domid );
			}

			continue;
		} else {
			if ( preResumeDomains_.find( dominfo.domid ) != preResumeDomains_.end() ) {
				xs_.unwatch( key, postResumeToken_ );
				preResumeDomains_.erase( dominfo.domid );
			}
		}

		if ( xs_.isDomainIntroduced( dominfo.domid ) ) {
			// New domain
			if ( domIds_.find( dominfo.domid ) == domIds_.end() ) {
				std::string path = "/local/domain/" + std::to_string( dominfo.domid ) + "/name";
				bool        self = isSelf( dominfo.domid );

				errno = 0;

				if ( self )
					initControlKey( dominfo.domid );

				CUniquePtr<char> name( xs_.readTimeout( XS::xbtNull, path, nullptr, 1 ) );

				if ( name ) { // domain running or new domain w name set
					if ( !self ) {
						std::string guestUuid = uuid( dominfo.domid );

						// Temporary UUID set for localhost migration purposes (XenServer/XAPI).
						// The guest is not really ready until the real UUID is set, so
						// wait for that.
						if ( guestUuid.length() > 24 &&
						     guestUuid.substr( 24 ) == TEMPORARY_UUID_SUFFIX ) {
							path = "/local/domain/" + std::to_string( dominfo.domid ) +
							       "/vm";
							xs_.watch( path, "uuid" + std::to_string( dominfo.domid ) );
						} else {
							processNewDomain( domains, dominfo.domid, guestUuid,
							                  name.get() );
							ret = true;
						}
					}
				} else // new domain, name not yet set
					xs_.watch( path, "dom" + std::to_string( dominfo.domid ) );
			}
		}
	}

	if ( err == -1 && ( errno == EACCES || errno == EPERM ) ) {
		std::runtime_error e( "access denied for xc_domain_getinfo()" );
		logger << ERROR << e.what() << std::flush;
		throw e;
	}

	return ret;
}

bool XenDomainWatcher::accessGranted()
{
	XenDomainInfo dominfo;

	if ( xc_.domainGetInfo( 1, dominfo ) == -1 && ( errno == EACCES || errno == EPERM ) )
		return false;

	return true;
}

bool XenDomainWatcher::waitForDomainsOrTimeout( std::list<DomainInfo> &domains, int ms )
{
	struct pollfd fd;
	bool          ret = false;

	fd.revents = 0;
	fd.fd      = xs_.fileno();
	fd.events  = POLLIN | POLLERR;

	int rc = poll( &fd, 1, ms );

	domains.clear();

	if ( rc == 0 )
		return false; // timeout

	if ( fd.revents & POLLIN ) {

		std::vector<std::string> vec;

		if ( !xs_.readWatch( vec ) )
			return false;

		if ( introduceToken_ == vec[XS::watchToken] )
			ret = getNewDomains( domains );

		if ( releaseToken_ == vec[XS::watchToken] ) {

			std::map<domid_t, std::string>::iterator i = domIds_.begin(), j;

			while ( i != domIds_.end() ) {
				j = i;
				++i;

				if ( !xs_.isDomainIntroduced( j->first ) ) {
					domains.emplace_back( j->second, DomainInfo::STATE_FINISHED );

					preResumeDomains_.erase( j->first );
					domIds_.erase( j );

					ret = true;
				}
			}
		}

		if ( controlToken_ == vec[XS::watchToken] ) {
			if ( firstControlCommand_ ) // ignore first event, it's just how XenStore works
				firstControlCommand_ = false;
			else {
				CUniquePtr<char> value(
				        xs_.readTimeout( XS::xbtNull, vec[XS::watchPath], nullptr, 1 ) );

				if ( value ) {
					std::string tmp = value.get();

					logger << INFO << "Received control command: " << tmp << std::flush;

					if ( tmp == "shutdown" )
						stop();
					else if ( tmp == "scandomains" )
						ret = getNewDomains( domains );
				}
			}
		}

		if ( postResumeToken_ == vec[XS::watchToken] )
			ret = getNewDomains( domains );

		if ( !vec[XS::watchToken].compare( 0, 3, "dom" ) ) {
			int domid = 1;

			if ( sscanf( vec[XS::watchToken].c_str(), "dom%d", &domid ) == 1 ) {
				CUniquePtr<char> name( xs_.readTimeout( XS::xbtNull, vec[XS::watchPath], nullptr, 1 ) );

				if ( name ) {
					if ( !isSelf( domid ) ) {
						processNewDomain( domains, domid, uuid( domid ), name.get() );
						ret = true;
					}

					xs_.unwatch( vec[XS::watchPath], vec[XS::watchToken] );
				}
			}
		}

		if ( !vec[XS::watchToken].compare( 0, 4, "uuid" ) ) {
			int domid = 1;

			if ( sscanf( vec[XS::watchToken].c_str(), "uuid%d", &domid ) == 1 ) {
				unsigned int size = 0;
				std::string  uuid;

				CUniquePtr<char> val( xs_.readTimeout( XS::xbtNull, vec[XS::watchPath], &size, 1 ) );

				if ( val ) {
					if ( size > PREFIX_SIZE )
						uuid = val.get() + PREFIX_SIZE;

					if ( !isSelf( domid ) ) {
						if ( uuid.length() > 24 &&
						     uuid.substr( 24 ) != TEMPORARY_UUID_SUFFIX ) {
							std::string path =
							        "/local/domain/" + std::to_string( domid ) + "/vm";

							xs_.unwatch( path, "uuid" + std::to_string( domid ) );

							path = "/local/domain/" + std::to_string( domid ) + "/name";

							CUniquePtr<char> name(
							        xs_.readTimeout( XS::xbtNull, path, nullptr, 1 ) );

							if ( name ) {
								processNewDomain( domains, domid, uuid, name.get() );
								ret = true;
							} else
								xs_.watch( "/local/domain/" + std::to_string( domid ) +
								                   "/name",
								           "dom" + std::to_string( domid ) );
						}
					}
				}
			}
		}
	}

	return ret;
}

std::string XenDomainWatcher::uuid( domid_t domain ) const
{
	std::string  strUuid;
	unsigned int size = 0;
	std::string  key  = "/local/domain/" + std::to_string( domain ) + "/vm";

	CUniquePtr<char> path( xs_.readTimeout( XS::xbtNull, key, &size, 1 ) );

	if ( path && size > PREFIX_SIZE )
		strUuid = path.get() + PREFIX_SIZE; // Get rid of "/vm/"

	return strUuid;
}

bool XenDomainWatcher::isSelf( domid_t domain ) const
{
	return ownUuid_ == uuid( domain );
}

void XenDomainWatcher::initControlKey( domid_t domain )
{
	if ( !keyCreated_ ) { // One-time only
		keyCreated_          = true;
		controlXenStorePath_ = "/local/domain/" + std::to_string( domain ) + "/vm-data/introspection-control";
		const std::string value = "started";

		if ( !xs_.write( XS::xbtNull, controlXenStorePath_, value.c_str(), value.length() ) )
			logger << ERROR << "Could not write XenStore key " << controlXenStorePath_ << std::flush;

		xs_.watch( controlXenStorePath_, controlToken_ );
	}
}

void XenDomainWatcher::processNewDomain( std::list<DomainInfo> &domains, domid_t domid, const std::string &uuid,
                                         const std::string &name )
{
	domains.emplace_back( uuid, DomainInfo::STATE_NEW, name );
	domIds_[domid] = uuid;
}

} // namespace bdvmi
