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

#include "bdvmi/loghelper.h"
#include "xcwrapper.h"
#include "xendomainwatcher.h"
#include <errno.h>
#include <poll.h>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

namespace bdvmi {

XenDomainWatcher::XenDomainWatcher( sig_atomic_t &sigStop, LogHelper *logHelper )
    : DomainWatcher{ sigStop }, ownUuid_{ xc_.uuid }, logHelper_{ logHelper }
{
	if ( !xs_.watch( "@introduceDomain", introduceToken_ ) )
		throw std::runtime_error( "xs_watch() failed" );

	if ( !xs_.watch( "@releaseDomain", releaseToken_ ) ) {
		xs_.unwatch( "@introduceDomain", introduceToken_ );
		throw std::runtime_error( "xs_watch() failed" );
	}

	// Retrieving the UUID can also be achieved under Linux by simply reading
	// /sys/hypervisor/uuid.
	LOG_INFO( logHelper_, "SVA UUID: ", ownUuid_ );
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

		void *dummy = xs_.readTimeout( XS::xbtNull, key, nullptr, 1 );

		// Key exists, so the domain is pre-resuming. Wait until post-resume to
		// hook the domain, don't hook it immediately.
		if ( dummy ) {
			free( dummy );

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

				errno      = 0;
				char *name = static_cast<char *>( xs_.readTimeout( XS::xbtNull, path, nullptr, 1 ) );

				if ( name ) { // domain running or new domain w name set
					if ( !isSelf( dominfo.domid ) ) {
						std::string guestUuid = uuid( dominfo.domid );
						domains.emplace_back( guestUuid, DomainInfo::STATE_NEW, name );
						domIds_[dominfo.domid] = guestUuid;
						ret                    = true;
					}

					free( name );
				} else // new domain, name not yet set
					xs_.watch( path, "dom" + std::to_string( dominfo.domid ) );
			}
		}
	}

	if ( err == -1 && ( errno == EACCES || errno == EPERM ) ) {
		std::runtime_error e( "access denied for xc_domain_getinfo()" );
		LOG_ERROR( logHelper_, e.what() );
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
			if ( firstUninitWrite_ ) // ignore first event, it's just how XenStore works
				firstUninitWrite_ = false;
			else {
				char *value = static_cast<char *>(
				        xs_.readTimeout( XS::xbtNull, vec[XS::watchPath], nullptr, 1 ) );

				if ( value ) {
					std::string tmp = value;
					free( value );

					LOG_INFO( logHelper_, "Received control command: ", tmp );

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

				char *name = static_cast<char *>(
				        xs_.readTimeout( XS::xbtNull, vec[XS::watchPath], nullptr, 1 ) );

				if ( name ) {
					if ( !isSelf( domid ) ) {
						domains.emplace_back( uuid( domid ), DomainInfo::STATE_NEW, name );
						ret = true;
					}

					free( name );
					xs_.unwatch( vec[XS::watchPath], vec[XS::watchToken] );
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

	char *path = static_cast<char *>( xs_.readTimeout( XS::xbtNull, key, &size, 1 ) );

	if ( path && path[0] != '\0' ) {
		key = std::string( path ) + "/uuid";

		free( path );
		size = 0;

		path = static_cast<char *>( xs_.readTimeout( XS::xbtNull, key, &size, 1 ) );

		if ( path && path[0] != '\0' )
			strUuid = path;
	}

	free( path );

	return strUuid;
}

bool XenDomainWatcher::isSelf( domid_t domain )
{
	if ( ownUuid_ == uuid( domain ) ) {
		initControlKey( domain );
		return true;
	}

	return false;
}

void XenDomainWatcher::initControlKey( domid_t domain )
{
	if ( !keyCreated_ ) { // One-time only
		keyCreated_          = true;
		controlXenStorePath_ = "/local/domain/" + std::to_string( domain ) + "/vm-data/introspection-control";
		const std::string value = "started";

		if ( !xs_.write( XS::xbtNull, controlXenStorePath_, value.c_str(), value.length() ) )
			LOG_ERROR( logHelper_, "Could not write XenStore key ", controlXenStorePath_ );

		xs_.watch( controlXenStorePath_, controlToken_ );
	}
}

} // namespace bdvmi
