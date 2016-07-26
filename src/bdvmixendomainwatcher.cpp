// Copyright (c) 2015-2016 Bitdefender SRL, All rights reserved.
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
#include "bdvmi/xendomainwatcher.h"
#include "bdvmi/xeninlines.h"
#include <errno.h>
#include <poll.h>
#include <cstdlib>
#include <sstream>
#include <cstring>
#include <stdexcept>

namespace bdvmi {

std::string uuidToString( const xen_domain_handle_t &uuid )
{
	std::stringstream ss;
	ss.setf( std::ios::hex, std::ios::basefield );

	for ( int i = 0; i < 4; ++i ) {
		ss << ( uuid[i] >> 4 );
		ss << ( uuid[i] & 0x0f );
	}

	ss << '-';

	for ( int i = 4; i < 6; ++i ) {
		ss << ( uuid[i] >> 4 );
		ss << ( uuid[i] & 0x0f );
	}

	ss << '-';

	for ( int i = 6; i < 8; ++i ) {
		ss << ( uuid[i] >> 4 );
		ss << ( uuid[i] & 0x0f );
	}

	ss << '-';

	for ( int i = 8; i < 10; ++i ) {
		ss << ( uuid[i] >> 4 );
		ss << ( uuid[i] & 0x0f );
	}

	ss << '-';

	for ( int i = 10; i < 16; ++i ) {
		ss << ( uuid[i] >> 4 );
		ss << ( uuid[i] & 0x0f );
	}

	return ss.str();
}

XenDomainWatcher::XenDomainWatcher( LogHelper *logHelper )
    : xsh_( NULL ), xci_( NULL ), introduceToken_( "introduce" ), releaseToken_( "release" ), controlToken_( "control" ),
      logHelper_( logHelper ), firstUninitWrite_( true ), ownId_( -1 ), keyCreated_( false )
{
	xsh_ = xs_open( 0 );

	if ( !xsh_ )
		throw std::runtime_error( "xs_open() failed" );

	if ( !xs_watch( xsh_, "@introduceDomain", introduceToken_.c_str() ) ) {
		xs_close( xsh_ );
		throw std::runtime_error( "xs_watch() failed" );
	}

	if ( !xs_watch( xsh_, "@releaseDomain", releaseToken_.c_str() ) ) {
		xs_unwatch( xsh_, "@introduceDomain", introduceToken_.c_str() );
		xs_close( xsh_ );
		throw std::runtime_error( "xs_watch() failed" );
	}

	xci_ = xc_interface_open( NULL, NULL, 0 );

	if ( !xci_ ) {
		xs_unwatch( xsh_, "@introduceDomain", introduceToken_.c_str() );
		xs_unwatch( xsh_, "@releaseDomain", releaseToken_.c_str() );
		xs_close( xsh_ );
		throw std::runtime_error( "xc_interface_init() failed" );
	}

	// Retrieving the UUID can also be achieved under Linux by simply reading
	// /sys/hypervisor/uuid.

	xen_domain_handle_t uuid;

	if ( !xc_version( xci_, XENVER_guest_handle, &uuid ) ) {
		ownUuid_ = uuidToString( uuid );

		if ( logHelper_ )
			logHelper_->info( std::string( "SVA UUID: " ) + ownUuid_ );
	}
}

XenDomainWatcher::~XenDomainWatcher()
{
	xs_unwatch( xsh_, "@introduceDomain", introduceToken_.c_str() );
	xs_unwatch( xsh_, "@releaseDomain", releaseToken_.c_str() );

	if ( !controlXenStorePath_.empty() ) {
		xs_unwatch( xsh_, controlXenStorePath_.c_str(), controlToken_.c_str() );
		xs_rm( xsh_, XBT_NULL, controlXenStorePath_.c_str() );
	}

	xs_close( xsh_ );

	xc_interface_close( xci_ );
}

bool XenDomainWatcher::getNewDomains( std::list<DomainInfo> &domains, char **vec )
{
	int domid = 1;
	xc_dominfo_t dominfo;
	int err = -1;
	bool ret = false;

	while ( ( err = xc_domain_getinfo( xci_, domid, 1, &dominfo ) ) == 1 ) {
		domid = dominfo.domid + 1;

		if ( xs_is_domain_introduced( xsh_, dominfo.domid ) ) {

			// New domain
			if ( domIds_.find( dominfo.domid ) == domIds_.end() ) {
				std::stringstream ss;
				ss << "/local/domain/" << dominfo.domid << "/name";

				std::string path = ss.str();

				errno = 0;
				char *name = static_cast<char *>(
				        xs_read_timeout( xsh_, XBT_NULL, path.c_str(), NULL, 1 ) );

				if ( name ) { // domain running or new domain w name set
					DomainInfo domain( name, DomainInfo::STATE_NEW );
					free( name );

					if ( !isSelf( dominfo.domid ) ) {
						domains.push_back( domain );
						domIds_[dominfo.domid] = domain.name;
						ret = true;
					}

				} else { // new domain, name not yet set
					ss.str( "" );
					ss << "dom" << dominfo.domid;
					xs_watch( xsh_, path.c_str(), ss.str().c_str() );
				}
			}
		}
	}

	if ( err == -1 && ( errno == EACCES || errno == EPERM ) ) {
		free( vec );

		std::runtime_error e( "access denied for xc_domain_getinfo()" );

		if ( logHelper_ )
			logHelper_->error( e.what() );

		throw e;
	}

	return ret;
}

bool XenDomainWatcher::waitForDomainsOrTimeout( std::list<DomainInfo> &domains, int ms )
{
	struct pollfd fd;
	bool ret = false;

	fd.revents = 0;
	fd.fd = xs_fileno( xsh_ );
	fd.events = POLLIN | POLLERR;

	int rc = poll( &fd, 1, ms );

	domains.clear();

	if ( rc == 0 )
		return false; // timeout

	if ( fd.revents & POLLIN ) {

		unsigned int num;
		char **vec = xs_read_watch( xsh_, &num );

		if ( vec && introduceToken_ == vec[XS_WATCH_TOKEN] )
			ret = getNewDomains( domains, vec );

		if ( vec && releaseToken_ == vec[XS_WATCH_TOKEN] ) {

			std::map<domid_t, std::string>::iterator i = domIds_.begin(), j;

			while ( i != domIds_.end() ) {
				j = i;
				++i;

				if ( !xs_is_domain_introduced( xsh_, j->first ) ) {
					DomainInfo domain( j->second, DomainInfo::STATE_FINISHED );
					domains.push_back( domain );

					domIds_.erase( j );

					ret = true;
				}
			}
		}

		if ( vec && controlToken_ == vec[XS_WATCH_TOKEN] ) {
			if ( firstUninitWrite_ ) // ignore first event, it's just how XenStore works
				firstUninitWrite_ = false;
			else {
				char *value = static_cast<char *>(
				        xs_read_timeout( xsh_, XBT_NULL, vec[XS_WATCH_PATH], NULL, 1 ) );

				if ( value ) {
					std::string tmp = value;
					free( value );

					if ( logHelper_ )
						logHelper_->info( std::string( "Received control command: " ) + tmp );

					if ( tmp == "shutdown" )
						stop();
					else if ( tmp == "scandomains" )
						ret = getNewDomains( domains, vec );
				}
			}
		}

		if ( vec && !strncmp( vec[XS_WATCH_TOKEN], "dom", 3 ) ) {

			int domid = 1;
			if ( sscanf( vec[XS_WATCH_TOKEN], "dom%u", &domid ) == 1 ) {

				char *name = static_cast<char *>(
				        xs_read_timeout( xsh_, XBT_NULL, vec[XS_WATCH_PATH], NULL, 1 ) );

				if ( name ) {
					if ( !isSelf( domid ) ) {
						DomainInfo domain( name, DomainInfo::STATE_NEW );
						domains.push_back( domain );
						ret = true;
					}

					free( name );
					xs_unwatch( xsh_, vec[XS_WATCH_PATH], vec[XS_WATCH_TOKEN] );
				}
			}
		}

		free( vec );
	}

	return ret;
}

bool XenDomainWatcher::isSelf( domid_t domain )
{
	std::stringstream ss;
	std::string uuid;
	unsigned int size = 0;

	ss << "/local/domain/" << domain << "/vm";

	char *path = static_cast<char *>( xs_read_timeout( xsh_, XBT_NULL, ss.str().c_str(), &size, 1 ) );

	if ( path && path[0] != '\0' ) {
		ss.str( "" );
		ss << path << "/uuid";

		free( path );
		size = 0;

		path = static_cast<char *>( xs_read_timeout( xsh_, XBT_NULL, ss.str().c_str(), &size, 1 ) );

		if ( path && path[0] != '\0' )
			uuid = path;
	}

	free( path );

	if ( uuid == ownUuid_ ) {
		ownId_ = domain;
		initControlKey( ownId_ );
		return true;
	}

	return false;
}

void XenDomainWatcher::initControlKey( domid_t domain )
{
	if ( !keyCreated_ ) { // One-time only
		keyCreated_ = true;

		std::stringstream ss;
		ss << "/local/domain/" << domain << "/vm-data/introspection-control";
		controlXenStorePath_ = ss.str();

		std::string value = "started";

		if ( !xs_write( xsh_, XBT_NULL, controlXenStorePath_.c_str(), value.c_str(), value.length() ) ) {
			if ( logHelper_ )
				logHelper_->error( std::string("Could not write XenStore key ") + controlXenStorePath_ );
		}

		xs_watch( xsh_, controlXenStorePath_.c_str(), controlToken_.c_str() );
	}
}

} // namespace bdvmi
