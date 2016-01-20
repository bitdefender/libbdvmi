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

namespace bdvmi {

XenDomainWatcher::XenDomainWatcher( LogHelper *logHelper )
    : xsh_( NULL ), xci_( NULL ), introduceToken_( "introduce" ), releaseToken_( "release" ), logHelper_( logHelper )
{
	xsh_ = xs_open( 0 );

	if ( !xsh_ )
		throw Exception( "xs_open() failed" );

	if ( !xs_watch( xsh_, "@introduceDomain", introduceToken_.c_str() ) ) {
		xs_close( xsh_ );
		throw Exception( "xs_watch() failed" );
	}

	if ( !xs_watch( xsh_, "@releaseDomain", releaseToken_.c_str() ) ) {
		xs_unwatch( xsh_, "@introduceDomain", introduceToken_.c_str() );
		xs_close( xsh_ );
		throw Exception( "xs_watch() failed" );
	}

	xci_ = xc_interface_open( NULL, NULL, 0 );

	if ( !xci_ ) {
		xs_unwatch( xsh_, "@introduceDomain", introduceToken_.c_str() );
		xs_unwatch( xsh_, "@releaseDomain", releaseToken_.c_str() );
		xs_close( xsh_ );
		throw Exception( "xc_interface_init() failed" );
	}
}

XenDomainWatcher::~XenDomainWatcher()
{
	xs_unwatch( xsh_, "@introduceDomain", introduceToken_.c_str() );
	xs_unwatch( xsh_, "@releaseDomain", releaseToken_.c_str() );
	xs_close( xsh_ );

	xc_interface_close( xci_ );
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

		if ( vec && introduceToken_ == vec[XS_WATCH_TOKEN] ) {

			int domid = 1;
			xc_dominfo_t dominfo;
			int err = -1;

			while ( ( err = xc_domain_getinfo( xci_, domid, 1, &dominfo ) ) == 1 ) {
				domid = dominfo.domid + 1;

				if ( xs_is_domain_introduced( xsh_, dominfo.domid ) ) {

					// New domain
					if ( domIds_.find( dominfo.domid ) == domIds_.end() ) {

						domIds_.insert( dominfo.domid );

						std::stringstream ss;
						ss << "/local/domain/" << dominfo.domid << "/name";

						std::string path = ss.str();

						errno = 0;
						char *name = static_cast<char *>(
						        xs_read_timeout( xsh_, XBT_NULL, path.c_str(), NULL, 1 ) );

						/*
						if ( !name && errno && logHelper_ )
						        logHelper_->error( std::string( "xs_read() error reading " ) +
						                           ss.str() + ": " + strerror( errno ) );
						*/

						if ( name ) { // domain running or new domain w name set

							ss.str( "" );
							ss << "/local/domain/" << dominfo.domid << "/console/tty";
							path = ss.str();

							DomainInfo domain;

							errno = 0;
							void *console = xs_read_timeout( xsh_, XBT_NULL, path.c_str(),
							                                 NULL, 1 );

							/*
							if ( !console && errno && logHelper_ )
							        logHelper_->error(
							                std::string( "xs_read() error reading " ) +
							                ss.str() + ": " + strerror( errno ) );
							*/

							if ( console ) {
								free( console );
								domain.isAlreadyRunning = true;
							} else {
								domain.isAlreadyRunning = false;
							}

							domain.name = name;
							free( name );

							domains.push_back( domain );
							ret = true;
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
				throw Exception( "access denied for xc_domain_getinfo()" );
			}
		}

		if ( vec && releaseToken_ == vec[XS_WATCH_TOKEN] ) {

			int domid = 1;
			xc_dominfo_t dominfo;

			while ( xc_domain_getinfo( xci_, domid, 1, &dominfo ) == 1 ) {
				domid = dominfo.domid + 1;

				if ( !xs_is_domain_introduced( xsh_, dominfo.domid ) )
					domIds_.erase( dominfo.domid );
			}
		}

		if ( vec && !strncmp( vec[XS_WATCH_TOKEN], "dom", 3 ) ) {

			int domid = 1;
			if ( sscanf( vec[XS_WATCH_TOKEN], "dom%u", &domid ) == 1 ) {

				char *name = static_cast<char *>(
				        xs_read_timeout( xsh_, XBT_NULL, vec[XS_WATCH_PATH], NULL, 1 ) );

				if ( name ) {
					DomainInfo domain;
					domain.isAlreadyRunning = false;
					domain.name = name;
					free( name );

					domains.push_back( domain );
					xs_unwatch( xsh_, vec[XS_WATCH_PATH], vec[XS_WATCH_TOKEN] );

					ret = true;
				}
			}
		}

		free( vec );
	}

	return ret;
}

} // namespace bdvmi
