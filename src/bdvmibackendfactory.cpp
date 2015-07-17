// Copyright (c) 2015 Bitdefender SRL, All rights reserved.
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

#include "bdvmi/backendfactory.h"
#include "bdvmi/xendriver.h"
#include "bdvmi/xendomainwatcher.h"
#include "bdvmi/xeneventmanager.h"

namespace bdvmi {

BackendFactory::BackendFactory( BackendType type, LogHelper *logHelper ) : type_( type ), logHelper_( logHelper )
{
	if ( type_ != BACKEND_XEN )
		throw Exception( "Xen is the only supported backend for now" );
}

DomainWatcher *BackendFactory::domainWatcher()
{
	switch ( type_ ) {
		case BACKEND_XEN:
			return new XenDomainWatcher( logHelper_ );
		default:
			throw Exception( "Xen is the only supported backend for now" );
	}
}

Driver *BackendFactory::driver( const std::string &domain, bool watchableOnly )
{
	switch ( type_ ) {
		case BACKEND_XEN:
			return new XenDriver( domain, logHelper_, watchableOnly );
		default:
			throw Exception( "Xen is the only supported backend for now" );
	}
}

EventManager *BackendFactory::eventManager( Driver &driver, unsigned short flags )
{
	switch ( type_ ) {
		case BACKEND_XEN:
			return new XenEventManager( dynamic_cast<XenDriver &>( driver ), flags, logHelper_ );
		default:
			throw Exception( "Xen is the only supported backend for now" );
	}
}

} // namespace bdvmi

