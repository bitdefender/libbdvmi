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

#include "bdvmi/backendfactory.h"
#include "bdvmi/xendriver.h"
#include "bdvmi/xendomainwatcher.h"
#include "bdvmi/xeneventmanager.h"
#include <stdexcept>

namespace bdvmi {

BackendFactory::BackendFactory( BackendType type, LogHelper *logHelper ) : type_( type ), logHelper_( logHelper )
{
	if ( type_ != BACKEND_XEN && type_ != BACKEND_KVM )
		throw std::runtime_error( "Xen and KVM are the only supported backends for now" );
}

DomainWatcher *BackendFactory::domainWatcher()
{
	switch ( type_ ) {
		case BACKEND_XEN:
			return new XenDomainWatcher( logHelper_ );
		case BACKEND_KVM:
		default:
			throw std::runtime_error( "Xen is the only supported backend for now" );
	}
}

Driver *BackendFactory::driver( const std::string &domain, bool watchableOnly )
{
	switch ( type_ ) {
		case BACKEND_XEN:
			return new XenDriver( domain, logHelper_, watchableOnly );
		case BACKEND_KVM:
		default:
			throw std::runtime_error( "Xen is the only supported backend for now" );
	}
}

EventManager *BackendFactory::eventManager( Driver &driver )
{
	switch ( type_ ) {
		case BACKEND_XEN:
			return new XenEventManager( dynamic_cast<XenDriver &>( driver ), logHelper_ );
		case BACKEND_KVM:
		default:
			throw std::runtime_error( "Xen is the only supported backend for now" );
	}
}

} // namespace bdvmi
