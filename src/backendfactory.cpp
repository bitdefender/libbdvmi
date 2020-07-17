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

#include "bdvmi/backendfactory.h"
#include "xendriver.h"
#include "xendomainwatcher.h"
#include "xeneventmanager.h"
#ifdef USE_KVMI
#include "kvmdriver.h"
#include "kvmdomainwatcher.h"
#include "kvmeventmanager.h"
#endif
#include <stdexcept>

namespace bdvmi {

BackendFactory::BackendFactory( BackendType type ) : type_{ type }
{
	if ( type_ != BACKEND_XEN && type_ != BACKEND_KVM )
		throw std::runtime_error( "Xen and KVM are the only supported backends for now" );
}

std::unique_ptr<DomainWatcher> BackendFactory::domainWatcher( sig_atomic_t &sigStop )
{
	switch ( type_ ) {
		case BACKEND_XEN:
			return std::make_unique<XenDomainWatcher>( sigStop  );
#ifdef USE_KVMI
		case BACKEND_KVM:
			return std::make_unique<KvmDomainWatcher>( sigStop );
#endif
		default:
			throw std::runtime_error( "Xen and KVM are the only supported backends for now" );
	}
}

std::unique_ptr<Driver> BackendFactory::driver( const std::string &domain, bool altp2m, bool hvmOnly )
{
	switch ( type_ ) {
		case BACKEND_XEN:
			return std::make_unique<XenDriver>( domain, altp2m, hvmOnly );
#ifdef USE_KVMI
		case BACKEND_KVM:
			return std::make_unique<KvmDriver>( domain, altp2m );
#endif
		default:
			throw std::runtime_error( "Xen and KVM are the only supported backends for now" );
	}
}

std::unique_ptr<EventManager> BackendFactory::eventManager( Driver &driver, sig_atomic_t &sigStop )
{
	switch ( type_ ) {
		case BACKEND_XEN:
			return std::make_unique<XenEventManager>( dynamic_cast<XenDriver &>( driver ), sigStop  );
#ifdef USE_KVMI
		case BACKEND_KVM:
			return std::make_unique<KvmEventManager>( dynamic_cast<KvmDriver &>( driver ), sigStop );
#endif
		default:
			throw std::runtime_error( "Xen and KVM are the only supported backends for now" );
	}
}

} // namespace bdvmi
