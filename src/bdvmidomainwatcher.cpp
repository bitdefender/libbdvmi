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

#include "bdvmi/domainwatcher.h"
#include "bdvmi/domainhandler.h"

namespace bdvmi {

DomainWatcher::DomainWatcher( sig_atomic_t &sigStop ) : sigStop_{ sigStop }
{
}

void DomainWatcher::waitForDomains()
{
	int ms = 100;

	for ( ;; ) {

		if ( sigStop_ || stop_ ) {
			if ( handler_ )
				handler_->cleanup( suspendIntrospectorDomain_ );
			return;
		}

		try {
			std::list<DomainInfo> domains;

			if ( waitForDomainsOrTimeout( domains, ms ) ) {

				for ( auto && domain : domains ) {
					if ( handler_ ) {
						switch ( domain.state ) {
						case DomainInfo::STATE_NEW:
							handler_->handleDomainFound( domain.uuid, domain.name );
							break;
						case DomainInfo::STATE_FINISHED:
							handler_->handleDomainFinished( domain.uuid );
							break;
						}
					}
				}
			}

			ms = 100;

		} catch ( ... ) { // try again on exceptions, but later
			ms = 2000; // make it 2 seconds
		}
	}
}

} // namespace bdvmi
