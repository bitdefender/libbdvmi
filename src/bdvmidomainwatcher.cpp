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

#include "bdvmi/domainwatcher.h"
#include "bdvmi/domainhandler.h"

namespace bdvmi {

DomainWatcher::DomainWatcher() : sigStop_( nullptr ), stop_( false ), handler_( nullptr )
{
}

void DomainWatcher::waitForDomains()
{
	for ( ;; ) {

		if ( ( sigStop_ && *sigStop_ ) || stop_ ) {
			if ( handler_ )
				handler_->cleanup();
			return;
		}

		std::list<DomainInfo> domains;
		int ms = 100;

		try {
			if ( waitForDomainsOrTimeout( domains, ms ) ) {

				std::list<DomainInfo>::const_iterator i = domains.begin();

				for ( ; i != domains.end(); ++i ) {

					if ( handler_ ) {
						switch ( i->state ) {
						case DomainInfo::STATE_NEW:
							handler_->handleDomainFound( i->uuid, i->name );
							break;
						case DomainInfo::STATE_FINISHED:
							handler_->handleDomainFinished( i->uuid );
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
