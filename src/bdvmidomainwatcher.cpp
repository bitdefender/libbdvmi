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

#include "bdvmi/domainwatcher.h"
#include "bdvmi/domainhandler.h"

namespace bdvmi {

DomainWatcher::DomainWatcher() : sigStop_( NULL ), stop_( false ), handler_( NULL )
{
}

void DomainWatcher::unprotectDomain( const std::string &domain )
{
	std::set<std::string>::iterator it = domains_.find( domain );

	if ( it != domains_.end() )
		domains_.erase( it );
}

void DomainWatcher::waitForDomains()
{
	for ( ;; ) {

		if ( sigStop_ && *sigStop_ )
			return;

		if ( stop_ )
			return;

		std::list<DomainInfo> domains;

		if ( waitForDomainsOrTimeout( domains, 100 ) ) {

			std::list<DomainInfo>::const_iterator i = domains.begin();

			for ( ; i != domains.end(); ++i ) {

				if ( protectedDomain( i->name ) ) {

					if ( handler_ && !i->isAlreadyRunning )
						handler_->handleNewProtectedDomain( i->name );

					if ( handler_ && i->isAlreadyRunning )
						handler_->handleRunningProtectedDomain( i->name );
				} else {

					if ( handler_ && !i->isAlreadyRunning )
						handler_->handleNewUnprotectedDomain( i->name );

					if ( handler_ && i->isAlreadyRunning )
						handler_->handleRunningUnprotectedDomain( i->name );
				}
			}
		}
	}
}

} // namespace bdvmi
