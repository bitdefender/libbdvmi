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

#ifndef __BDVMIDOMAINWATCHER_H_INCLUDED__
#define __BDVMIDOMAINWATCHER_H_INCLUDED__

#include <set>
#include <list>
#include <string>
#include <signal.h>

namespace bdvmi {

// Forward declaration, minimize compile-time header dependencies
class DomainHandler;

class DomainWatcher {

protected:
	struct DomainInfo {
		DomainInfo() : isAlreadyRunning( false )
		{
		}

		std::string name;
		bool isAlreadyRunning;
	};

public:
	DomainWatcher();

	// base class, so virtual destructor
	virtual ~DomainWatcher()
	{
	}

public:
	void handler( DomainHandler *h )
	{
		handler_ = h;
	}

	void protectDomain( const std::string &domain )
	{
		domains_.insert( domain );
	}

	void unprotectDomain( const std::string &domain );

	bool protectedDomain( const std::string &domain ) const
	{
		return domains_.find( domain ) != domains_.end();
	}

	void stop()
	{
		stop_ = true;
	}

	// "Template" pattern - calls waitForDomainOrTimeout()
	void waitForDomains();

	void signalStopVar( sig_atomic_t *sigStop )
	{
		sigStop_ = sigStop;
	}

protected:
	// Return true if a new domain is up, false for timeout
	virtual bool waitForDomainsOrTimeout( std::list<DomainInfo> &domains, int ms ) = 0;

protected:
	sig_atomic_t *sigStop_;

private:
	std::set<std::string> domains_;
	bool stop_;
	DomainHandler *handler_;
};

} // namespace bdvmi

#endif // __BDVMIDOMAINWATCHER_H_INCLUDED__

