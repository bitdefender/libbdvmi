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
		enum State { STATE_NEW, STATE_FINISHED };

		DomainInfo( const std::string &u, State s = STATE_NEW, const std::string &n = "unknown" )
		    : uuid( u ), state( s ), name( n )
		{
		}

		std::string uuid;
		State       state;
		std::string name;
	};

public:
	DomainWatcher( sig_atomic_t &sigStop );

	// Base class, so virtual destructor
	virtual ~DomainWatcher() = default;

public:
	// Return true if the guest running the application can do introspection
	virtual bool accessGranted() = 0;

	// Called if (and when) a dedicated child process has fork()ed to handle the domain
	virtual void forkedHandler( const std::string & /* uuid */, bool /* parent */ = true )
	{
	}

	void handler( DomainHandler *h )
	{
		handler_ = h;
	}

	void stop()
	{
		stop_ = true;
	}

	// "Template" pattern - calls waitForDomainOrTimeout()
	void waitForDomains();

	virtual void setAuthCookie( const std::string & /* authCookie */ )
	{
	}

	virtual bool ownUuid( std::string &uuid ) const = 0;

protected:
	// Return true if a new domain is up, false for timeout
	virtual bool waitForDomainsOrTimeout( std::list<DomainInfo> &domains, int ms ) = 0;

protected:
	sig_atomic_t &sigStop_;
	bool          suspendIntrospectorDomain_{ false };

private:
	bool           stop_{ false };
	DomainHandler *handler_{ nullptr };
};

} // namespace bdvmi

#endif // __BDVMIDOMAINWATCHER_H_INCLUDED__
