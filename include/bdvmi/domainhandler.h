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

#ifndef __BDVMIDOMAINHANDLER_H_INCLUDED__
#define __BDVMIDOMAINHANDLER_H_INCLUDED__

#include <string>

namespace bdvmi {

class DomainHandler {

public:
	// base class, so virtual destructor
	virtual ~DomainHandler()
	{
	}

public:
	// A new domain appeared
	virtual void handleNewDomain( const std::string &domain ) = 0;

	// Handle an already running domain
	virtual void handleRunningDomain( const std::string &domain ) = 0;
};

} // namespace bdvmi

#endif // __BDVMIDOMAINHANDLER_H_INCLUDED__
