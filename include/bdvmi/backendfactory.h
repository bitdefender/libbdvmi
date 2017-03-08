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

#ifndef __BDVMIBACKENDFACTORY_H_INCLUDED__
#define __BDVMIBACKENDFACTORY_H_INCLUDED__

#include <string>

namespace bdvmi {

class DomainWatcher;
class Driver;
class EventManager;
class LogHelper;

class BackendFactory {

public:
	enum BackendType { BACKEND_XEN, BACKEND_KVM };

public:
	BackendFactory( BackendType type, LogHelper *logHelper = NULL );

public:
	DomainWatcher *domainWatcher();

	Driver *driver( const std::string &domain, bool watchableOnly = true );

	EventManager *eventManager( Driver &driver, unsigned short handlerFlags );

private:
	// Prevent copying
	BackendFactory( const BackendFactory & );

	// Prevent copying
	BackendFactory &operator=( const BackendFactory & );

private:
	BackendType type_;
	LogHelper *logHelper_;
};

} // namespace bdvmi

#endif // __BDVMIBACKENDFACTORY_H_INCLUDED__
