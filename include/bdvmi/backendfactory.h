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

#ifndef __BDVMIBACKENDFACTORY_H_INCLUDED__
#define __BDVMIBACKENDFACTORY_H_INCLUDED__

#include <memory>
#include <signal.h>
#include <string>

namespace bdvmi {

class DomainWatcher;
class Driver;
class EventManager;

class BackendFactory {

public:
	enum BackendType { BACKEND_XEN, BACKEND_KVM };

public:
	explicit BackendFactory( BackendType type );

public:
	std::unique_ptr<DomainWatcher> domainWatcher( sig_atomic_t &sigStop );

	std::unique_ptr<Driver> driver( const std::string &domain, bool altp2m, bool watchableOnly = true );

	std::unique_ptr<EventManager> eventManager( Driver &driver, sig_atomic_t &sigStop );

public:
	BackendFactory( const BackendFactory & ) = delete;
	BackendFactory &operator=( const BackendFactory & ) = delete;

private:
	BackendType type_;
};

} // namespace bdvmi

#endif // __BDVMIBACKENDFACTORY_H_INCLUDED__
