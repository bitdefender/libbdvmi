// Copyright (c) 2018 Bitdefender SRL, All rights reserved.
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

#include "dynamiclibfactory.h"

namespace bdvmi {

DynamicLibFactory::DynamicLibFactory( const std::string &libPath )
{
	libHandle_ = dlopen( libPath.c_str(), RTLD_NOW | RTLD_GLOBAL );
	if ( !libHandle_ )
		throw std::runtime_error( "Failed to open the \"" + libPath + "\" library: " + dlerror() );
}

DynamicLibFactory::~DynamicLibFactory()
{
	dlclose( libHandle_ );
}

bool DynamicLibFactory::contains( const std::string &name ) const
{
	dlerror();
	::dlsym( libHandle_, name.c_str() );

	return ( dlerror() == nullptr );
}

} // namespace bdvmi
