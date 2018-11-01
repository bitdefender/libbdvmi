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

#ifndef __BDVMIDYNAMICLIBFACTORY_H_INCLUDED__
#define __BDVMIDYNAMICLIBFACTORY_H_INCLUDED__

#include <dlfcn.h>
#include <functional>
#include <string>

namespace bdvmi {

class DynamicLibFactory {
public:
	DynamicLibFactory( const std::string &libPath );
	~DynamicLibFactory();

	DynamicLibFactory( const DynamicLibFactory & ) = delete;
	DynamicLibFactory &operator=( const DynamicLibFactory & ) = delete;

	template <typename T, const char name[]> T *lookup( bool required = true ) const
	{
		char *error;

		dlerror();
		T *func = reinterpret_cast<T *>(::dlsym( libHandle_, name ) );
		error   = dlerror();

		if ( required && error )
			throw std::runtime_error( std::string( "Failed to get the \"" ) + name + "\" function" );
		return func;
	}

	bool contains( const std::string &name ) const;

private:
	void *libHandle_;
};

} // namespace bdvmi

#endif // __BDVMIDYNAMICLIBFACTORY_H_INCLUDED__
