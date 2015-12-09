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

#include "bdvmi/exception.h"
#include <execinfo.h>
#include <cstdlib>
#include <cxxabi.h>

namespace bdvmi {

Exception::Exception( const std::string &reason, ErrorCode ec ) : reason_( reason ), ec_( ec )
{
	initBacktrace();
}

Exception::~Exception() throw()
{
}

void Exception::initBacktrace()
{
	backtrace_.clear();

	const int SIZE = 100;
	void *buffer[SIZE];

	int nptrs = ::backtrace( buffer, SIZE );

	char **strings = backtrace_symbols( buffer, nptrs );

	if ( !strings )
		return; // Don't throw, don't do anything spectacular

	for ( int i = 0; i < nptrs; ++i ) {

		char *line = strings[i];

		while ( *line && *line != '(' )
			backtrace_ += *line++;

		if ( *line ) // skip '('
			backtrace_ += *line++;

		std::string symbol;
		while ( *line && *line != '+' && *line != ')' )
			symbol += *line++;

		char *demangled = NULL;
		int status;

		if ( ( demangled = abi::__cxa_demangle( symbol.c_str(), NULL, NULL, &status ) ) ) {
			backtrace_ += demangled;
			free( demangled );
		} else {
			backtrace_ += symbol;
		}

		while ( *line )
			backtrace_ += *line++;

		if ( i < nptrs - 1 )
			backtrace_ += '\n';
	}

	free( strings );
}

} // namespace bdvmi
