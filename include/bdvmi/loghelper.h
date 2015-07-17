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

#ifndef __LOGHELPER_H_INCLUDED__
#define __LOGHELPER_H_INCLUDED__

#include <string>

namespace bdvmi {

class LogHelper {

public:
	// base class, so virtual destructor
	virtual ~LogHelper()
	{
	}

public:
	virtual void error( const std::string &message ) = 0;
	virtual void warning( const std::string &message ) = 0;
	virtual void info( const std::string &message ) = 0;
	virtual void debug( const std::string &message ) = 0;
};

} // namespace bdvmi

#endif // __LOGHELPER_H_INCLUDED__

