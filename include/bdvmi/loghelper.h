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

#ifndef __LOGHELPER_H_INCLUDED__
#define __LOGHELPER_H_INCLUDED__

#include <iomanip>
#include <sstream>
#include <string>
#include <atomic>

namespace bdvmi {

class LogHelper {

public:
	// base class, so virtual destructor
	virtual ~LogHelper() = default;

public:
	virtual void error( const std::string &message )   = 0;
	virtual void warning( const std::string &message ) = 0;
	virtual void info( const std::string &message )    = 0;
	virtual void debug( const std::string &message )   = 0;

	void trace( bool value )
	{
		trace_ = value;
	}

	bool trace() const
	{
		return trace_;
	}

private:
	std::atomic_bool trace_{ false };
};

template <typename Arg> std::ostream &write( std::ostream &out, Arg &&arg )
{
	return out << std::forward<Arg>( arg );
}

template <typename Arg, typename... Args> std::ostream &write( std::ostream &out, Arg &&arg, Args &&... args )
{
	out << std::forward<Arg>( arg );
	return write( out, std::forward<Args>( args )... );
}

template <typename... Args> std::string formatParams( Args &&... args )
{
	std::stringstream ss;
	write( ss, std::forward<Args>( args )... );

	return ss.str();
}

template <typename... Args> void LOG_ERROR( LogHelper *logHelper, Args &&... args )
{
	if ( logHelper ) {
		int e = errno;
		logHelper->error( formatParams( std::forward<Args>( args )... ) );
		errno = e;
	}
}

template <typename... Args> void LOG_WARNING( LogHelper *logHelper, Args &&... args )
{
	if ( logHelper ) {
		int e = errno;
		logHelper->warning( formatParams( std::forward<Args>( args )... ) );
		errno = e;
	}
}

template <typename... Args> void LOG_INFO( LogHelper *logHelper, Args &&... args )
{
	if ( logHelper ) {
		int e = errno;
		logHelper->info( formatParams( std::forward<Args>( args )... ) );
		errno = e;
	}
}

template <typename... Args> void LOG_DEBUG( LogHelper *logHelper, Args &&... args )
{
	if ( logHelper ) {
		int e = errno;
		logHelper->debug( formatParams( std::forward<Args>( args )... ) );
		errno = e;
	}
}

template <typename... Args> void LOG_TRACE( LogHelper *logHelper, Args &&... args )
{
	if ( logHelper && logHelper->trace() ) {
		int e = errno;
		logHelper->debug( formatParams( std::forward<Args>( args )... ) );
		errno = e;
	}
}

} // namespace bdvmi

#endif // __LOGHELPER_H_INCLUDED__
