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

#ifndef __LOGGER_H_INCLUDED__
#define __LOGGER_H_INCLUDED__

#include <atomic>
#include <functional>
#include <map>
#include <mutex>
#include <ostream>
#include <streambuf>
#include <string>

namespace bdvmi {

std::ostream &DEBUG( std::ostream &os );
std::ostream &ERROR( std::ostream &os );
std::ostream &INFO( std::ostream &os );
std::ostream &WARNING( std::ostream &os );
std::ostream &TRACE( std::ostream &os );

class LogStream;

using LogHelperFunction = std::function<void( const std::string & )>;

class LogStreambuf : public std::streambuf {

public:
	enum LogLevel { DEBUG, INFO, WARNING, ERROR, TRACE };

private:
	struct Buffer {
		std::string contents_;
		LogLevel    level_{ DEBUG };
	};

public:
	LogStreambuf();
	~LogStreambuf();

public:
	void level( LogLevel level );

private:
	int_type overflow( int_type c ) override;
	std::streamsize xsputn( const char_type *s, std::streamsize n ) override;
	int_type sync() override;

private:
	thread_local static std::map<long, Buffer> buffers_;
	static std::atomic_long                    indexGenerator_;
	long                                       index_{ 0 };
	LogHelperFunction                          debug_;
	LogHelperFunction                          error_;
	LogHelperFunction                          info_;
	LogHelperFunction                          warning_;
	std::atomic_bool                           trace_{ false };
	std::string                                prefix_;

	friend class LogStream;
};

class LogStream : public std::ostream {

public:
	LogStream() : std::ostream{ &lsb_ }
	{
	}

	void debug( LogHelperFunction fn )
	{
		lsb_.debug_ = std::move( fn );
	}

	void error( LogHelperFunction fn )
	{
		lsb_.error_ = std::move( fn );
	}

	void info( LogHelperFunction fn )
	{
		lsb_.info_ = std::move( fn );
	}

	void warning( LogHelperFunction fn )
	{
		lsb_.warning_ = std::move( fn );
	}

	bool trace() const
	{
		return lsb_.trace_;
	}

	void trace( bool value )
	{
		lsb_.trace_ = value;
	}

	void prefix( const std::string &prefix )
	{
		lsb_.prefix_ = prefix;
	}

private:
	LogStreambuf lsb_;
};

extern LogStream logger;

} // namespace bdvmi

#endif // __LOGGER_H_INCLUDED__
