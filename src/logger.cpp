// Copyright (c) 2018-2019 Bitdefender SRL, All rights reserved.
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

#include <bdvmi/logger.h>

namespace {

std::ostream &setLevel( std::ostream &os, bdvmi::LogStreambuf::LogLevel level )
{
	bdvmi::LogStreambuf *lsb = dynamic_cast<bdvmi::LogStreambuf *>( os.rdbuf() );

	if ( lsb )
		lsb->level( level );

	return os;
}
} // anonymous namespace

namespace bdvmi {

thread_local std::unordered_map<long, LogStreambuf::Buffer> LogStreambuf::buffers_;
std::atomic_long LogStreambuf::indexGenerator_{ 0 };

LogStreambuf::LogStreambuf()
{
	index_ = ++indexGenerator_;
}

LogStreambuf::~LogStreambuf()
{
	sync();

	// You'd think we'd buffers_.erase( index_ ) here, but a logger is often a global
	// object, and there are legitimate cases where that means that buffers_ is destroyed
	// _before_ it (especially with all the thread_local magic).
	// This means that the application will end up with a buffer per logger instance until
	// the end. It shouldn't be a big deal - how many different loggers could one
	// application be interested in?
}

void LogStreambuf::level( LogLevel level )
{
	sync();
	buffers_[index_].level_ = level;
}

LogStreambuf::int_type LogStreambuf::overflow( int_type c )
{
	if ( c != EOF )
		buffers_[index_].contents_ += static_cast<char>( c );

	return c;
}

std::streamsize LogStreambuf::xsputn( const char_type *s, std::streamsize n )
{
	buffers_[index_].contents_.append( s, n );

	return n;
}

LogStreambuf::int_type LogStreambuf::sync()
{
	if ( buffers_[index_].contents_.empty() )
		return 0;

	auto &buffer = buffers_[index_];

	if ( !prefix_.empty() )
		buffer.contents_ = prefix_ + buffer.contents_;

	switch ( buffer.level_ ) {
		case DEBUG:
			if ( debug_ )
				debug_( buffer.contents_ );
			break;
		case TRACE: // TRACE is a special case of DEBUG
			if ( debug_ && trace_ )
				debug_( buffer.contents_ );
			break;
		case ERROR:
			if ( error_ )
				error_( buffer.contents_ );
			break;
		case INFO:
			if ( info_ )
				info_( buffer.contents_ );
			break;
		case WARNING:
			if ( warning_ )
				warning_( buffer.contents_ );
			break;
		default:
			buffer.contents_.clear();
			return -1;
	}

	buffer.contents_.clear();
	return 0;
}

// Singleton, but not enforced (there's no harm in several instances)
LogStream logger;

std::ostream &DEBUG( std::ostream &os )
{
	return setLevel( os, LogStreambuf::DEBUG );
}

std::ostream &ERROR( std::ostream &os )
{
	return setLevel( os, LogStreambuf::ERROR );
}

std::ostream &INFO( std::ostream &os )
{
	return setLevel( os, LogStreambuf::INFO );
}

std::ostream &WARNING( std::ostream &os )
{
	return setLevel( os, LogStreambuf::WARNING );
}

std::ostream &TRACE( std::ostream &os )
{
	return setLevel( os, LogStreambuf::TRACE );
}

} // namespace bdvmi
