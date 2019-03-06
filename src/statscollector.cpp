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

#include "bdvmi/statscollector.h"
#include "bdvmi/logger.h"

namespace bdvmi {

StatsCollector &StatsCollector::instance()
{
	static StatsCollector theInstance;
	return theInstance;
}

void StatsCollector::enable( bool value )
{
	enable_ = value;

	std::lock_guard<std::mutex> lock( statsMutex_ );
	counter_.clear();
	duration_.clear();
}

void StatsCollector::count( const std::string &st, const std::chrono::duration<double> &duration )
{
	if ( !enable_ )
		return;

	std::lock_guard<std::mutex> lock( statsMutex_ );
	counter_[st]++;
	duration_[st] += duration;
}

void StatsCollector::dump() const
{
	std::lock_guard<std::mutex> lock( statsMutex_ );

	logger << DEBUG;
	for ( auto &&s : counter_ )
		logger << s.first << ": " << s.second << "; ";
	logger << std::flush;

	logger << DEBUG;
	for ( auto &&s : duration_ )
		logger << s.first << ": " << s.second.count() << " s; ";
	logger << std::flush;
}

} // namespace bdvmi
