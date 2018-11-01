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

#include "bdvmi/statscollector.h"
#include <sstream>

#ifdef DUMP_STATS
#define DEBUG_ONLY_PARAM( x ) x
#else
#define DEBUG_ONLY_PARAM( x )
#endif

namespace bdvmi {

StatsCollector & StatsCollector::instance()
{
	static StatsCollector theInstance;
	return theInstance;
}

void StatsCollector::incStat( const std::string & DEBUG_ONLY_PARAM( st ) )
{
#ifdef DUMP_STATS
	std::lock_guard<std::mutex> lock( statsMutex_ );
	stats_[st]++;
#endif
}

void StatsCollector::addToStat( const std::string & DEBUG_ONLY_PARAM( st ),
                                unsigned long DEBUG_ONLY_PARAM( number ) )
{
#ifdef DUMP_STATS
	std::lock_guard<std::mutex> lock( statsMutex_ );
	stats_[st] += number;
#endif
}

std::string StatsCollector::dumpStats(int DEBUG_ONLY_PARAM( seconds ) )
{
#ifdef DUMP_STATS
	std::lock_guard<std::mutex> lock( statsMutex_ );

	std::stringstream ss;

	for ( auto &&s : stats_ )
		ss << s.first << ": " << ( double )s.second / seconds << " ";

	stats_.clear();

	return ss.str();
#else
	return "";
#endif
}

} // namespace bdvmi
