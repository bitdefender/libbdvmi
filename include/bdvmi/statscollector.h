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

#ifndef __BDVMISTATSCOLLECTOR_H_INCLUDED__
#define __BDVMISTATSCOLLECTOR_H_INCLUDED__

#include <map>
#include <mutex>
#include <string>

namespace bdvmi {

class StatsCollector {

private:
	StatsCollector() = default;

public:
	StatsCollector( const StatsCollector & ) = delete;
	StatsCollector &operator=( const StatsCollector & ) = delete;

public:
	static StatsCollector &instance();

public:
	void incStat( const std::string &st );

	void addToStat( const std::string &st, unsigned long number );

	// Seconds is the number of seconds elapsed since we've started
	// collecting them. The dumped stats will show numbers of each
	// stat per second.
	std::string dumpStats( int seconds );

private:
	std::map<std::string, unsigned long> stats_;
	mutable std::mutex statsMutex_;
};

} // namespace bdvmi

#endif // __BDVMISTATSCOLLECTOR_H_INCLUDED__
