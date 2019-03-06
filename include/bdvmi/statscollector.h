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

#ifndef __BDVMISTATSCOLLECTOR_H_INCLUDED__
#define __BDVMISTATSCOLLECTOR_H_INCLUDED__

#include <map>
#include <mutex>
#include <string>
#include <atomic>

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
	void enable( bool value );

	void count( const std::string &                  st,
	            const std::chrono::duration<double> &duration = std::chrono::duration<double>::zero() );

	void dump() const;

private:
	std::atomic_bool                                     enable_{ false };
	std::map<std::string, unsigned long>                 counter_;
	std::map<std::string, std::chrono::duration<double>> duration_;
	mutable std::mutex                                   statsMutex_;
};

class StatsCounter {

public:
	StatsCounter( const std::string &st )
	{
		start_ = std::chrono::system_clock::now();
		name_  = st;
	}

	~StatsCounter()
	{
		stop_ = std::chrono::system_clock::now();
		StatsCollector::instance().count( name_, stop_ - start_ );
	}

private:
	std::string                                                 name_;
	std::chrono::time_point<std::chrono::high_resolution_clock> start_;
	std::chrono::time_point<std::chrono::high_resolution_clock> stop_;
};

} // namespace bdvmi

#endif // __BDVMISTATSCOLLECTOR_H_INCLUDED__
