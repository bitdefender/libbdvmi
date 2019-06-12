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

#include <mutex>
#include <string>
#include <atomic>
#include <unordered_map>
#include <utility>

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

	bool enabled() const
	{
		return enable_;
	}

private:
	std::atomic_bool enable_{ false };
	std::unordered_map<std::string, std::pair<unsigned long, std::chrono::duration<double>>> stats_;
	mutable std::mutex statsMutex_;
};

#ifndef BDVMI_DISABLE_STATS

class StatsCounter {

public:
	explicit StatsCounter( std::string st ) : name_{ std::move( st ) }
	{
		if ( !StatsCollector::instance().enabled() )
			return;

		start_ = std::chrono::high_resolution_clock::now();
	}

	~StatsCounter()
	{
		if ( !StatsCollector::instance().enabled() )
			return;

		StatsCollector::instance().count( name_, std::chrono::high_resolution_clock::now() - start_ );
	}

private:
	std::string                                                 name_;
	std::chrono::time_point<std::chrono::high_resolution_clock> start_;
};

#else

struct StatsCounter {
	StatsCounter( ... )
	{
	}
};

#endif // BDVMI_DISABLE_STATS

} // namespace bdvmi

#endif // __BDVMISTATSCOLLECTOR_H_INCLUDED__
