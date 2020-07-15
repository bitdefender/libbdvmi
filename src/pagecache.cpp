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

#include <algorithm>
#include "bdvmi/logger.h"
#include "bdvmi/pagecache.h"
#include <sys/mman.h>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <errno.h>
#include <vector>

namespace bdvmi {

PageCache::PageCache( Driver *driver ) : driver_{ driver }
{
	std::ifstream in( "/proc/sys/kernel/osrelease" );

	if ( in )
		in >> linuxMajVersion_;
	else
		logger << WARNING << "Cannot access /proc/sys/kernel/osrelease" << std::flush;
}

bool PageCache::checkPages( void *addr, size_t size ) const
{
	unsigned char vec[1] = {};

	// The page is not present or otherwise unavailable
	if ( linuxMajVersion_ < 4 && ( mincore( addr, size, vec ) < 0 || !( vec[0] & 0x01 ) ) )
		return false;

	return true;
}

size_t PageCache::setLimit( size_t limit )
{
	if ( limit >= 50 ) // magic number!
		cacheLimit_ = limit;

	return cacheLimit_;
}

void PageCache::reset()
{
	if ( driver_ ) {
		for ( auto &&item : cache_ ) {
			if ( item.second.inUse )
				logger << TRACE << "Address " << item.second.pointer << " (gfn " << std::hex
				       << reverseCache_[item.second.pointer] << std::dec << ") is still mapped ("
				       << item.second.inUse << ") ?!" << std::flush;

			driver_->unmapGuestPageImpl( item.second.pointer, item.first );
		}
	}

	cache_.clear();
}

PageCache::~PageCache()
{
	reset();
}

MapReturnCode PageCache::update( unsigned long gfn, void *&pointer )
{
	auto i = cache_.find( gfn );

	if ( i == cache_.end() ) // not found
		return insertNew( gfn, pointer );

	i->second.accessed = generateIndex();
	++i->second.inUse;

	pointer = i->second.pointer;
	return MAP_SUCCESS;
}

bool PageCache::release( void *pointer )
{
	auto ri = reverseCache_.find( pointer );

	if ( ri == reverseCache_.end() )
		return false; // nothing to do, not in cache

	auto ci = cache_.find( ri->second );

	if ( ci == cache_.end() )
		return false;

	--ci->second.inUse; // decrease refcount

	return true;
}

MapReturnCode PageCache::insertNew( unsigned long gfn, void *&pointer )
{
	if ( !driver_ ) {
		pointer = nullptr;
		return MAP_FAILED_GENERIC;
	}

	if ( cache_.size() >= cacheLimit_ )
		cleanup();

	CacheInfo ci;

	ci.accessed = generateIndex();
	ci.inUse    = 1;
	ci.pointer  = driver_->mapGuestPageImpl( gfn );

	if ( !ci.pointer ) {
		/*
		logger << ERROR << "xc_map_foreign_range(0x" << std::setfill( '0' ) << std::setw( 16 )
		        << std::hex << gfn << ") failed: " << strerror( errno ) << std::flush;
		*/

		pointer = nullptr;
		return MAP_FAILED_GENERIC;
	}

	if ( !checkPages( ci.pointer, PAGE_SIZE ) ) {
		logger << ERROR << "check_pages(0x" << std::setfill( '0' ) << std::setw( 16 ) << std::hex << gfn
		       << ") failed: " << strerror( errno ) << std::flush;

		driver_->unmapGuestPageImpl( ci.pointer, gfn );

		pointer = nullptr;
		return MAP_PAGE_NOT_PRESENT;
	}

	cache_[gfn]               = ci;
	reverseCache_[ci.pointer] = gfn;

	pointer = ci.pointer;
	return MAP_SUCCESS;
}

void PageCache::cleanup()
{
	std::vector<std::pair<unsigned long, unsigned long>> timeOrderedGFNs;

	for ( auto &&item : cache_ )
		if ( item.second.inUse < 1 )
			timeOrderedGFNs.push_back(
			        std::pair<unsigned long, unsigned long>( item.second.accessed, item.first ) );

	if ( timeOrderedGFNs.empty() ) // All mapped pages are in use.
		return;

	std::sort( timeOrderedGFNs.begin(), timeOrderedGFNs.end(),
	           []( const auto &lhs, const auto &rhs ) { return lhs.first < rhs.first; } );

	size_t count = 0;

	for ( auto &&item : timeOrderedGFNs ) {
		if ( count++ >= cacheLimit_ / 2 )
			break;

		auto ci = cache_.find( item.second );

		if ( ci == cache_.end() )
			continue;

		driver_->unmapGuestPageImpl( ci->second.pointer, ci->first );
		reverseCache_.erase( ci->second.pointer );
		cache_.erase( ci );
	}
}

unsigned long PageCache::generateIndex() const
{
	static unsigned long index = 0;
	return index++;
}

} // namespace bdvmi
