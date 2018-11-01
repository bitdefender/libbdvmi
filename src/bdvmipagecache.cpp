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

#include "bdvmi/loghelper.h"
#include "bdvmi/pagecache.h"
#include <sys/mman.h>
#include <cstring>
#include <fstream>
#include <errno.h>

namespace bdvmi {

PageCache::PageCache( Driver &driver, LogHelper *logHelper )
    : driver_{ driver }, logHelper_{ logHelper }
{
	std::ifstream in( "/proc/sys/kernel/osrelease" );

	if ( in )
		in >> linuxMajVersion_;
	else
		LOG_WARNING( logHelper_, "Cannot access /proc/sys/kernel/osrelease" );
}

bool PageCache::checkPages( void *addr, size_t size )
{
	unsigned char vec[1] = {};

	// The page is not present or otherwise unavailable
	if ( linuxMajVersion_ < 4  && ( mincore( addr, size, vec ) < 0 || !( vec[0] & 0x01 ) ) )
		return false;

	return true;
}

size_t PageCache::setLimit( size_t limit )
{
	if ( limit >= 50 ) // magic number!
		cacheLimit_ = limit;

	return cacheLimit_;
}

PageCache::~PageCache()
{
	for ( auto &&item : cache_ )
		// don't need to do anything else, std::map::~map() will
		// take care of itself
		driver_.unmapGuestPageImpl( item.second.pointer, item.first );
}

MapReturnCode PageCache::update( unsigned long gfn, void *&pointer )
{
	cache_t::iterator i = cache_.find( gfn );

	if ( i == cache_.end() ) // not found
		return insertNew( gfn, pointer );

	i->second.accessed = generateIndex();
	++i->second.inUse;

	pointer = i->second.pointer;
	return MAP_SUCCESS;
}

void PageCache::release( void *pointer )
{
	reverse_cache_t::const_iterator ri = reverseCache_.find( pointer );

	if ( ri == reverseCache_.end() )
		return; // nothing to do, not in cache (how did we get here though?)

	cache_t::iterator ci = cache_.find( ri->second );

	if ( ci == cache_.end() )
		return; // this should be impossible

	--ci->second.inUse; // decrease refcount
}

MapReturnCode PageCache::insertNew( unsigned long gfn, void *&pointer )
{
	if ( cache_.size() >= cacheLimit_ )
		cleanup();

	CacheInfo ci;

	ci.accessed = generateIndex();
	ci.inUse = 1;
	ci.pointer = driver_.mapGuestPageImpl( gfn );

	if ( !ci.pointer ) {
		/*
		LOG_ERROR( logHelper_, "xc_map_foreign_range(0x", std::setfill( '0' ), std::setw( 16 ), std::hex, gfn,
		           ") failed: ", strerror( errno ) );
		*/

		pointer = nullptr;
		return MAP_FAILED_GENERIC;
	}

	if ( !checkPages( ci.pointer, PAGE_SIZE ) ) {
		LOG_ERROR( logHelper_, "check_pages(0x", std::setfill( '0' ), std::setw( 16 ), std::hex, gfn,
		           ") failed: ", strerror( errno ) );

		driver_.unmapGuestPageImpl( ci.pointer, gfn );

		pointer = nullptr;
		return MAP_PAGE_NOT_PRESENT;
	}

	cache_[gfn] = ci;
	reverseCache_[ci.pointer] = gfn;

	pointer = ci.pointer;
	return MAP_SUCCESS;
}

void PageCache::cleanup()
{
	std::multimap<unsigned long, unsigned long> timeOrderedGFNs;

	for ( auto &&item : cache_ )
		if ( item.second.inUse < 1 )
			timeOrderedGFNs.insert(
			        std::pair<unsigned long, unsigned long>( item.second.accessed, item.first ) );

	size_t count = 0;

	for ( auto &&item : timeOrderedGFNs ) {
		if ( count++ >= cacheLimit_ / 2 )
			break;

		cache_t::iterator ci = cache_.find( item.second );

		if ( ci == cache_.end() )
			continue;

		driver_.unmapGuestPageImpl( ci->second.pointer, ci->first );
		reverseCache_.erase( ci->second.pointer );
		cache_.erase( ci );
	}
}

unsigned long PageCache::generateIndex()
{
	static unsigned long index = 0;
	return index++;
}

} // namespace bdvmi
