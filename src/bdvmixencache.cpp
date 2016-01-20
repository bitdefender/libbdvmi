// Copyright (c) 2015-2016 Bitdefender SRL, All rights reserved.
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
#include "bdvmi/xencache.h"
#include <sys/mman.h>
#include <cstring>
#include <sstream>
#include <errno.h>
#include <iomanip>

namespace bdvmi {

static bool check_pages( void *addr, size_t size )
{
	unsigned char vec[1] = {};

	// The page is not present or otherwise unavailable
	if ( mincore( addr, size, vec ) < 0 || !( vec[0] & 0x01 ) )
		return false;

	return true;
}

XenPageCache::XenPageCache( xc_interface *xci, domid_t domain, LogHelper *logHelper )
    : xci_( NULL ), domain_( -1 ), cacheLimit_( MAX_CACHE_SIZE_DEFAULT ), logHelper_( logHelper )
{
	init( xci, domain );
}

XenPageCache::XenPageCache( LogHelper *logHelper )
    : xci_( NULL ), domain_( -1 ), cacheLimit_( MAX_CACHE_SIZE_DEFAULT ), logHelper_( logHelper )
{
}

void XenPageCache::init( xc_interface *xci, domid_t domain )
{
	xci_ = xci;
	domain_ = domain;
}

bool XenPageCache::setLimit( size_t limit )
{
	if ( limit < 50 ) // magic number!
		return false;

	cacheLimit_ = limit;
	return true;
}

XenPageCache::~XenPageCache()
{
	cache_t::iterator i = cache_.begin();

	for ( ; i != cache_.end(); ++i ) {
		munmap( i->second.pointer, XC_PAGE_SIZE );

		// don't need to do anything else, std::map::~map() will
		// take care of itself
	}
}

MapReturnCode XenPageCache::update( unsigned long gfn, void *&pointer )
{
	if ( !xci_ ) {
		pointer = NULL;
		return MAP_FAILED_GENERIC;
	}

	cache_t::iterator i = cache_.find( gfn );

	if ( i == cache_.end() ) // not found
		return insertNew( gfn, pointer );

	i->second.accessed = generateIndex();
	i->second.in_use = true;

	pointer = i->second.pointer;
	return MAP_SUCCESS;
}

void XenPageCache::release( void *pointer )
{
	reverse_cache_t::const_iterator ri = reverseCache_.find( pointer );

	if ( ri == reverseCache_.end() )
		return; // nothing to do, not in cache (how did we get here though?)

	cache_t::iterator ci = cache_.find( ri->second );

	if ( ci == cache_.end() )
		return; // this should be impossible

	ci->second.in_use = false; // mark for collection
}

MapReturnCode XenPageCache::insertNew( unsigned long gfn, void *&pointer )
{
	if ( !xci_ ) {
		pointer = NULL;
		return MAP_FAILED_GENERIC;
	}

	if ( cache_.size() >= cacheLimit_ )
		cleanup();

	CacheInfo ci;

	ci.accessed = generateIndex();
	ci.in_use = true;
	ci.pointer = xc_map_foreign_range( xci_, domain_, XC_PAGE_SIZE, PROT_READ | PROT_WRITE, gfn );

	if ( !ci.pointer ) {

		/*
		if ( logHelper_ ) {

		        std::stringstream ss;
		        ss << "xc_map_foreign_range(0x" << std::setfill( '0' ) << std::setw( 16 ) << std::hex << gfn
		           << ") failed: " << strerror( errno );

		        logHelper_->error( ss.str() );
		}
		*/

		pointer = NULL;
		return MAP_FAILED_GENERIC;
	}

	if ( !check_pages( ci.pointer, XC_PAGE_SIZE ) ) {

		if ( logHelper_ ) {
			std::stringstream ss;
			ss << "check_pages(0x" << std::setfill( '0' ) << std::setw( 16 ) << std::hex << gfn
			   << ") failed: " << strerror( errno );

			logHelper_->error( ss.str() );
		}

		munmap( ci.pointer, XC_PAGE_SIZE );

		pointer = NULL;
		return MAP_PAGE_NOT_PRESENT;
	}

	cache_[gfn] = ci;
	reverseCache_[ci.pointer] = gfn;

	pointer = ci.pointer;
	return MAP_SUCCESS;
}

void XenPageCache::cleanup()
{
	std::multimap<unsigned long, unsigned long> timeOrderedGFNs;
	cache_t::iterator ci = cache_.begin();

	for ( ; ci != cache_.end(); ++ci ) {
		if ( !ci->second.in_use )
			timeOrderedGFNs.insert(
			        std::pair<unsigned long, unsigned long>( ci->second.accessed, ci->first ) );
	}

	size_t count = 0, unmapped = 0, total = cache_.size();
	std::multimap<unsigned long, unsigned long>::const_iterator ti = timeOrderedGFNs.begin();

	for ( ; ti != timeOrderedGFNs.end(); ++ti ) {

		if ( count++ >= cacheLimit_ / 2 )
			break;

		ci = cache_.find( ti->second );

		if ( ci == cache_.end() )
			continue;

		munmap( ci->second.pointer, XC_PAGE_SIZE );
		reverseCache_.erase( ci->second.pointer );
		cache_.erase( ci );

		++unmapped;
	}

	if ( logHelper_ ) {
		std::stringstream ss;

		ss << "Page cache cleanup - total: " << total << " unused: " << timeOrderedGFNs.size()
		   << " deleted: " << unmapped;

		logHelper_->debug( ss.str() );
	}
}

unsigned long XenPageCache::generateIndex()
{
	static unsigned long index = 0;
	return index++;
}

} // namespace bdvmi
