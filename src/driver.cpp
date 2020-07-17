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

#include "bdvmi/driver.h"
#include "bdvmi/logger.h"
#include <utility>

namespace bdvmi {

bool Driver::setPageProtection( unsigned long long guestAddress, bool read, bool write, bool execute,
                                unsigned short view )
{
	/*
	 * The Intel SDM says:
	 *
	 * AN EPT misconfiguration occurs if any of the following is identified while translating
	 * a guest-physical address:
	 *
	 * * The value of bits 2:0 of an EPT paging-structure entry is either 010b (write-only)
	 *   or 110b (write/execute).
	 *
	 */
	if ( write && !read ) {
		logger << ERROR << "Attempted to set GPA " << std::hex << std::showbase << guestAddress << " "
		       << ( read ? "r" : "-" ) << ( write ? "w" : "-" ) << ( execute ? "x" : "-" ) << std::flush;
		return false;
	}

	uint64_t gfn       = gpa_to_gfn( guestAddress );
	uint8_t  memaccess = ( read ? PAGE_READ : 0 ) | ( write ? PAGE_WRITE : 0 ) | ( execute ? PAGE_EXECUTE : 0 );

	std::lock_guard<std::mutex> guard( memAccessCacheMutex_ );

	auto &&accessMap = memAccessCache_[view];
	auto   it        = accessMap.find( gfn );

	if ( it == accessMap.end() && read && write && execute )
		return true;

	if ( it != accessMap.end() && it->second == memaccess )
		return true;

	memAccessCache_[view][gfn]        = memaccess;
	delayedMemAccessWrite_[view][gfn] = memaccess;

	return true;
}

bool Driver::setEPTPageConvertible( unsigned short view, unsigned long long guestAddress, bool convertible )
{
	uint64_t gfn = gpa_to_gfn( guestAddress );

	std::lock_guard<std::mutex> guard( convertibleCacheMutex_ );

	delayedConvertibleWrite_[view][gfn] = convertible;

	// TODO: if we can't think of any input validation criteria, this function should become void
	return true;
}

bool Driver::getPageProtection( unsigned long long guestAddress, bool &read, bool &write, bool &execute,
                                unsigned short view )
{
	uint64_t gfn       = gpa_to_gfn( guestAddress );
	uint8_t  memaccess = 0;

	{
		std::lock_guard<std::mutex> guard( memAccessCacheMutex_ );

		auto &&accessMap = memAccessCache_[view];
		auto   it        = accessMap.find( gfn );

		if ( it != accessMap.end() ) {
			memaccess = it->second;

			read    = !!( memaccess & PAGE_READ );
			write   = !!( memaccess & PAGE_WRITE );
			execute = !!( memaccess & PAGE_EXECUTE );

			return true;
		}
	}

	if ( !getPageProtectionImpl( guestAddress, read, write, execute, view ) )
		return false;

	memaccess = ( read ? PAGE_READ : 0 ) | ( write ? PAGE_WRITE : 0 ) | ( execute ? PAGE_EXECUTE : 0 );

	std::lock_guard<std::mutex> guard( memAccessCacheMutex_ );
	memAccessCache_[view][gfn] = memaccess;

	return true;
}

void Driver::flushPageProtections()
{
	{
		std::lock_guard<std::mutex> guard( memAccessCacheMutex_ );

		for ( auto &&item : delayedMemAccessWrite_ ) {
			if ( item.second.empty() )
				continue;

			setPageProtectionImpl( item.second, item.first );

			// item.second.clear();
			decltype( item.second ) notUsingMemory;
			std::swap( item.second, notUsingMemory );
		}
	}

	std::lock_guard<std::mutex> guard( convertibleCacheMutex_ );

	for ( auto &&item : delayedConvertibleWrite_ ) {
		if ( item.second.empty() )
			continue;

		setPageConvertibleImpl( item.second, item.first );

		// item.second.clear();
		decltype( item.second ) notUsingMemory;
		std::swap( item.second, notUsingMemory );
	}
}

bool Driver::maxGPFN( unsigned long long &gfn )
{
	std::lock_guard<std::mutex> guard( maxGPFNMutex_ );

	// Integrators call this method before becoming multi-threaded relying on the fact
	// that the result gets cached and the algorithm below never gets to run again
	if ( maxGPFN_ ) {
		gfn = maxGPFN_;
		return true;
	}

	unsigned long long maxGpfn = 0;

	if ( !maxGPFNImpl( maxGpfn ) )
		return false;

		//
		// The code below resided in the introspection engine (introcore), but it was decided that
		// it should be pushed down to the glue layer. While in its initial location the following
		// explanation existed for it:
		//
		// although there is a GLUE_IFACE.QueryGuestInfo information class that returns this
		// information, #IG_QUERY_INFO_CLASS_MAX_GPFN, in practice is has been observed to not
		// always be accurate. Especially on XEN, for example, for guests with 1G of memory it
		// would usually report back 4G of memory available, or for guests with more memory, the
		// value would be slightly below the last page the guest could actually access. Since
		// having this information is vital for some subsystems (such as the \#VE one), we try to
		// figure it out ourselves. The algorithm is simple enough. Start with the page returned
		// by #IG_QUERY_INFO_CLASS_MAX_GPFN query, and try to see if there is any memory available
		// about it. If a physical page is mappable, we consider that it is available to the guest,
		// since introcore should not be able to access memory that is not available to the guest.
		// We do this search until a hole of 256 consecutive invalid pages is found. If during this
		// search a valid page is found above the one returned by the hypervisor, we consider it to
		// be the last physical page which the guest can access. If no page is found about the hint
		// value, we may be in the case in which the hypervisor reported more than the guest has
		// access to. While this is not as critical as the case in which the value is lower, it may
		// still lead to unnecessary memory consumption. In this case we go below the page returned
		// by the hypervisor until we find a page that we can map. The first page that can be
		// mapped is treated as the last physical page the guest can access. Since this value will
		// not change while introcore is running, it is cached inside the #gGuest variable and
		// subsequent calls to this function will return the cached value, in order to avoid long
		// pauses every time the query is done.
		//

#define MAX_GPA_SEARCH_COUNT 256

	bool atLeastOneValid = false;

	// A frame number is returned, so shift it to make it a GPA again.
	unsigned long long lastOkGpa = maxGpfn << 12;
	unsigned long long testGpa   = lastOkGpa + PAGE_SIZE;

	// Sometimes max GPFN does not actually tell us what is the last GPA that the guest can
	// access, so we try to find it by mapping some pages above it and see where we are
	// forced to stop. We've observed that for some VMs, GPFNs above max GPFN are sometimes
	// used by a guest (for PTs, for example).
	unsigned int invalidCount = 0;
	while ( invalidCount < MAX_GPA_SEARCH_COUNT ) {
		void *dummy = nullptr;

		if ( mapPhysMemToHost( testGpa, PAGE_SIZE, PHYSMAP_NO_CACHE, dummy ) == MAP_SUCCESS ) {
			lastOkGpa = testGpa;
			unmapPhysMem( dummy );
			invalidCount    = 0;
			atLeastOneValid = true;
		} else
			invalidCount++;

		testGpa += PAGE_SIZE;
	}

	if ( !atLeastOneValid ) {
		testGpa = lastOkGpa;

		while ( true ) {
			void *dummy = nullptr;

			if ( mapPhysMemToHost( testGpa, PAGE_SIZE, PHYSMAP_NO_CACHE, dummy ) == MAP_SUCCESS ) {
				lastOkGpa = testGpa;
				unmapPhysMem( dummy );
				break;
			}

			testGpa -= PAGE_SIZE;

			if ( !testGpa ) {
				logger << ERROR << "No valid GPA was found" << std::flush;
				return false;
			}
		}
	}

#undef MAX_GPA_SEARCH_COUNT

	maxGPFN_ = gfn = lastOkGpa >> 12;

	logger << DEBUG << "MaxGPFN: " << std::hex << std::showbase << maxGPFN_ << std::flush;

	return true;
}

} // namespace bdvmi
