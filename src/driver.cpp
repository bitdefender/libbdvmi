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
			item.second.clear();
		}
	}

	std::lock_guard<std::mutex> guard( convertibleCacheMutex_ );

	for ( auto &&item : delayedConvertibleWrite_ ) {
		if ( item.second.empty() )
			continue;

		setPageConvertibleImpl( item.second, item.first );
		item.second.clear();
	}
}

} // namespace bdvmi
