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

#include "bdvmi/driver.h"
#include "bdvmi/loghelper.h"

namespace bdvmi {

bool Driver::setPageProtection( unsigned long long guestAddress, bool read, bool write, bool execute )
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
		LOG_ERROR( logHelper_, "Attempted to set GPA ", std::hex, std::showbase, guestAddress, " ",
		           ( read ? "r" : "-" ), ( write ? "w" : "-" ), ( execute ? "x" : "-" ) );
		return false;
	}

	uint64_t gfn       = gpa_to_gfn( guestAddress );
	uint8_t  memaccess = ( read ? PAGE_READ : 0 ) | ( write ? PAGE_WRITE : 0 ) | ( execute ? PAGE_EXECUTE : 0 );

	std::lock_guard<std::mutex> guard( memAccessCacheMutex_ );

	memAccessCache_[gfn]        = memaccess;
	delayedMemAccessWrite_[gfn] = memaccess;

	return true;
}

bool Driver::getPageProtection( unsigned long long guestAddress, bool &read, bool &write, bool &execute )
{
	uint64_t gfn       = gpa_to_gfn( guestAddress );
	uint8_t  memaccess = 0;

	{
		std::lock_guard<std::mutex> guard( memAccessCacheMutex_ );

		auto it = memAccessCache_.find( gfn );
		if ( it != memAccessCache_.end() ) {
			memaccess = it->second;

			read    = !!( memaccess & PAGE_READ );
			write   = !!( memaccess & PAGE_WRITE );
			execute = !!( memaccess & PAGE_EXECUTE );

			return true;
		}
	}

	if ( !getPageProtectionImpl( guestAddress, read, write, execute ) )
		return false;

	memaccess = ( read ? PAGE_READ : 0 ) | ( write ? PAGE_WRITE : 0 ) | ( execute ? PAGE_EXECUTE : 0 );

	std::lock_guard<std::mutex> guard( memAccessCacheMutex_ );
	memAccessCache_[gfn] = memaccess;

	return true;
}

bool Driver::getDelayedPageProtection( unsigned long long guestAddress, unsigned &access )
{
	uint64_t gfn = gpa_to_gfn( guestAddress );

	std::lock_guard<std::mutex> guard( memAccessCacheMutex_ );

	auto it = delayedMemAccessWrite_.find( gfn );
	if ( it == delayedMemAccessWrite_.end() )
		return false;

	access = it->second;

	return true;
}

void Driver::flushPageProtections()
{
	std::lock_guard<std::mutex> guard( memAccessCacheMutex_ );

	if ( delayedMemAccessWrite_.empty() )
		return;

	setPageProtectionImpl( delayedMemAccessWrite_ );

	delayedMemAccessWrite_.clear();
}

} // namespace bdvmi
