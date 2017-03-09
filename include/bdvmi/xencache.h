// Copyright (c) 2015-2017 Bitdefender SRL, All rights reserved.
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

#ifndef __BDVMIXENCACHE_H_INCLUDED__
#define __BDVMXENCACHE_H_INCLUDED__

#include <map>
#include "driver.h"

extern "C" {
#include <xenctrl.h>
}

namespace bdvmi {

class LogHelper;

class XenPageCache {

public:
	enum { MAX_CACHE_SIZE_DEFAULT = 1536 /* pages */ };

private:
	struct CacheInfo {
		CacheInfo() : accessed( 0 ), pointer( NULL ), in_use( 1 )
		{
		}

		unsigned long accessed;
		void *pointer;
		short in_use;
	};

	typedef std::map<unsigned long, CacheInfo> cache_t;
	typedef std::map<void *, unsigned long> reverse_cache_t;

public:
	XenPageCache( xc_interface *xci, domid_t domain, LogHelper *logHelper = NULL );

	XenPageCache( LogHelper *logHelper = NULL );

	~XenPageCache();

public:
	void init( xc_interface *xci, domid_t domain );
	bool setLimit( size_t limit );

	MapReturnCode update( unsigned long gfn, void *&pointer );
	void release( void *pointer );

private:
	MapReturnCode insertNew( unsigned long gfn, void *&pointer );
	void cleanup();
	unsigned long generateIndex();
	bool checkPages( void *addr, size_t size );

private: // no copying around
	XenPageCache( const XenPageCache & );
	XenPageCache &operator=( const XenPageCache & );

private:
	cache_t cache_;
	reverse_cache_t reverseCache_;
	xc_interface *xci_;
	domid_t domain_;
	size_t cacheLimit_;
	LogHelper *logHelper_;
	int linuxMajVersion_;
};

} // namespace bdvmi

#endif // __BDVMIXENCACHE_H_INCLUDED__
