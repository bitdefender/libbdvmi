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

#ifndef __BDVMIPAGECACHE_H_INCLUDED__
#define __BDVMIPAGECACHE_H_INCLUDED__

#include "driver.h"
#include <unordered_map>

namespace bdvmi {

class PageCache {

public:
	static constexpr size_t MAX_CACHE_SIZE_DEFAULT = 1536; // pages

private:
	struct CacheInfo {
		unsigned long accessed{ 0 };
		void *        pointer{ nullptr };
		short         inUse{ 1 };
	};

	using CacheMap        = std::unordered_map<unsigned long, CacheInfo>;
	using ReverseCacheMap = std::unordered_map<void *, unsigned long>;

public:
	PageCache( Driver *driver );
	~PageCache();

public:
	size_t setLimit( size_t limit );

	void reset();
	void driver( Driver *driver )
	{
		driver_ = driver;
	}
	MapReturnCode update( unsigned long gfn, void *&pointer );
	bool          release( void *pointer );

private:
	MapReturnCode insertNew( unsigned long gfn, void *&pointer );
	void          cleanup();
	unsigned long generateIndex() const;
	bool          checkPages( void *addr, size_t size ) const;

public: // no copying around
	PageCache( const PageCache & ) = delete;
	PageCache &operator=( const PageCache & ) = delete;

private:
	Driver *        driver_;
	CacheMap        cache_;
	ReverseCacheMap reverseCache_;
	size_t          cacheLimit_{ MAX_CACHE_SIZE_DEFAULT };
	int             linuxMajVersion_{ -1 };
};

} // namespace bdvmi

#endif // __BDVMIPAGECACHE_H_INCLUDED__
