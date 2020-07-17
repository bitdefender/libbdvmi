// Copyright (c) 2018-2019 Bitdefender SRL, All rights reserved.
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

#ifndef __BDVMIXENALTP2M_H_INCLUDED__
#define __BDVMIXENALTP2M_H_INCLUDED__

#ifndef __XEN_TOOLS__
#define __XEN_TOOLS__ 1
#endif

#include <cstdint>
#include <mutex>
#include <set>
#include <unordered_map>

#include "xcwrapper.h"

extern "C" {
#include <xen/memory.h>
}

namespace bdvmi {

class XenAltp2mDomainState {

	struct ViewCache {
		std::unordered_map< uint32_t, uint16_t > views_;
		std::mutex mutex_;
	};

public:
	XenAltp2mDomainState( XC &xc, uint32_t domain, bool enable = true );
	~XenAltp2mDomainState();

	int createView( xenmem_access_t defaultAccess, uint16_t &id );

	int switchToView( uint16_t view );

	int destroyView( uint16_t view );

	int getCurrentView( uint32_t vcpu, uint16_t &view ) const;

	int setVEInfoPage( uint32_t vcpu, xen_pfn_t gpa );

	int disableVE( uint32_t vcpu );

	int setSuppressVE( uint16_t view, xen_pfn_t gfn, bool sve );

	int getSuppressVE( uint16_t view, xen_pfn_t gfn, bool &sve );

	explicit operator bool() const
	{
		return enabled_;
	}

	void enableCache( uint32_t vcpu, uint16_t view );

	void disableCache( uint32_t vcpu );

private:
	bool isCacheEnabled( uint32_t vcpu, uint16_t &view ) const;

private:
	XC &               xc_;
	uint32_t           domain_;
	uint16_t           currentView_{ 0 };
	std::set<uint16_t> views_;
	bool               enabled_{ false };
	mutable ViewCache  viewCache_;
};

} // namespace bdvmi
#endif //__BDVMIXENALTP2M_H_INCLUDED__
