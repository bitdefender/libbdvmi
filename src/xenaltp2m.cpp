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

#include "bdvmi/driver.h"
#include "bdvmi/logger.h"
#include "xenaltp2m.h"
#include "xcwrapper.h"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <string>

namespace bdvmi {

XenAltp2mDomainState::XenAltp2mDomainState( XC &xc, uint32_t domain, bool enable )
    : xc_{ xc }, domain_{ domain }
{
	if ( !enable )
		return;

	if ( !xc_.altp2mSetVcpuDisableNotify ) {
		logger << WARNING << "[ALTP2M] no disable_notify() function present" << std::flush;
		return;
	}

	if ( !xc_.altp2mSetSuppressVE || !xc_.altp2mGetSuppressVE ) {
		logger << WARNING << "[ALTP2M] no #VE suppress bit handlers available" << std::flush;
		return;
	}

	if ( xc_.altp2mSetDomainState( domain, true ) < 0 ) {
		logger << WARNING << "[ALTP2M] could not enable altp2m on domain: " << strerror( errno ) << std::flush;
		return;
	}

	enabled_ = true;
}

XenAltp2mDomainState::~XenAltp2mDomainState()
{
	if ( !enabled_ )
		return;

	switchToView( 0 );

	for ( auto &&view : views_ )
		xc_.altp2mDestroyView( domain_, view );

	xc_.altp2mSetDomainState( domain_, false );
}

int XenAltp2mDomainState::createView( xenmem_access_t defaultAccess, uint16_t &id )
{
	if ( !enabled_ )
		return -ENOTSUP;

	int rc;
	if ( ( rc = xc_.altp2mCreateView( domain_, defaultAccess, &id ) ) >= 0 ) {
		// Driver::MemAccessMap ma;
		// ma[~0ull] = Driver::PAGE_READ | Driver::PAGE_WRITE;
		// xc_.altp2mSetMemAccess( domain_, id, ma );

		views_.insert( id );
	}

	return rc;
}

int XenAltp2mDomainState::destroyView( uint16_t view )
{
	if ( !enabled_ )
		return -ENOTSUP;

	int rc = xc_.altp2mDestroyView( domain_, view );

	if ( rc >= 0 )
		views_.erase( view );

	return rc;
}

int XenAltp2mDomainState::switchToView( uint16_t view )
{
	if ( !enabled_ )
		return -ENOTSUP;

	if ( view == currentView_ )
		return 0;

	if ( view && views_.find( view ) == views_.end() )
		return -EINVAL;

	int rc;

	if ( ( rc = xc_.altp2mSwitchToView( domain_, view ) ) >= 0 )
		currentView_ = view;

	return rc;
}

int XenAltp2mDomainState::setVEInfoPage( uint32_t vcpu, xen_pfn_t gpa )
{
	if ( !enabled_ )
		return -ENOTSUP;

	return xc_.altp2mSetVcpuEnableNotify( domain_, vcpu, gpa );
}

int XenAltp2mDomainState::disableVE( uint32_t vcpu )
{
	if ( !enabled_ || !xc_.altp2mSetVcpuDisableNotify )
		return -ENOTSUP;

	return xc_.altp2mSetVcpuDisableNotify( domain_, vcpu );
}

int XenAltp2mDomainState::setSuppressVE( uint16_t view, xen_pfn_t gfn, bool sve )
{
	if ( !enabled_ )
		return -ENOTSUP;

	if ( view && views_.find( view ) == views_.end() )
		return -EINVAL;

	return xc_.altp2mSetSuppressVE( domain_, view, gfn, sve );
}

int XenAltp2mDomainState::getSuppressVE( uint16_t view, xen_pfn_t gfn, bool &sve )
{
	if ( !enabled_ )
		return -ENOTSUP;

	if ( view && views_.find( view ) == views_.end() )
		return -EINVAL;

	return xc_.altp2mGetSuppressVE( domain_, view, gfn, &sve );
}

} // namespace bdvmi
