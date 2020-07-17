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

// #define BDVMI_DISABLE_STATS

#include "bdvmi/driver.h"
#include "bdvmi/logger.h"
#include "bdvmi/statscollector.h"
#include "xenaltp2m.h"
#include "xcwrapper.h"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <string>

namespace bdvmi {

XenAltp2mDomainState::XenAltp2mDomainState( XC &xc, uint32_t domain, bool enable )
    : xc_{ xc }
    , domain_{ domain }
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

	if ( !xc_.altp2mGetVcpuP2mIdx )
		logger << WARNING << "[ALTP2M] no p2m_idx() function present" << std::flush;

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

	uint16_t currentView;

	int rc = getCurrentView( 0, currentView );
	if ( rc < 0 )
		return rc;

	if ( view == currentView )
		return 0;

	if ( view && views_.find( view ) == views_.end() )
		return -EINVAL;

	if ( ( rc = xc_.altp2mSwitchToView( domain_, view ) ) >= 0 ) {
		currentView_ = view;
	}

	return rc;
}

int XenAltp2mDomainState::getCurrentView( uint32_t vcpu, uint16_t &view ) const
{
	if ( !enabled_ ) {
		view = 0;
		return 0;
	}

	if ( isCacheEnabled( vcpu, view ) )
		return 0;

	if ( !xc_.altp2mGetVcpuP2mIdx ) {
		view = currentView_;
		return 0;
	}

	StatsCounter counter( "altp2mGetVcpuP2mIdx" );
	return xc_.altp2mGetVcpuP2mIdx( domain_, vcpu, &view );
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

void XenAltp2mDomainState::enableCache( uint32_t vcpu, uint16_t idx )
{
	if ( !enabled_ )
		return;

	std::lock_guard<std::mutex> lock( viewCache_.mutex_ );
	viewCache_.views_[vcpu] = idx;
}

void XenAltp2mDomainState::disableCache( uint32_t vcpu )
{
	if ( !enabled_ )
		return;

	std::lock_guard<std::mutex> lock( viewCache_.mutex_ );
	viewCache_.views_.erase( vcpu );
}

bool XenAltp2mDomainState::isCacheEnabled( uint32_t vcpu, uint16_t &view ) const
{
	std::lock_guard<std::mutex> lock( viewCache_.mutex_ );
	auto                        it = viewCache_.views_.find( vcpu );

	if ( it == viewCache_.views_.end() )
		return false;

	view = it->second;

	return true;
}

} // namespace bdvmi
