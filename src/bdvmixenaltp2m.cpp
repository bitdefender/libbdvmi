// Copyright (c) 2018 Bitdefender SRL, All rights reserved.
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

#include "xenaltp2m.h"
#include "xcwrapper.h"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <string>

namespace bdvmi {

XenAltp2mDomainState::XenAltp2mDomainState( XC &xc, uint32_t domain ) : xc_{ xc }, domain_{ domain }
{
	if ( xc_.altp2mSetDomainState( domain, true ) < 0 )
		throw std::runtime_error( std::string( "[ALTP2M] could not enable altp2m on domain: " ) +
		                          strerror( errno ) );
}

XenAltp2mDomainState::~XenAltp2mDomainState()
{
	switchToView( 0 );

	for ( auto &&view : views_ )
		xc_.altp2mDestroyView( domain_, view );

	xc_.altp2mSetDomainState( domain_, false );
}

int XenAltp2mDomainState::createView( xenmem_access_t default_access, uint16_t &id )
{
	int rc;

	if ( ( rc = xc_.altp2mCreateView( domain_, default_access, &id ) ) >= 0 )
		views_.insert( id );

	return rc;
}

int XenAltp2mDomainState::switchToView( uint16_t view_id )
{
	int rc;

	if ( view_id == current_view_ )
		return 0;

	if ( view_id && views_.find( view_id ) == views_.end() )
		return -EINVAL;

	if ( ( rc = xc_.altp2mSwitchToView( domain_, view_id ) ) >= 0 )
		current_view_ = view_id;

	return rc;
}

} // namespace bdvmi
