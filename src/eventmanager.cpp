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

#include "bdvmi/eventmanager.h"

namespace bdvmi {

EventManager::EventManager( sig_atomic_t &sigStop )
    : sigStop_{ sigStop }
{
}

bool EventManager::enableMsrEvents( unsigned int msr, bool &oldValue )
{
	oldValue = ( enabledMsrs_.find( msr ) != enabledMsrs_.end() );

	if ( oldValue )
		return true; // Already enabled

	if ( !enableMsrEventsImpl( msr ) )
		return false;

	enabledMsrs_.insert( msr );

	return true;
}

bool EventManager::disableMsrEvents( unsigned int msr, bool &oldValue )
{
	oldValue = ( enabledMsrs_.find( msr ) != enabledMsrs_.end() );

	if ( !oldValue )
		return true; // Already disabled

	if ( !disableMsrEventsImpl( msr ) )
		return false;

	enabledMsrs_.erase( msr );

	return true;
}

bool EventManager::enableCrEvents( unsigned int cr )
{
	if ( enabledCrs_.find( cr ) != enabledCrs_.end() )
		return true; // Already enabled

	if ( !enableCrEventsImpl( cr ) )
		return false;

	enabledCrs_.insert( cr );

	return true;
}

bool EventManager::disableCrEvents( unsigned int cr )
{
	if ( enabledCrs_.find( cr ) == enabledCrs_.end() )
		return true; // Already disabled

	if ( !disableCrEventsImpl( cr ) )
		return false;

	enabledCrs_.erase( cr );

	return true;
}

bool EventManager::enableXSETBVEvents()
{
	if ( xsetbvEnabled_ )
		return true;

	xsetbvEnabled_ = enableXSETBVEventsImpl();

	return xsetbvEnabled_;
}

bool EventManager::disableXSETBVEvents()
{
	if ( !xsetbvEnabled_ )
		return true;

	xsetbvEnabled_ = !disableXSETBVEventsImpl();

	return !xsetbvEnabled_;
}

bool EventManager::enableBreakpointEvents()
{
	if ( breakpointEnabled_ )
		return true;

	breakpointEnabled_ = enableBreakpointEventsImpl();

	return breakpointEnabled_;
}

bool EventManager::disableBreakpointEvents()
{
	if ( !breakpointEnabled_ )
		return true;

	breakpointEnabled_ = !disableBreakpointEventsImpl();

	return !breakpointEnabled_;
}

bool EventManager::enableVMCALLEvents()
{
	if ( vmcallEnabled_ )
		return true;

	vmcallEnabled_ = enableVMCALLEventsImpl();

	return vmcallEnabled_;
}

bool EventManager::disableVMCALLEvents()
{
	if ( !vmcallEnabled_ )
		return true;

	vmcallEnabled_ = !disableVMCALLEventsImpl();

	return !vmcallEnabled_;
}

bool EventManager::enableDescriptorEvents()
{
	if ( descriptorEnabled_ )
		return true;

	descriptorEnabled_ = enableDescriptorEventsImpl();

	return descriptorEnabled_;
}

bool EventManager::disableDescriptorEvents()
{
	if ( !descriptorEnabled_ )
		return true;

	descriptorEnabled_ = !disableDescriptorEventsImpl();

	return !descriptorEnabled_;
}

} // namespace bdvmi
