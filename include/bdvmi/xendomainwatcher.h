// Copyright (c) 2015-2016 Bitdefender SRL, All rights reserved.
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

#ifndef __BDVMIXENDOMAINWATCHER_H_INCLUDED__
#define __BDVMIXENDOMAINWATCHER_H_INCLUDED__

#include "domainwatcher.h"
#include "exception.h"
#include <set>

extern "C" {
#include <xenctrl.h>
#include <xen/xen-compat.h>
#if __XEN_LATEST_INTERFACE_VERSION__ < 0x00040600
#error unsupported Xen version
#endif

#include <xenstore.h>
}

namespace bdvmi {

// Forward declaration, minimize compile time
class LogHelper;

class XenDomainWatcher : public DomainWatcher {

public:
	XenDomainWatcher( LogHelper *logHelper );

	virtual ~XenDomainWatcher();

private:
	// No copying allowed (class has xsh_ and xci_)
	XenDomainWatcher( const XenDomainWatcher & );

	// No copying allowed (class has xsh_ and xci_)
	XenDomainWatcher &operator=( const XenDomainWatcher );

private:
	virtual bool waitForDomainsOrTimeout( std::list<DomainInfo> &domains, int ms );

private:
	xs_handle *xsh_;
	xc_interface *xci_;
	const std::string introduceToken_;
	const std::string releaseToken_;
	std::set<domid_t> domIds_;
	LogHelper *logHelper_;
};

} // namespace bdvmi

#endif // __BDVMIXENDOMAINWATCHER_H_INCLUDED__
