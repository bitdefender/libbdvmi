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

#ifndef __BDVMIXENDOMAINWATCHER_H_INCLUDED__
#define __BDVMIXENDOMAINWATCHER_H_INCLUDED__

#include "bdvmi/domainwatcher.h"
#include "xcwrapper.h"
#include "xswrapper.h"
#include <map>

namespace bdvmi {

// Forward declaration, minimize compile time
class LogHelper;

class XenDomainWatcher : public DomainWatcher {

public:
	XenDomainWatcher( sig_atomic_t &sigStop, LogHelper *logHelper );

	virtual ~XenDomainWatcher();

public:
	bool accessGranted() override;

	bool ownUuid( std::string &uuid ) const override
	{
		uuid = ownUuid_;
		return true;
	}

private:
	// No copying allowed
	XenDomainWatcher( const XenDomainWatcher & );

	// No copying allowed
	XenDomainWatcher &operator=( const XenDomainWatcher & );

private:
	bool waitForDomainsOrTimeout( std::list<DomainInfo> &domains, int ms ) override;

	bool isSelf( domid_t domain );

	void initControlKey( domid_t domain );

	bool getNewDomains( std::list<DomainInfo> &domains );

	std::string uuid( domid_t domain ) const;

private:
	mutable XS        xs_;
	mutable XC        xc_;
	std::string       ownUuid_;
	std::string       controlXenStorePath_;
	const std::string introduceToken_{ "introduce" };
	const std::string releaseToken_{ "release" };
	const std::string controlToken_{ "control" };
	const std::string postResumeToken_{ "post-resume" };
	std::map<domid_t, std::string> domIds_;
	LogHelper *       logHelper_;
	bool              firstUninitWrite_{ false };
	bool              keyCreated_{ false };
	std::set<domid_t> preResumeDomains_;
};

} // namespace bdvmi

#endif // __BDVMIXENDOMAINWATCHER_H_INCLUDED__
