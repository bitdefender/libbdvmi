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

#include "bdvmi/version.h"

namespace bdvmi {

Version::Version( int verMajor, int verMinor, const std::string &verExtra )
    : verMajor_{ verMajor }
    , verMinor_{ verMinor }
    , verExtra_{ verExtra }
{
}

int Version::getMajor() const
{
	return verMajor_;
}

int Version::getMinor() const
{
	return verMinor_;
}

std::string Version::getExtra() const
{
	return verExtra_;
}

int cmp( const Version &l, const Version &r )
{
	int majorDiff = l.verMajor_ - r.verMajor_;
	return ( majorDiff ) ? majorDiff : ( l.verMinor_ - r.verMinor_ );
}

std::ostream &operator<<( std::ostream &str, const Version &obj )
{
	str << std::dec << obj.verMajor_ << "." << obj.verMinor_ << obj.verExtra_;
	return str;
}

} // namespace bdvmi
