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

#ifndef __BDVMIVERSION_H_INCLUDED__
#define __BDVMIVERSION_H_INCLUDED__

#include <iostream>

namespace bdvmi {

class Version {
public:
	Version( int verMajor = 0, int verMinor = 0, const std::string &verExtra = "" );

	int         getMajor() const;
	int         getMinor() const;
	std::string getExtra() const;

	friend std::ostream &operator<<( std::ostream &, const Version & );
	friend int cmp( const Version &l, const Version &r );

private:
	int         verMajor_;
	int         verMinor_;
	std::string verExtra_;
};

inline bool operator==( const Version &l, const Version &r )
{
	return cmp( l, r ) == 0;
}

inline bool operator!=( const Version &l, const Version &r )
{
	return cmp( l, r ) != 0;
}

inline bool operator<( const Version &l, const Version &r )
{
	return cmp( l, r ) < 0;
}

inline bool operator>( const Version &l, const Version &r )
{
	return cmp( l, r ) > 0;
}

inline bool operator<=( const Version &l, const Version &r )
{
	return cmp( l, r ) <= 0;
}

inline bool operator>=( const Version &l, const Version &r )
{
	return cmp( l, r ) >= 0;
}

} // namespace bdvmi

#endif // __BDVMIVERSION_H_INCLUDED__
