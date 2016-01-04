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

#ifndef __BDVMIEXCEPTION_H_INCLUDED__
#define __BDVMIEXCEPTION_H_INCLUDED__

#include <string>
#include <exception>

namespace bdvmi {

class Exception : public std::exception {

public:
	enum ErrorCode { GENERIC_ERROR, NOT_HVM };

public:
	Exception( const std::string &reason = "", ErrorCode ec = GENERIC_ERROR );
	virtual ~Exception() throw();

public:
	virtual const char *what() const throw()
	{
		return reason_.c_str();
	}

	ErrorCode errorCode() const throw()
	{
		return ec_;
	}

	/*
	   Should compile the code with -rdynamic for best results. See:
	   http://www.ibm.com/developerworks/linux/library/l-cppexcep/index.html
	*/
	virtual const char *backtrace() const throw()
	{
		return backtrace_.c_str();
	}

private:
	void initBacktrace();

private:
	std::string reason_;
	std::string backtrace_;
	ErrorCode ec_;
};

} // namespace bdvmi

#endif // __BDVMIDRIVER_H_INCLUDED__
