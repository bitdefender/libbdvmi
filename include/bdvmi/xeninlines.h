// Copyright (c) 2015 Bitdefender SRL, All rights reserved.
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

#ifndef __BDVMIXENINLINES_H_INCLUDED__
#define __BDVMIXENINLINES_H_INCLUDED__

namespace bdvmi {

inline void *xs_read_timeout( struct xs_handle *h, xs_transaction_t t, const char *path, unsigned int *len,
                              unsigned int timeout )
{
	struct timespec tim, tim2;
	const long nanosec_sleep = 1000000;
	float seconds_timeout = timeout;
	void *ret = NULL;
	int saved_errno;

	do {
		tim.tv_sec = 0;
		tim.tv_nsec = nanosec_sleep;

		ret = xs_read( h, t, path, len );

		if ( ret || errno != EPERM )
			break;

		saved_errno = errno;

		if ( nanosleep( &tim, &tim2 ) != 0 && errno == EINTR )
			tim.tv_nsec -= tim2.tv_nsec;

		errno = saved_errno;
		seconds_timeout -= 1.0e-9 * tim.tv_nsec;

	} while ( seconds_timeout > 0 );

	return ret;
}

} // namespace bdvmi

#endif // __BDVMIXENINLINES_H_INCLUDED__

