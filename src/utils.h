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

#ifndef __BDVMIUTILS_H_INCLUDED__
#define __BDVMIUTILS_H_INCLUDED__

#include <functional>
#include <memory>

namespace bdvmi {

class NonCopyable {
protected:
	NonCopyable() = default;

public:
	NonCopyable( const NonCopyable & ) = delete;
	NonCopyable &operator=( const NonCopyable & ) = delete;
};

template <class T> class NCFunction;

template <class R, class... Args>
class NCFunction<R( Args... )> : private NonCopyable, public std::function<R( Args... )> {
public:
	NCFunction() = default;

	explicit NCFunction( const std::function<R( Args... )> &&f ) : std::function<R( Args... )>( f )
	{
	}

	NCFunction &operator=( std::function<R( Args... )> &&f )
	{
		std::function<R( Args... )>::operator=( std::move( f ) );
		return *this;
	}
};

template <typename A, typename F> struct PrependArg;

template <typename R, typename A, typename... Args> struct PrependArg<A, R( Args... )> {
	using type = R( A, Args... );
};

using CDeleterType                         = void ( * )( void * );
template <typename T> using CUniquePtrType = std::unique_ptr<T, CDeleterType>;

template <typename T> class CUniquePtr : public CUniquePtrType<T> {
public:
	CUniquePtr( void *ptr = nullptr )
	    : CUniquePtrType<T>( static_cast<T *>( ptr ), []( void *ptr ) { ::free( ptr ); } )
	{
	}
};

} // namespace bdvmi
#endif /* __BDVMIUTILS_H_INCLUDED__ */
