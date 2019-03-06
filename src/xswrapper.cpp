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

#include "dynamiclibfactory.h"
#include "utils.h"
#include "xswrapper.h"

extern "C" {
#include <xenstore.h>
}

namespace bdvmi {

using xs_open_fn_t  = struct xs_handle *( unsigned long );
using xs_close_fn_t = void( struct xs_handle * );

using xs_read_timeout_fn_t         = PrependArg<xs_handle *, bdvmi_xs_read_timeout_fn_t>::type;
using xs_write_fn_t                = PrependArg<xs_handle *, bdvmi_xs_write_fn_t>::type;
using xs_directory_fn_t            = PrependArg<xs_handle *, bdvmi_xs_directory_fn_t>::type;
using xs_watch_fn_t                = PrependArg<xs_handle *, bdvmi_xs_watch_fn_t>::type;
using xs_unwatch_fn_t              = PrependArg<xs_handle *, bdvmi_xs_unwatch_fn_t>::type;
using xs_rm_fn_t                   = PrependArg<xs_handle *, bdvmi_xs_rm_fn_t>::type;
using xs_fileno_fn_t               = PrependArg<xs_handle *, bdvmi_xs_fileno_fn_t>::type;
using xs_read_watch_fn_t           = PrependArg<xs_handle *, bdvmi_xs_read_watch_fn_t>::type;
using xs_transaction_start_fn_t    = PrependArg<xs_handle *, bdvmi_xs_transaction_start_fn_t>::type;
using xs_transaction_end_fn_t      = PrependArg<xs_handle *, bdvmi_xs_transaction_end_fn_t>::type;
using xs_is_domain_introduced_fn_t = PrependArg<xs_handle *, bdvmi_xs_is_domain_introduced_fn_t>::type;

constexpr char xs_open_fn_name[]                 = "xs_open";
constexpr char xs_close_fn_name[]                = "xs_close";
constexpr char xs_read_fn_name[]                 = "xs_read";
constexpr char xs_write_fn_name[]                = "xs_write";
constexpr char xs_directory_fn_name[]            = "xs_directory";
constexpr char xs_watch_fn_name[]                = "xs_watch";
constexpr char xs_unwatch_fn_name[]              = "xs_unwatch";
constexpr char xs_rm_fn_name[]                   = "xs_rm";
constexpr char xs_fileno_fn_name[]               = "xs_fileno";
constexpr char xs_read_watch_fn_name[]           = "xs_read_watch";
constexpr char xs_transaction_start_fn_name[]    = "xs_transaction_start";
constexpr char xs_transaction_end_fn_name[]      = "xs_transaction_end";
constexpr char xs_is_domain_introduced_fn_name[] = "xs_is_domain_introduced";

constexpr char xs_read_timeout_fn_name[] = "xs_read_timeout";

struct XSFactory;

template <typename T, const char name[]> struct XSFactoryImpl {
	static std::function<T> lookup( const XSFactory *p, bool required );
};

class XSFactory {
public:
	static XSFactory &instance();

	DynamicLibFactory lib_;
	std::unique_ptr<xs_handle, void ( * )( struct xs_handle * )> createHandle() const;

	template <typename T, const char *name> std::function<T> lookup( bool required = true ) const
	{
		return XSFactoryImpl<T, name>::lookup( this, required );
	}

	std::function<xs_read_timeout_fn_t>         readTimeout;
	std::function<xs_write_fn_t>                write;
	std::function<xs_directory_fn_t>            directory;
	std::function<xs_watch_fn_t>                watch;
	std::function<xs_unwatch_fn_t>              unwatch;
	std::function<xs_rm_fn_t>                   rm;
	std::function<xs_fileno_fn_t>               fileno;
	std::function<xs_read_watch_fn_t>           readWatch;
	std::function<xs_transaction_start_fn_t>    transactionStart;
	std::function<xs_transaction_end_fn_t>      transactionEnd;
	std::function<xs_is_domain_introduced_fn_t> isDomainIntroduced;

private:
	XSFactory();
};

XSFactory &XSFactory::instance()
{
	static XSFactory instance;
	return instance;
}

XSFactory::XSFactory() : lib_( "libxenstore.so" )
{
	readTimeout        = lookup<xs_read_timeout_fn_t, xs_read_timeout_fn_name>();
	write              = lookup<xs_write_fn_t, xs_write_fn_name>();
	directory          = lookup<xs_directory_fn_t, xs_directory_fn_name>();
	watch              = lookup<xs_watch_fn_t, xs_watch_fn_name>();
	unwatch            = lookup<xs_unwatch_fn_t, xs_unwatch_fn_name>();
	rm                 = lookup<xs_rm_fn_t, xs_rm_fn_name>();
	fileno             = lookup<xs_fileno_fn_t, xs_fileno_fn_name>();
	readWatch          = lookup<xs_read_watch_fn_t, xs_read_watch_fn_name>();
	transactionStart   = lookup<xs_transaction_start_fn_t, xs_transaction_start_fn_name>();
	transactionEnd     = lookup<xs_transaction_end_fn_t, xs_transaction_end_fn_name>();
	isDomainIntroduced = lookup<xs_is_domain_introduced_fn_t, xs_is_domain_introduced_fn_name>();
}

std::unique_ptr<xs_handle, void ( * )( struct xs_handle * )> XSFactory::createHandle() const
{
	auto open_fn  = lib_.lookup<xs_open_fn_t, xs_open_fn_name>();
	auto close_fn = lib_.lookup<xs_close_fn_t, xs_close_fn_name>();

	xs_handle *xsh = open_fn( 0 );
	if ( !xsh )
		throw std::runtime_error( "xs_open() failed" );
	return std::unique_ptr<xs_handle, void ( * )( struct xs_handle * )>( xsh, close_fn );
}

template <typename T, const char name[]>
std::function<T> XSFactoryImpl<T, name>::lookup( const XSFactory *p, bool required )
{
	return p->lib_.lookup<T, name>( required );
}

template <> struct XSFactoryImpl<xs_read_timeout_fn_t, xs_read_timeout_fn_name> {
	static std::function<xs_read_timeout_fn_t> lookup( const XSFactory *p, bool )
	{
		using fn_t = void *( struct xs_handle *, xs_transaction_t, const char *, unsigned int * );
		fn_t *fn   = p->lib_.lookup<fn_t, xs_read_fn_name>();
		return [fn]( xs_handle *xsh, xs_transaction_t t, const std::string &path, unsigned int *len,
		             unsigned int timeout ) {
			struct timespec tim, tim2;
			const long      nanosec_sleep   = 1000000;
			float           seconds_timeout = timeout;
			void *          ret             = nullptr;
			int             saved_errno;

			do {
				tim.tv_sec  = 0;
				tim.tv_nsec = nanosec_sleep;

				ret = fn( xsh, t, path.c_str(), len );

				if ( ret || errno != EPERM )
					break;

				saved_errno = errno;

				if ( nanosleep( &tim, &tim2 ) != 0 && errno == EINTR )
					tim.tv_nsec -= tim2.tv_nsec;

				errno = saved_errno;
				seconds_timeout -= 1.0e-9 * tim.tv_nsec;

			} while ( seconds_timeout > 0 );

			return ret;
		};
	}
};

template <> struct XSFactoryImpl<xs_write_fn_t, xs_write_fn_name> {
	static std::function<xs_write_fn_t> lookup( const XSFactory *p, bool )
	{
		using fn_t = bool( struct xs_handle *, xs_transaction_t, const char *, const void *, unsigned int );
		fn_t *fn   = p->lib_.lookup<fn_t, xs_write_fn_name>();
		return [fn]( xs_handle *xsh, xs_transaction_t t, const std::string &path, const void *data,
		             unsigned int len ) { return fn( xsh, t, path.c_str(), data, len ); };
	}
};

template <> struct XSFactoryImpl<xs_directory_fn_t, xs_directory_fn_name> {
	static std::function<xs_directory_fn_t> lookup( const XSFactory *p, bool )
	{
		using fn_t = char **( struct xs_handle *, xs_transaction_t, const char *, unsigned int * );
		fn_t *fn   = p->lib_.lookup<fn_t, xs_directory_fn_name>();
		return [fn]( xs_handle *xsh, xs_transaction_t t, const std::string &path,
		             std::vector<std::string> &dir ) {
			unsigned int       count = 0;
			CUniquePtr<char *> res( fn( xsh, t, path.c_str(), &count ) );

			if ( !res )
				return false;

			dir.reserve( count );
			std::copy( res.get(), res.get() + count, std::back_inserter( dir ) );

			return true;
		};
	}
};

template <> struct XSFactoryImpl<xs_watch_fn_t, xs_watch_fn_name> {
	static std::function<xs_watch_fn_t> lookup( const XSFactory *p, bool )
	{
		using fn_t = bool( struct xs_handle *, const char *, const char * );
		fn_t *fn   = p->lib_.lookup<fn_t, xs_watch_fn_name>();
		return [fn]( xs_handle *xsh, const std::string &path, const std::string &token ) {
			return fn( xsh, path.c_str(), token.c_str() );
		};
	}
};

template <> struct XSFactoryImpl<xs_unwatch_fn_t, xs_unwatch_fn_name> {
	static std::function<xs_unwatch_fn_t> lookup( const XSFactory *p, bool )
	{
		using fn_t = bool( struct xs_handle *, const char *, const char * );
		fn_t *fn   = p->lib_.lookup<fn_t, xs_unwatch_fn_name>();
		return [fn]( xs_handle *xsh, const std::string &path, const std::string &token ) {
			return fn( xsh, path.c_str(), token.c_str() );
		};
	}
};

template <> struct XSFactoryImpl<xs_rm_fn_t, xs_rm_fn_name> {
	static std::function<xs_rm_fn_t> lookup( const XSFactory *p, bool )
	{
		using fn_t = bool( struct xs_handle *, xs_transaction_t, const char * );
		fn_t *fn   = p->lib_.lookup<fn_t, xs_rm_fn_name>();
		return [fn]( xs_handle *xsh, xs_transaction_t t, const std::string &path ) {
			return fn( xsh, t, path.c_str() );
		};
	}
};

template <> struct XSFactoryImpl<xs_read_watch_fn_t, xs_read_watch_fn_name> {
	static std::function<xs_read_watch_fn_t> lookup( const XSFactory *p, bool )
	{
		using fn_t = char **( struct xs_handle *, unsigned int * );
		fn_t *fn   = p->lib_.lookup<fn_t, xs_read_watch_fn_name>();
		return [fn]( xs_handle *xsh, std::vector<std::string> &watch ) {
			unsigned int       num = 0;
			CUniquePtr<char *> res( fn( xsh, &num ) );

			if ( !res )
				return false;

			watch.reserve( num );
			std::copy( res.get(), res.get() + num, std::back_inserter( watch ) );

			return true;
		};
	}
};

const xs_transaction_t XS::xbtNull    = XBT_NULL;
const uint32_t         XS::watchPath  = XS_WATCH_PATH;
const uint32_t         XS::watchToken = XS_WATCH_TOKEN;

using namespace std::placeholders;

XS::XS()
    : xsh_{ XSFactory::instance().createHandle() },
      readTimeout{ std::bind( XSFactory::instance().readTimeout, xsh_.get(), _1, _2, _3, _4 ) },
      write{ std::bind( XSFactory::instance().write, xsh_.get(), _1, _2, _3, _4 ) },
      directory{ std::bind( XSFactory::instance().directory, xsh_.get(), _1, _2, _3 ) },
      watch{ std::bind( XSFactory::instance().watch, xsh_.get(), _1, _2 ) },
      unwatch{ std::bind( XSFactory::instance().unwatch, xsh_.get(), _1, _2 ) },
      rm{ std::bind( XSFactory::instance().rm, xsh_.get(), _1, _2 ) },
      fileno{ std::bind( XSFactory::instance().fileno, xsh_.get() ) },
      readWatch{ std::bind( XSFactory::instance().readWatch, xsh_.get(), _1 ) },
      transactionStart{ std::bind( XSFactory::instance().transactionStart, xsh_.get() ) },
      transactionEnd{ std::bind( XSFactory::instance().transactionEnd, xsh_.get(), _1, _2 ) },
      isDomainIntroduced{ std::bind( XSFactory::instance().isDomainIntroduced, xsh_.get(), _1 ) }
{
}

} // namespace bdvmi
