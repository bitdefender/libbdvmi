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

#ifndef __BDVMIXSWRAPPER_H_INCLUDED__
#define __BDVMIXSWRAPPER_H_INCLUDED__

#include <string>
#include <vector>
#include <functional>
#include <memory>

#include "utils.h"

struct xs_handle;
using xs_transaction_t = uint32_t;

namespace bdvmi {

using bdvmi_xs_read_timeout_fn_t      = void *( xs_transaction_t, const std::string &, unsigned int *, unsigned int );
using bdvmi_xs_write_fn_t             = bool( xs_transaction_t, const std::string &, const void *, unsigned int );
using bdvmi_xs_directory_fn_t         = bool( xs_transaction_t, const std::string &, std::vector<std::string> & );
using bdvmi_xs_watch_fn_t             = bool( const std::string &, const std::string & );
using bdvmi_xs_unwatch_fn_t           = bool( const std::string &, const std::string & );
using bdvmi_xs_rm_fn_t                = bool( xs_transaction_t, const std::string & );
using bdvmi_xs_fileno_fn_t            = int();
using bdvmi_xs_read_watch_fn_t        = bool( std::vector<std::string> & );
using bdvmi_xs_transaction_start_fn_t = xs_transaction_t();
using bdvmi_xs_transaction_end_fn_t   = bool( xs_transaction_t, bool );
using bdvmi_xs_is_domain_introduced_fn_t = bool( unsigned int );

class XS {
public:
	XS();

	static const xs_transaction_t xbtNull;
	static const uint32_t         watchPath;
	static const uint32_t         watchToken;

private:
	std::unique_ptr<xs_handle, void ( * )( struct xs_handle * )> xsh_;

public:
	NCFunction<bdvmi_xs_read_timeout_fn_t>         readTimeout;
	NCFunction<bdvmi_xs_write_fn_t>                write;
	NCFunction<bdvmi_xs_directory_fn_t>            directory;
	NCFunction<bdvmi_xs_watch_fn_t>                watch;
	NCFunction<bdvmi_xs_unwatch_fn_t>              unwatch;
	NCFunction<bdvmi_xs_rm_fn_t>                   rm;
	NCFunction<bdvmi_xs_fileno_fn_t>               fileno;
	NCFunction<bdvmi_xs_read_watch_fn_t>           readWatch;
	NCFunction<bdvmi_xs_transaction_start_fn_t>    transactionStart;
	NCFunction<bdvmi_xs_transaction_end_fn_t>      transactionEnd;
	NCFunction<bdvmi_xs_is_domain_introduced_fn_t> isDomainIntroduced;
};

} // namespace bdvmi

#endif // __BDVMIXSWRAPPER_H_INCLUDED__
