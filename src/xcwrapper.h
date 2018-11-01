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

#ifndef __BDVMIXCWRAPPER_H_INCLUDED__
#define __BDVMIXCWRAPPER_H_INCLUDED__

#ifndef __XEN_TOOLS__
#define __XEN_TOOLS__ 1
#endif

#include <functional>
#include <memory>

extern "C" {
#include <xen/domctl.h>
#include <xen/memory.h>
#include <xen/version.h>
}

#include "bdvmi/driver.h"
#include "bdvmi/version.h"
#include "utils.h"

/*
 *  DEFINITIONS FOR CPU BARRIERS
 */
#ifndef xen_barrier
#define xen_barrier() asm volatile( "" : : : "memory" )

#if defined( __i386__ )
#define xen_mb() asm volatile( "lock; addl $0,0(%%esp)" : : : "memory" )
#define xen_rmb() xen_barrier()
#define xen_wmb() xen_barrier()
#elif defined( __x86_64__ )
#define xen_mb() asm volatile( "mfence" : : : "memory" )
#define xen_rmb() xen_barrier()
#define xen_wmb() xen_barrier()
#else
#error "Define barriers"
#endif
#endif // xen_barrier

struct xc_interface_core;
using xc_interface = struct xc_interface_core;

#if __XEN_LATEST_INTERFACE_VERSION__ == 0x00040600
using xc_evtchn = struct xc_interface_core;
#else
struct xenevtchn_handle;
using xc_evtchn = struct xenevtchn_handle;
#endif

namespace bdvmi {

struct XenDomainInfo {
	XenDomainInfo() : domid( 0 ), hvm( false ), dying( false ), shutdown( false ), max_vcpu_id( 0 )
	{
	}

	uint32_t     domid;
	bool         hvm;
	bool         dying;
	bool         shutdown;
	unsigned int max_vcpu_id;
};

struct XenDomctlInfo {
	XenDomctlInfo() : pvh( false )
	{
	}

	bool pvh;
};

struct Registers;

//
// The simplest way to add a new dynamically-loaded function to libbdvmi:
//
// Say the libxc function's name is int xc_do_stuff(xc_interface *, uint32_t ), then:
//
// 1. DECLARE_BDVMI_FUNCTION( do_stuff, int( uint32_t ) ) below.
// _Don't_ add the xc_interface * param.
//
// 2. Add a member in class XC:
// NCFunction<bdvmi_do_stuff_fn_t> doStuff; // NC stands for non-copyable
//
// 3. Add a member in class XCFactory:
// std::function<xc_do_stuff_fn_t> doStuff;
//
// 4. Add:
// doStuff = LOOKUP_XC_FUNCTION_REQUIRED( do_stuff );
// to XCFactory::XCFactory()'s body (follow the other similar code).
// If it's OK to _not_ find the function in the library, say LOOKUP_XC_FUNCTION_OPTIONAL() instead.
// For required functions, not finding them results in an exception being thrown.
//
// 5. Add doStuff( std::bind( XCFactory::instance().doStuff, xci_.get(), _1 ) ) to class XC's constructor's
// initializer list. This will bind the internal libxc handle to the first parameter, and _1 is a
// placeholder for the uint32_t parameter. If you have several parameters in the original function after
// xc_interface *, they become _1, _2, _3, and so on here.
//

#define DECLARE_BDVMI_FUNCTION( NAME, TYPE )                                                                              \
	using bdvmi_##NAME##_fn_t            = TYPE;                                                                   \
	using xc_##NAME##_fn_t               = PrependArg<xc_interface *, bdvmi_##NAME##_fn_t>::type;                  \
	constexpr char xc_##NAME##_fn_name[] = "xc_" #NAME;

DECLARE_BDVMI_FUNCTION( domain_pause, int( uint32_t ) )
DECLARE_BDVMI_FUNCTION( domain_unpause, int( uint32_t ) )
DECLARE_BDVMI_FUNCTION( domain_shutdown, int( uint32_t, int ) )
DECLARE_BDVMI_FUNCTION( domain_getinfo, int( uint32_t, XenDomainInfo & ) )
DECLARE_BDVMI_FUNCTION( domain_getinfolist, int( uint32_t, XenDomctlInfo & ) )
DECLARE_BDVMI_FUNCTION( domain_maximum_gpfn, int( uint32_t, xen_pfn_t * ) )
DECLARE_BDVMI_FUNCTION( domain_debug_control, int( uint32_t, uint32_t, uint32_t ) )
DECLARE_BDVMI_FUNCTION( domain_get_tsc_info, int( uint32_t, uint32_t *, uint64_t *, uint32_t *, uint32_t * ) )
DECLARE_BDVMI_FUNCTION( domain_set_access_required, int( uint32_t, unsigned int ) )
DECLARE_BDVMI_FUNCTION( domain_hvm_getcontext, int( uint32_t, uint8_t *, uint32_t ) )
DECLARE_BDVMI_FUNCTION( domain_hvm_getcontext_partial, int( uint32_t, uint16_t, uint16_t, void *, uint32_t ) )
DECLARE_BDVMI_FUNCTION( domain_set_cores_per_socket, int( uint32_t, uint32_t ) )
DECLARE_BDVMI_FUNCTION( set_mem_access, int( uint32_t, const Driver::MemAccessMap & ) )
DECLARE_BDVMI_FUNCTION( altp2m_set_mem_access, int( uint32_t, uint16_t, const Driver::MemAccessMap & ) )
DECLARE_BDVMI_FUNCTION( altp2m_set_domain_state, int( uint32_t, bool ) )
DECLARE_BDVMI_FUNCTION( altp2m_create_view, int( uint32_t, xenmem_access_t, uint16_t * ) )
DECLARE_BDVMI_FUNCTION( altp2m_destroy_view, int( uint32_t, uint16_t ) )
DECLARE_BDVMI_FUNCTION( altp2m_switch_to_view, int( uint32_t, uint16_t ) )
DECLARE_BDVMI_FUNCTION( map_foreign_range, void *( uint32_t, int, int, unsigned long ) )
DECLARE_BDVMI_FUNCTION( get_mem_access, int( uint32_t, uint64_t, xenmem_access_t * ) )
DECLARE_BDVMI_FUNCTION( translate_foreign_address, unsigned long( uint32_t, int, unsigned long long ) )
DECLARE_BDVMI_FUNCTION( copy_to_domain_page, int( uint32_t, unsigned long, const char * ) )
DECLARE_BDVMI_FUNCTION( hvm_inject_trap, int( uint32_t, int, uint8_t, uint8_t, uint32_t, uint8_t, uint64_t ) )
DECLARE_BDVMI_FUNCTION( vcpu_set_registers, int( uint32_t, unsigned short, const Registers &, bool ) )
DECLARE_BDVMI_FUNCTION( monitor_enable, void *( uint32_t, uint32_t * ) )
DECLARE_BDVMI_FUNCTION( monitor_disable, int( uint32_t ) )
DECLARE_BDVMI_FUNCTION( monitor_singlestep, int( uint32_t, bool ) )
DECLARE_BDVMI_FUNCTION( monitor_software_breakpoint, int( uint32_t, bool ) )
DECLARE_BDVMI_FUNCTION( monitor_emulate_each_rep, int( uint32_t, bool ) )
DECLARE_BDVMI_FUNCTION( monitor_mov_to_msr, int( uint32_t, uint32_t, bool, bool ) )
DECLARE_BDVMI_FUNCTION( monitor_guest_request, int( uint32_t, bool, bool, bool ) )
DECLARE_BDVMI_FUNCTION( monitor_write_ctrlreg, int( uint32_t, uint16_t, bool, bool, uint64_t, bool ) )

using bdvmi_evtchn_open_fn_t                   = xc_evtchn *( void );
using bdvmi_evtchn_close_fn_t                  = int( xc_evtchn * );
using bdvmi_evtchn_fd_fn_t                     = int( xc_evtchn * );
using bdvmi_evtchn_pending_fn_t                = int( xc_evtchn * );
using bdvmi_evtchn_bind_interdomain_fn_t       = int( xc_evtchn *, uint32_t, uint32_t );
using bdvmi_evtchn_unbind_fn_t                 = int( xc_evtchn *, uint32_t );
using bdvmi_evtchn_unmask_fn_t                 = int( xc_evtchn *, uint32_t );
using bdvmi_evtchn_notify_fn_t                 = int( xc_evtchn *, uint32_t );

class XC {
public:
	XC();

	static const unsigned long pageSize;
	static const unsigned long pageShift;
	static const unsigned long pageMask;
	static const unsigned long invalidMfn;
	static const uint8_t       shutdownPoweroff;

	static xenmem_access_t xenMemAccess( uint8_t bdvmiBitmask );

private:
	std::unique_ptr<xc_interface, int ( * )( xc_interface * )> xci_;

public:
	const Version     version;
	const bool        isXenServer{ false };
	const std::string caps;
	const std::string uuid;

	/*
	 * Domain Management functions
	 */
	NCFunction<bdvmi_domain_pause_fn_t>                  domainPause;
	NCFunction<bdvmi_domain_unpause_fn_t>                domainUnpause;
	NCFunction<bdvmi_domain_shutdown_fn_t>               domainShutdown;
	NCFunction<bdvmi_domain_getinfo_fn_t>                domainGetInfo;
	NCFunction<bdvmi_domain_getinfolist_fn_t>            domainGetInfoList;
	NCFunction<bdvmi_domain_maximum_gpfn_fn_t>           domainMaximumGpfn;
	NCFunction<bdvmi_domain_debug_control_fn_t>          domainDebugControl;
	NCFunction<bdvmi_domain_get_tsc_info_fn_t>           domainGetTscInfo;
	NCFunction<bdvmi_domain_set_access_required_fn_t>    domainSetAccessRequired;
	NCFunction<bdvmi_domain_hvm_getcontext_fn_t>         domainHvmGetContext;
	NCFunction<bdvmi_domain_hvm_getcontext_partial_fn_t> domainHvmGetContextPartial;
	NCFunction<bdvmi_set_mem_access_fn_t>                setMemAccess;

	/*
	 * ALTP2M support
	 */
	NCFunction<bdvmi_altp2m_set_mem_access_fn_t>   altp2mSetMemAccess;
	NCFunction<bdvmi_altp2m_set_domain_state_fn_t> altp2mSetDomainState;
	NCFunction<bdvmi_altp2m_create_view_fn_t>      altp2mCreateView;
	NCFunction<bdvmi_altp2m_destroy_view_fn_t>     altp2mDestroyView;
	NCFunction<bdvmi_altp2m_switch_to_view_fn_t>   altp2mSwitchToView;

	NCFunction<bdvmi_map_foreign_range_fn_t>         mapForeignRange;
	NCFunction<bdvmi_get_mem_access_fn_t>            getMemAccess;
	NCFunction<bdvmi_translate_foreign_address_fn_t> translateForeignAddress;
	NCFunction<bdvmi_copy_to_domain_page_fn_t>       copyToDomainPage;
	NCFunction<bdvmi_hvm_inject_trap_fn_t>           hvmInjectTrap;
	NCFunction<bdvmi_vcpu_set_registers_fn_t>        vcpuSetRegisters;

	/*
	 * Monitor functions
	 */
	NCFunction<bdvmi_monitor_enable_fn_t>              monitorEnable;
	NCFunction<bdvmi_monitor_disable_fn_t>             monitorDisable;
	NCFunction<bdvmi_monitor_singlestep_fn_t>          monitorSinglestep;
	NCFunction<bdvmi_monitor_software_breakpoint_fn_t> monitorSoftwareBreakpoint;
	NCFunction<bdvmi_monitor_emulate_each_rep_fn_t>    monitorEmulateEachRep;
	NCFunction<bdvmi_monitor_mov_to_msr_fn_t>          monitorMovToMsr;
	NCFunction<bdvmi_monitor_guest_request_fn_t>       monitorGuestRequest;
	NCFunction<bdvmi_monitor_write_ctrlreg_fn_t>       monitorWriteCtrlreg;

	/*
	 * XenServer-specific functions
	 */
	NCFunction<bdvmi_domain_set_cores_per_socket_fn_t> domainSetCoresPerSocket;

	/*
	 * Event Channel functions
	 */
	std::function<bdvmi_evtchn_open_fn_t>             evtchnOpen;
	std::function<bdvmi_evtchn_close_fn_t>            evtchnClose;
	std::function<bdvmi_evtchn_fd_fn_t>               evtchnFd;
	std::function<bdvmi_evtchn_pending_fn_t>          evtchnPending;
	std::function<bdvmi_evtchn_bind_interdomain_fn_t> evtchnBindInterdomain;
	std::function<bdvmi_evtchn_unbind_fn_t>           evtchnUnbind;
	std::function<bdvmi_evtchn_unmask_fn_t>           evtchnUnmask;
	std::function<bdvmi_evtchn_notify_fn_t>           evtchnNotify;
};

} // namespace bdvmi

#endif // __BDVMIXCWRAPPER_H_INCLUDED__
