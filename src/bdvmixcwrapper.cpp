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

#include "bdvmi/driver.h"
#include "bdvmi/statscollector.h"

#include <iomanip>
#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include <type_traits>
#include <vector>

extern "C" {
#include <xenctrl.h>
#include <xen/xen.h>
#define private rprivate /* private is a C++ keyword */
#include <xen/vm_event.h>
#undef private
}

#include "dynamiclibfactory.h"
#include "xcwrapper.h"
#include "xswrapper.h"

namespace bdvmi {

#define LOOKUP_XC_FUNCTION_REQUIRED( NAME ) lookup<xc_##NAME##_fn_t, xc_##NAME##_fn_name>( true )
#define LOOKUP_XC_FUNCTION_OPTIONAL( NAME ) lookup<xc_##NAME##_fn_t, xc_##NAME##_fn_name>( false )

#define LOOKUP_BDVMI_FUNCTION_REQUIRED( NAME ) lookup<bdvmi_##NAME##_fn_t, xc_##NAME##_fn_name>( true )
#define LOOKUP_BDVMI_FUNCTION_OPTIONAL( NAME ) lookup<bdvmi_##NAME##_fn_t, xc_##NAME##_fn_name>( false )

struct xen_arch_domainconfig_extension {
#define _EXT_XEN_X86_EMU_LAPIC 0
#define EXT_XEN_X86_EMU_LAPIC ( 1U << _EXT_XEN_X86_EMU_LAPIC )
	uint32_t emulation_flags;
};

struct xen_domctl_getdomaininfo_extended {
	domid_t                                domain; /* Also echoed in domctl.domain */
	uint32_t                               flags;  /* XEN_DOMINF_* */
	uint64_aligned_t                       tot_pages;
	uint64_aligned_t                       max_pages;
	uint64_aligned_t                       outstanding_pages;
	uint64_aligned_t                       shr_pages;
	uint64_aligned_t                       paged_pages;
	uint64_aligned_t                       shared_info_frame; /* GMFN of shared_info struct */
	uint64_aligned_t                       cpu_time;
	uint32_t                               nr_online_vcpus; /* Number of VCPUs currently online. */
	uint32_t                               max_vcpu_id;     /* Maximum VCPUID in use by this domain. */
	uint32_t                               ssidref;
	xen_domain_handle_t                    handle;
	uint32_t                               cpupool;
	struct xen_arch_domainconfig_extension arch_config; /* HOTFIX member (NEW). */
};

union xen_domctl_getdomaininfo_extended_safe {
	xen_domctl_getdomaininfo_extended extended;
	xen_domctl_getdomaininfo          standard;
};

using xc_interface_open_fn_t  = xc_interface *( xentoollog_logger *, xentoollog_logger *, unsigned );
using xc_interface_close_fn_t = int( xc_interface * );
using xc_version_fn_t         = int( xc_interface *, int, void * );

constexpr char xc_interface_open_fn_name[]                = "xc_interface_open";
constexpr char xc_interface_close_fn_name[]               = "xc_interface_close";
constexpr char xc_version_fn_name[]                       = "xc_version";
constexpr char xc_set_mem_access_multi_fn_name[]          = "xc_set_mem_access_multi";
constexpr char xc_altp2m_set_mem_access_multi_fn_name[]   = "xc_altp2m_set_mem_access_multi";
constexpr char xc_evtchn_open_fn_name[]                   = "xc_evtchn_open";
constexpr char xc_evtchn_close_fn_name[]                  = "xc_evtchn_close";
constexpr char xc_evtchn_fd_fn_name[]                     = "xc_evtchn_fd";
constexpr char xc_evtchn_pending_fn_name[]                = "xc_evtchn_pending";
constexpr char xc_evtchn_bind_interdomain_fn_name[]       = "xc_evtchn_bind_interdomain";
constexpr char xc_evtchn_unbind_fn_name[]                 = "xc_evtchn_unbind";
constexpr char xc_evtchn_unmask_fn_name[]                 = "xc_evtchn_unmask";
constexpr char xc_evtchn_notify_fn_name[]                 = "xc_evtchn_notify";
constexpr char xc_vcpu_getcontext_fn_name[]               = "xc_vcpu_getcontext";
constexpr char xc_vcpu_setcontext_fn_name[]               = "xc_vcpu_setcontext";

struct XCFactory;

template <typename T, const char name[]> struct XCFactoryImpl {
	static std::function<T> lookup( const XCFactory *p, bool required );
};

class XCFactory {
public:
	static XCFactory &instance();
	static Version    getVersion();

	Version           version;
	DynamicLibFactory lib_;

	std::unique_ptr<xc_interface, int ( * )( xc_interface * )> createInterface() const;

	template <typename T, const char *name> std::function<T> lookup( bool required = true ) const
	{
		return XCFactoryImpl<T, name>::lookup( this, required );
	}

	bool        isXenServer;
	std::string caps;
	std::string uuid;

	std::function<xc_domain_pause_fn_t>                  domainPause;
	std::function<xc_domain_unpause_fn_t>                domainUnpause;
	std::function<xc_domain_shutdown_fn_t>               domainShutdown;
	std::function<xc_domain_getinfo_fn_t>                domainGetInfo;
	std::function<xc_domain_getinfolist_fn_t>            domainGetInfoList;
	std::function<xc_domain_maximum_gpfn_fn_t>           domainMaximumGpfn;
	std::function<xc_domain_debug_control_fn_t>          domainDebugControl;
	std::function<xc_domain_get_tsc_info_fn_t>           domainGetTscInfo;
	std::function<xc_domain_set_access_required_fn_t>    domainSetAccessRequired;
	std::function<xc_domain_hvm_getcontext_fn_t>         domainHvmGetContext;
	std::function<xc_domain_hvm_getcontext_partial_fn_t> domainHvmGetContextPartial;
	std::function<xc_domain_set_cores_per_socket_fn_t>   domainSetCoresPerSocket;
	std::function<xc_set_mem_access_fn_t>                setMemAccess;
	std::function<xc_altp2m_set_mem_access_fn_t>         altp2mSetMemAccess;
	std::function<xc_altp2m_set_domain_state_fn_t>       altp2mSetDomainState;
	std::function<xc_altp2m_create_view_fn_t>            altp2mCreateView;
	std::function<xc_altp2m_destroy_view_fn_t>           altp2mDestroyView;
	std::function<xc_altp2m_switch_to_view_fn_t>         altp2mSwitchToView;
	std::function<xc_map_foreign_range_fn_t>             mapForeignRange;
	std::function<xc_get_mem_access_fn_t>                getMemAccess;
	std::function<xc_translate_foreign_address_fn_t>     translateForeignAddress;
	std::function<xc_copy_to_domain_page_fn_t>           copyToDomainPage;
	std::function<xc_hvm_inject_trap_fn_t>               hvmInjectTrap;
	std::function<xc_vcpu_set_registers_fn_t>            vcpuSetRegisters;
	std::function<xc_monitor_enable_fn_t>                monitorEnable;
	std::function<xc_monitor_disable_fn_t>               monitorDisable;
	std::function<xc_monitor_singlestep_fn_t>            monitorSinglestep;
	std::function<xc_monitor_software_breakpoint_fn_t>   monitorSoftwareBreakpoint;
	std::function<xc_monitor_emulate_each_rep_fn_t>      monitorEmulateEachRep;
	std::function<xc_monitor_mov_to_msr_fn_t>            monitorMovToMsr;
	std::function<xc_monitor_guest_request_fn_t>         monitorGuestRequest;
	std::function<xc_monitor_write_ctrlreg_fn_t>         monitorWriteCtrlreg;

	std::function<bdvmi_evtchn_open_fn_t>             evtchnOpen;
	std::function<bdvmi_evtchn_close_fn_t>            evtchnClose;
	std::function<bdvmi_evtchn_fd_fn_t>               evtchnFd;
	std::function<bdvmi_evtchn_pending_fn_t>          evtchnPending;
	std::function<bdvmi_evtchn_bind_interdomain_fn_t> evtchnBindInterdomain;
	std::function<bdvmi_evtchn_unbind_fn_t>           evtchnUnbind;
	std::function<bdvmi_evtchn_unmask_fn_t>           evtchnUnmask;
	std::function<bdvmi_evtchn_notify_fn_t>           evtchnNotify;

private:
	XCFactory();
};

XCFactory &XCFactory::instance()
{
	static XCFactory instance;
	return instance;
}

Version XCFactory::getVersion()
{
	int         verMajor, verMinor;
	std::string verExtra;

	std::ifstream is_major( "/sys/hypervisor/version/major" );
	std::ifstream is_minor( "/sys/hypervisor/version/minor" );
	std::ifstream is_extra( "/sys/hypervisor/version/extra" );

	if ( !is_major || !is_minor || !is_extra )
		throw std::runtime_error( "failed to open the /sys/hypervisor/version interface" );

	is_major >> verMajor;
	is_minor >> verMinor;
	is_extra >> verExtra;

	return Version( verMajor, verMinor, verExtra );
}

XCFactory::XCFactory() : version{ getVersion() }, lib_{ "libxenctrl.so" }
{
	xen_capabilities_info_t xen_caps;
	xen_domain_handle_t     xen_uuid;
	auto                    open_fn    = lib_.lookup<xc_interface_open_fn_t, xc_interface_open_fn_name>();
	auto                    close_fn   = lib_.lookup<xc_interface_close_fn_t, xc_interface_close_fn_name>();
	auto                    version_fn = lib_.lookup<xc_version_fn_t, xc_version_fn_name>();

	if ( version < Version( 4, 6 ) )
		throw std::runtime_error( "Unsupported Xen version. Should be at least 4.6" );

	xc_interface *xci = open_fn( nullptr, nullptr, 0 );

	if ( !xci )
		throw std::runtime_error( "xc_interface_open() failed" );

	XS           xs;
	unsigned int size = 0;
	char *       xenServer =
	        static_cast<char *>( xs.readTimeout( XS::xbtNull, "/mh/XenSource-TM_XenEnterprise-TM", &size, 1 ) );

	if ( xenServer && xenServer[0] != '\0' )
		isXenServer = true;

	free( xenServer );

	if ( !isXenServer && ( version == Version( 4, 6 ) || version == Version( 4, 7 ) ) &&
	     lib_.contains( "xc_set_mem_access_multi" ) )
		isXenServer = true;

	if ( version_fn( xci, XENVER_capabilities, &xen_caps ) != 0 ) {
		close_fn( xci );
		throw std::runtime_error( "Could not get Xen capabilities" );
	}

	caps = std::string( xen_caps );

	if ( version_fn( xci, XENVER_guest_handle, &xen_uuid ) != 0 ) {
		close_fn( xci );
		throw std::runtime_error( "Could not get local domain UUID" );
	}

	std::stringstream ss;
	ss << std::hex << std::setfill( '0' );

	for ( int i = 0; i < 16; ++i ) {
		ss << std::setw( 2 ) << ( int )xen_uuid[i];
		if ( i == 3 || i == 5 || i == 7 || i == 9 )
			ss << '-';
	}

	uuid = ss.str();
	close_fn( xci );

	domainPause                = LOOKUP_XC_FUNCTION_REQUIRED( domain_pause );
	domainUnpause              = LOOKUP_XC_FUNCTION_REQUIRED( domain_unpause );
	domainShutdown             = LOOKUP_XC_FUNCTION_REQUIRED( domain_shutdown );
	domainGetInfo              = LOOKUP_XC_FUNCTION_REQUIRED( domain_getinfo );
	domainGetInfoList          = LOOKUP_XC_FUNCTION_REQUIRED( domain_getinfolist );
	domainMaximumGpfn          = LOOKUP_XC_FUNCTION_REQUIRED( domain_maximum_gpfn );
	domainDebugControl         = LOOKUP_XC_FUNCTION_REQUIRED( domain_debug_control );
	domainGetTscInfo           = LOOKUP_XC_FUNCTION_REQUIRED( domain_get_tsc_info );
	domainSetAccessRequired    = LOOKUP_XC_FUNCTION_REQUIRED( domain_set_access_required );
	domainHvmGetContext        = LOOKUP_XC_FUNCTION_REQUIRED( domain_hvm_getcontext );
	domainHvmGetContextPartial = LOOKUP_XC_FUNCTION_REQUIRED( domain_hvm_getcontext_partial );
	domainSetCoresPerSocket    = LOOKUP_XC_FUNCTION_OPTIONAL( domain_set_cores_per_socket );
	setMemAccess               = LOOKUP_XC_FUNCTION_REQUIRED( set_mem_access );
	altp2mSetMemAccess         = LOOKUP_XC_FUNCTION_REQUIRED( altp2m_set_mem_access );
	altp2mSetDomainState       = LOOKUP_XC_FUNCTION_REQUIRED( altp2m_set_domain_state );
	altp2mCreateView           = LOOKUP_XC_FUNCTION_REQUIRED( altp2m_create_view );
	altp2mDestroyView          = LOOKUP_XC_FUNCTION_REQUIRED( altp2m_destroy_view );
	altp2mSwitchToView         = LOOKUP_XC_FUNCTION_REQUIRED( altp2m_switch_to_view );
	mapForeignRange            = LOOKUP_XC_FUNCTION_REQUIRED( map_foreign_range );
	getMemAccess               = LOOKUP_XC_FUNCTION_REQUIRED( get_mem_access );
	translateForeignAddress    = LOOKUP_XC_FUNCTION_REQUIRED( translate_foreign_address );
	copyToDomainPage           = LOOKUP_XC_FUNCTION_REQUIRED( copy_to_domain_page );
	hvmInjectTrap              = LOOKUP_XC_FUNCTION_REQUIRED( hvm_inject_trap );
	vcpuSetRegisters           = LOOKUP_XC_FUNCTION_REQUIRED( vcpu_set_registers );
	monitorEnable              = LOOKUP_XC_FUNCTION_REQUIRED( monitor_enable );
	monitorDisable             = LOOKUP_XC_FUNCTION_REQUIRED( monitor_disable );
	monitorSinglestep          = LOOKUP_XC_FUNCTION_REQUIRED( monitor_singlestep );
	monitorSoftwareBreakpoint  = LOOKUP_XC_FUNCTION_REQUIRED( monitor_software_breakpoint );
	monitorEmulateEachRep      = LOOKUP_XC_FUNCTION_OPTIONAL( monitor_emulate_each_rep );
	monitorMovToMsr            = LOOKUP_XC_FUNCTION_REQUIRED( monitor_mov_to_msr );
	monitorGuestRequest        = LOOKUP_XC_FUNCTION_REQUIRED( monitor_guest_request );
	monitorWriteCtrlreg        = LOOKUP_XC_FUNCTION_REQUIRED( monitor_write_ctrlreg );

	evtchnOpen            = LOOKUP_BDVMI_FUNCTION_REQUIRED( evtchn_open );
	evtchnClose           = LOOKUP_BDVMI_FUNCTION_REQUIRED( evtchn_close );
	evtchnFd              = LOOKUP_BDVMI_FUNCTION_REQUIRED( evtchn_fd );
	evtchnPending         = LOOKUP_BDVMI_FUNCTION_REQUIRED( evtchn_pending );
	evtchnBindInterdomain = LOOKUP_BDVMI_FUNCTION_REQUIRED( evtchn_bind_interdomain );
	evtchnUnbind          = LOOKUP_BDVMI_FUNCTION_REQUIRED( evtchn_unbind );
	evtchnUnmask          = LOOKUP_BDVMI_FUNCTION_REQUIRED( evtchn_unmask );
	evtchnNotify          = LOOKUP_BDVMI_FUNCTION_REQUIRED( evtchn_notify );
}

std::unique_ptr<xc_interface, int ( * )( xc_interface * )> XCFactory::createInterface() const
{
	auto open_fn  = lib_.lookup<xc_interface_open_fn_t, xc_interface_open_fn_name>();
	auto close_fn = lib_.lookup<xc_interface_close_fn_t, xc_interface_close_fn_name>();

	xc_interface *xci = open_fn( nullptr, nullptr, 0 );
	if ( !xci )
		throw std::runtime_error( "xc_interface_open() failed" );
	return std::unique_ptr<xc_interface, int ( * )( xc_interface * )>( xci, close_fn );
}

template <typename T, const char name[]>
std::function<T> XCFactoryImpl<T, name>::lookup( const XCFactory *p, bool required )
{
	return p->lib_.lookup<T, name>( required );
}

template <> struct XCFactoryImpl<xc_domain_getinfo_fn_t, xc_domain_getinfo_fn_name> {
	static std::function<xc_domain_getinfo_fn_t> lookup( const XCFactory *p, bool )
	{
		using fn_t = int( xc_interface *, uint32_t, unsigned int, xc_dominfo_t * );
		fn_t *fun  = p->lib_.lookup<fn_t, xc_domain_getinfo_fn_name>();
		if ( !fun )
			return nullptr;

		return [fun]( xc_interface *xci, uint32_t domid, XenDomainInfo &info ) {
			xc_dominfo_t impl;
			int          ret = fun( xci, domid, 1, &impl );
			if ( ret != -1 ) {
				info.domid       = impl.domid;
				info.hvm         = ( impl.hvm != 0 );
				info.dying       = ( impl.dying != 0 );
				info.shutdown    = ( impl.shutdown != 0 );
				info.max_vcpu_id = impl.max_vcpu_id;
			}
			return ret;
		};
	}
};

template <> struct XCFactoryImpl<xc_domain_getinfolist_fn_t, xc_domain_getinfolist_fn_name> {
	static std::function<xc_domain_getinfolist_fn_t> lookup( const XCFactory *p, bool )
	{
		using fn_t = int( xc_interface *, uint32_t, unsigned int, xc_domaininfo_t * );
		fn_t *fun  = p->lib_.lookup<fn_t, xc_domain_getinfolist_fn_name>();

		return [fun]( xc_interface *xci, uint32_t domid, XenDomctlInfo &info ) {
			xen_domctl_getdomaininfo_extended_safe info_hotfix = {};
			int                                    ret         = fun( xci, domid, 1,
			               reinterpret_cast<xen_domctl_getdomaininfo *>( &info_hotfix.extended ) );

			if ( ret != -1 ) {
				// PVH domain, according to Andrew Cooper.
				info.pvh =
				        ( info_hotfix.extended.arch_config.emulation_flags == EXT_XEN_X86_EMU_LAPIC );
			}

			return ret;
		};
	}
};

template <> struct XCFactoryImpl<xc_set_mem_access_fn_t, xc_set_mem_access_fn_name> {
	static std::function<xc_set_mem_access_fn_t> lookup( const XCFactory *p, bool )
	{
		using multi_fn_t = int( xc_interface *, uint32_t, uint8_t *, uint64_t *, uint32_t );
		multi_fn_t *fun1 = p->lib_.lookup<multi_fn_t, xc_set_mem_access_multi_fn_name>( false );
		if ( fun1 ) {
			return [fun1]( xc_interface *xci, uint32_t domid, const Driver::MemAccessMap &access ) {
				std::vector<uint8_t>  access_type;
				std::vector<uint64_t> gfns;

				for ( auto &&item : access ) {
					access_type.push_back( XC::xenMemAccess( item.second ) );
					gfns.push_back( item.first );
				}
				StatsCollector::instance().incStat( "xcSetMemAccessMulti" );
				return fun1( xci, domid, &access_type[0], &gfns[0], gfns.size() );
			};
		}

		using fn_t = int( xc_interface *, uint32_t, xenmem_access_t, uint64_t, uint32_t );
		fn_t *fun2 = p->lib_.lookup<fn_t, xc_set_mem_access_fn_name>();
		return [fun2]( xc_interface *xci, uint32_t domid, const Driver::MemAccessMap &access ) {
			for ( auto &&item : access ) {
				StatsCollector::instance().incStat( "xcSetMemAccess" );
				fun2( xci, domid, XC::xenMemAccess( item.second ), item.first, 1 );
			}
			return 0; // FIXME: value is ignored in the original code
		};
	}
};

template <> struct XCFactoryImpl<xc_altp2m_set_mem_access_fn_t, xc_altp2m_set_mem_access_fn_name> {
	static std::function<xc_altp2m_set_mem_access_fn_t> lookup( const XCFactory *p, bool )
	{
		using multi_fn_t = int( xc_interface *, uint16_t, uint32_t, uint8_t *, uint64_t *, uint32_t );
		multi_fn_t *fun1 = p->lib_.lookup<multi_fn_t, xc_altp2m_set_mem_access_multi_fn_name>( false );
		if ( fun1 ) {
			return [fun1]( xc_interface *xci, uint32_t domid, uint16_t altp2mViewId,
			               const Driver::MemAccessMap &access ) {
				std::vector<uint8_t>  access_type;
				std::vector<uint64_t> gfns;

				for ( auto &&item : access ) {
					access_type.push_back( XC::xenMemAccess( item.second ) );
					gfns.push_back( item.first );
				}
				StatsCollector::instance().incStat( "xcSetMemAccessMulti" );
				return fun1( xci, domid, altp2mViewId, &access_type[0], &gfns[0], gfns.size() );
			};
		}

		using fn_t = int( xc_interface *, uint16_t, uint32_t, xenmem_access_t, uint64_t, uint32_t );
		fn_t *fun2 = p->lib_.lookup<fn_t, xc_altp2m_set_mem_access_fn_name>();
		return [fun2]( xc_interface *xci, uint32_t domid, uint16_t altp2mViewId,
		               const Driver::MemAccessMap &access ) {
			for ( auto &&item : access ) {
				StatsCollector::instance().incStat( "xcSetMemAccess" );
				fun2( xci, domid, altp2mViewId, XC::xenMemAccess( item.second ), item.first, 1 );
			}
			return 0; // FIXME: value is ignored in the original code
		};
	}
};

template <> struct XCFactoryImpl<xc_monitor_mov_to_msr_fn_t, xc_monitor_mov_to_msr_fn_name> {
	static std::function<xc_monitor_mov_to_msr_fn_t> lookup( const XCFactory *p, bool )
	{
		if ( p->version < Version( 4, 11 ) ) {
			using fn_t = int( xc_interface *, uint32_t, uint32_t, bool );
			fn_t *fun  = p->lib_.lookup<fn_t, xc_monitor_mov_to_msr_fn_name>();
			return [fun]( xc_interface *xci, uint32_t domid, uint32_t msr, bool enable, bool ) {
				return fun( xci, domid, msr, enable );
			};
		}

		using fn_t = int( xc_interface *, uint32_t, uint32_t, bool, bool );
		fn_t *fun  = p->lib_.lookup<fn_t, xc_monitor_mov_to_msr_fn_name>();
		return [fun]( xc_interface *xci, uint32_t domid, uint32_t msr, bool enable, bool onchangeonly ) {
			return fun( xci, domid, msr, enable, onchangeonly );
		};
	}
};

template <> struct XCFactoryImpl<xc_monitor_guest_request_fn_t, xc_monitor_guest_request_fn_name> {
	static std::function<xc_monitor_guest_request_fn_t> lookup( const XCFactory *p, bool )
	{
		if ( p->version < Version( 4, 9 ) ) {
			using fn_t = int( xc_interface *, uint32_t, bool, bool );
			fn_t *fun  = p->lib_.lookup<fn_t, xc_monitor_guest_request_fn_name>();
			return [fun]( xc_interface *xci, uint32_t domid, bool enable, bool sync, bool ) {
				return fun( xci, domid, enable, sync );
			};
		}

		using fn_t = int( xc_interface *, uint32_t, bool, bool, bool );
		fn_t *fun  = p->lib_.lookup<fn_t, xc_monitor_guest_request_fn_name>();
		return [fun]( xc_interface *xci, uint32_t domid, bool enable, bool sync, bool allow_userspace ) {
			return fun( xci, domid, enable, sync, allow_userspace );
		};
	}
};

template <> struct XCFactoryImpl<xc_monitor_write_ctrlreg_fn_t, xc_monitor_write_ctrlreg_fn_name> {
	static std::function<xc_monitor_write_ctrlreg_fn_t> lookup( const XCFactory *p, bool )
	{
		if ( p->version < Version( 4, 10 ) ) {
			using fn_t = int( xc_interface *, uint32_t, uint16_t, bool, bool, bool );
			fn_t *fun  = p->lib_.lookup<fn_t, xc_monitor_write_ctrlreg_fn_name>();
			return [fun]( xc_interface *xci, uint32_t domid, uint16_t index, bool enable, bool sync,
			              uint64_t, bool onchangeonly ) {
				return fun( xci, domid, index, enable, sync, onchangeonly );
			};
		}

		using fn_t = int( xc_interface *, uint32_t, uint16_t, bool, uint64_t, bool, bool );
		fn_t *fun  = p->lib_.lookup<fn_t, xc_monitor_write_ctrlreg_fn_name>();
		return [fun]( xc_interface *xci, uint32_t domid, uint16_t index, bool enable, bool sync,
		              uint64_t bitmask, bool onchangeonly ) {
			return fun( xci, domid, index, enable, sync, bitmask, onchangeonly );
		};
	}
};

template <> struct XCFactoryImpl<bdvmi_evtchn_open_fn_t, xc_evtchn_open_fn_name> {
	static std::function<bdvmi_evtchn_open_fn_t> lookup( const XCFactory *p, bool )
	{
		using fn_t = xc_evtchn *( xentoollog_logger *, unsigned );
		fn_t *fun  = p->lib_.lookup<fn_t, xc_evtchn_open_fn_name>();
		return [fun]() { return fun( nullptr, 0 ); };
	}
};

template <> struct XCFactoryImpl<xc_vcpu_set_registers_fn_t, xc_vcpu_set_registers_fn_name> {
	static std::function<xc_vcpu_set_registers_fn_t> lookup( const XCFactory *p, bool )
	{
		using getcontext_fn_t = int( xc_interface *, uint32_t, uint32_t, vcpu_guest_context_any_t * );
		using setcontext_fn_t = int( xc_interface *, uint32_t, uint32_t, vcpu_guest_context_any_t * );

		getcontext_fn_t *get_fun = p->lib_.lookup<getcontext_fn_t, xc_vcpu_getcontext_fn_name>();
		setcontext_fn_t *set_fun = p->lib_.lookup<setcontext_fn_t, xc_vcpu_setcontext_fn_name>();

		bool isX86_64 = p->caps.find( "x86_64" ) != std::string::npos;

		return [get_fun, set_fun, isX86_64]( xc_interface *xci, uint32_t domid, unsigned short vcpu,
		                                     const Registers &regs, bool setEip ) {
			vcpu_guest_context_any_t ctxt;
			int                      ret = 0;

			StatsCollector::instance().incStat( "xcGetVcpuContext" );
			if ( ( ret = get_fun( xci, domid, vcpu, &ctxt ) ) != 0 )
				return ret;

			if ( isX86_64 ) {
				ctxt.x64.user_regs.rax    = regs.rax;
				ctxt.x64.user_regs.rcx    = regs.rcx;
				ctxt.x64.user_regs.rdx    = regs.rdx;
				ctxt.x64.user_regs.rbx    = regs.rbx;
				ctxt.x64.user_regs.rsp    = regs.rsp;
				ctxt.x64.user_regs.rbp    = regs.rbp;
				ctxt.x64.user_regs.rsi    = regs.rsi;
				ctxt.x64.user_regs.rdi    = regs.rdi;
				ctxt.x64.user_regs.r8     = regs.r8;
				ctxt.x64.user_regs.r9     = regs.r9;
				ctxt.x64.user_regs.r10    = regs.r10;
				ctxt.x64.user_regs.r11    = regs.r11;
				ctxt.x64.user_regs.r12    = regs.r12;
				ctxt.x64.user_regs.r13    = regs.r13;
				ctxt.x64.user_regs.r14    = regs.r14;
				ctxt.x64.user_regs.r15    = regs.r15;
				ctxt.x64.user_regs.rflags = regs.rflags;

				if ( setEip )
					ctxt.x64.user_regs.eip = regs.rip;
			} else {
				ctxt.x32.user_regs.eax    = regs.rax;
				ctxt.x32.user_regs.ecx    = regs.rcx;
				ctxt.x32.user_regs.edx    = regs.rdx;
				ctxt.x32.user_regs.ebx    = regs.rbx;
				ctxt.x32.user_regs.esp    = regs.rsp;
				ctxt.x32.user_regs.ebp    = regs.rbp;
				ctxt.x32.user_regs.esi    = regs.rsi;
				ctxt.x32.user_regs.edi    = regs.rdi;
				ctxt.x32.user_regs.eflags = regs.rflags;

				if ( setEip )
					ctxt.x32.user_regs.eip = regs.rip;
			}

			StatsCollector::instance().incStat( "xcSetContext" );
			ret = set_fun( xci, domid, vcpu, &ctxt );

			return ret;
		};
	}
};

const unsigned long XC::pageSize         = XC_PAGE_SIZE;
const unsigned long XC::pageShift        = XC_PAGE_SHIFT;
const unsigned long XC::pageMask         = XC_PAGE_MASK;
const unsigned long XC::invalidMfn       = INVALID_MFN;
const uint8_t       XC::shutdownPoweroff = SHUTDOWN_poweroff;

using namespace std::placeholders;

XC::XC()
    : xci_{ XCFactory::instance().createInterface() }, version{ XCFactory::instance().version },
      isXenServer{ XCFactory::instance().isXenServer }, caps{ XCFactory::instance().caps },
      uuid{ XCFactory::instance().uuid }, domainPause{ std::bind( XCFactory::instance().domainPause, xci_.get(), _1 ) },
      domainUnpause{ std::bind( XCFactory::instance().domainUnpause, xci_.get(), _1 ) },
      domainShutdown{ std::bind( XCFactory::instance().domainShutdown, xci_.get(), _1, _2 ) },
      domainGetInfo{ std::bind( XCFactory::instance().domainGetInfo, xci_.get(), _1, _2 ) },
      domainGetInfoList{ std::bind( XCFactory::instance().domainGetInfoList, xci_.get(), _1, _2 ) },
      domainMaximumGpfn{ std::bind( XCFactory::instance().domainMaximumGpfn, xci_.get(), _1, _2 ) },
      domainDebugControl{ std::bind( XCFactory::instance().domainDebugControl, xci_.get(), _1, _2, _3 ) },
      domainGetTscInfo{ std::bind( XCFactory::instance().domainGetTscInfo, xci_.get(), _1, _2, _3, _4, _5 ) },
      domainSetAccessRequired{ std::bind( XCFactory::instance().domainSetAccessRequired, xci_.get(), _1, _2 ) },
      domainHvmGetContext{ std::bind( XCFactory::instance().domainHvmGetContext, xci_.get(), _1, _2, _3 ) },
      domainHvmGetContextPartial{
              std::bind( XCFactory::instance().domainHvmGetContextPartial, xci_.get(), _1, _2, _3, _4, _5 ) },
      setMemAccess{ std::bind( XCFactory::instance().setMemAccess, xci_.get(), _1, _2 ) },
      altp2mSetMemAccess{ std::bind( XCFactory::instance().altp2mSetMemAccess, xci_.get(), _1, _2, _3 ) },
      altp2mSetDomainState{ std::bind( XCFactory::instance().altp2mSetDomainState, xci_.get(), _1, _2 ) },
      altp2mCreateView{ std::bind( XCFactory::instance().altp2mCreateView, xci_.get(), _1, _2, _3 ) },
      altp2mDestroyView{ std::bind( XCFactory::instance().altp2mDestroyView, xci_.get(), _1, _2 ) },
      altp2mSwitchToView{ std::bind( XCFactory::instance().altp2mSwitchToView, xci_.get(), _1, _2 ) },
      mapForeignRange{ std::bind( XCFactory::instance().mapForeignRange, xci_.get(), _1, _2, _3, _4 ) },
      getMemAccess{ std::bind( XCFactory::instance().getMemAccess, xci_.get(), _1, _2, _3 ) },
      translateForeignAddress{ std::bind( XCFactory::instance().translateForeignAddress, xci_.get(), _1, _2, _3 ) },
      copyToDomainPage{ std::bind( XCFactory::instance().copyToDomainPage, xci_.get(), _1, _2, _3 ) },
      hvmInjectTrap{ std::bind( XCFactory::instance().hvmInjectTrap, xci_.get(), _1, _2, _3, _4, _5, _6, _7 ) },
      vcpuSetRegisters{ std::bind( XCFactory::instance().vcpuSetRegisters, xci_.get(), _1, _2, _3, _4 ) },
      monitorEnable{ std::bind( XCFactory::instance().monitorEnable, xci_.get(), _1, _2 ) },
      monitorDisable{ std::bind( XCFactory::instance().monitorDisable, xci_.get(), _1 ) },
      monitorSinglestep{ std::bind( XCFactory::instance().monitorSinglestep, xci_.get(), _1, _2 ) },
      monitorSoftwareBreakpoint{ std::bind( XCFactory::instance().monitorSoftwareBreakpoint, xci_.get(), _1, _2 ) },
      monitorMovToMsr{ std::bind( XCFactory::instance().monitorMovToMsr, xci_.get(), _1, _2, _3, _4 ) },
      monitorGuestRequest{ std::bind( XCFactory::instance().monitorGuestRequest, xci_.get(), _1, _2, _3, _4 ) },
      monitorWriteCtrlreg{ std::bind( XCFactory::instance().monitorWriteCtrlreg, xci_.get(), _1, _2, _3, _4, _5, _6 ) },
      evtchnOpen{ XCFactory::instance().evtchnOpen }, evtchnClose{ XCFactory::instance().evtchnClose },
      evtchnFd{ XCFactory::instance().evtchnFd }, evtchnPending{ XCFactory::instance().evtchnPending },
      evtchnBindInterdomain{ XCFactory::instance().evtchnBindInterdomain },
      evtchnUnbind{ XCFactory::instance().evtchnUnbind }, evtchnUnmask{ XCFactory::instance().evtchnUnmask },
      evtchnNotify{ XCFactory::instance().evtchnNotify }
{
	if ( XCFactory::instance().monitorEmulateEachRep )
		monitorEmulateEachRep = std::bind( XCFactory::instance().monitorEmulateEachRep, xci_.get(), _1, _2 );

	if ( XCFactory::instance().domainSetCoresPerSocket )
		domainSetCoresPerSocket = std::bind( XCFactory::instance().domainSetCoresPerSocket, xci_.get(), _1, _2 );
}

xenmem_access_t XC::xenMemAccess( uint8_t bdvmiBitmask )
{
	xenmem_access_t memaccess = XENMEM_access_n;

	bool read    = !!( bdvmiBitmask & Driver::PAGE_READ );
	bool write   = !!( bdvmiBitmask & Driver::PAGE_WRITE );
	bool execute = !!( bdvmiBitmask & Driver::PAGE_EXECUTE );

	if ( read && !write && !execute )
		memaccess = XENMEM_access_r;

	else if ( !read && write && !execute )
		memaccess = XENMEM_access_w;

	else if ( !read && !write && execute )
		memaccess = XENMEM_access_x;

	else if ( read && write && !execute )
		memaccess = XENMEM_access_rw;

	else if ( read && !write && execute )
		memaccess = XENMEM_access_rx;

	else if ( !read && write && execute )
		memaccess = XENMEM_access_wx;

	else if ( read && write && execute )
		memaccess = XENMEM_access_rwx;

	return memaccess;
}

} // namespace bdvmi
