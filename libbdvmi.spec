Name: libbdvmi
Summary: A C++ virtual machine introspection library
License: LGPLv3+
URL: https://github.com/bitdefender/libbdvmi
Version: 1.0.0
Release: 0
Group: System/Libraries
BuildRequires: autoconf automake libtool glibc-devel gcc-c++ kernel-headers make libkvmi-devel
Source0: https://github.com/bitdefender/libbdvmi/archive/v1.0.0.tar.gz

%description
This package contains a fairly basic VMI library written in C++ and which supports Xen and KVM (via libkvmi)

%package devel
Summary: A C++ virtual machine introspection library development package
Requires: libbdvmi = %{version}
Group: Development/Libraries

%description devel
This package contains the headers and static library necessary for building
applications that use libbdvmi

%prep
%setup
./bootstrap

%build
%configure --enable-optimize --enable-kvmi
make

%install
%make_install

%files
%{_bindir}/hookguest
%{_libdir}/libbdvmi.so
%{_libdir}/libbdvmi.so.1
%{_libdir}/libbdvmi.so.1.0.0

%files devel
%{_includedir}/bdvmi/
%{_libdir}/libbdvmi.a
%{_libdir}/libbdvmi.la
%{_libdir}/pkgconfig/libbdvmi.pc
