AC_INIT([libbdvmi], [1.0])

LT_INIT

AC_CONFIG_SRCDIR(src/xendriver.cpp)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS(config.h)

CXXFLAGS="$CXXFLAGS -W -Wall -DXC_WANT_COMPAT_MAP_FOREIGN_API -DXC_WANT_COMPAT_EVTCHN_API -DXC_WANT_COMPAT_DEVICEMODEL_API"
XENDIR=""

AC_ARG_ENABLE(debug,
    [  --enable-debug          compile with gdb debug information],
    CXXFLAGS="$CXXFLAGS -g")

AC_ARG_ENABLE(optimize,
    [  --enable-optimize       optimize compiled code (-O2)],
    CXXFLAGS="$CXXFLAGS -O2")

AC_ARG_WITH(xen,
    [  --with-xen              specify Xen includes and libraries parent directory],
    XENDIR="$withval")

AC_ARG_ENABLE(kvmi,
    [  --enable-kvmi           enable KVMI support],
    CPPFLAGS="$CPPFLAGS -DUSE_KVMI")

if test -n $XENDIR ; then
    CFLAGS="-I$/XENDIR/include $CFLAGS"
    CXXFLAGS="-I$XENDIR/include $CXXFLAGS"
    LDFLAGS="-L$XENDIR/lib -Wl,-rpath,$XENDIR/lib $LDFLAGS"
fi

AM_INIT_AUTOMAKE
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_LIBTOOL

AX_CXX_COMPILE_STDCXX([14], [ext])

AC_CHECK_LIB(xenctrl, xc_interface_open, , AC_MSG_ERROR([Could not find libxenctrl!]))
AC_CHECK_LIB(xenstore, xs_open, , AC_MSG_ERROR([Could not find libxenstore!]))

if test "x$enable_kvmi" = "xyes" ; then
    PKG_CHECK_MODULES([KVMI], [libkvmi])
    PKG_CHECK_MODULES([UUID], [uuid])
    PKG_CHECK_MODULES([CRYPTO], [libcrypto])
fi

AM_CONDITIONAL([KVMI], [test "x$enable_kvmi" = "xyes"])

AC_CHECK_TYPE(int32_t, int)
AC_CHECK_TYPE(int16_t, short)
AC_CHECK_TYPE(uint16_t, unsigned short)
AC_CHECK_TYPE(uint32_t, unsigned int)
AC_CHECK_TYPE(uint64_t, unsigned long long)

AC_OUTPUT(Makefile src/Makefile include/Makefile examples/Makefile)
