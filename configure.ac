AC_INIT([libbdvmi], [0.1])

LT_INIT

AC_CONFIG_SRCDIR(src/bdvmixendriver.cpp)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS(config.h)

CXXFLAGS="$CXXFLAGS -W -Wall"

AC_ARG_ENABLE(debug,
    [  --enable-debug          compile with gdb debug information.], 
    CXXFLAGS="$CXXFLAGS -g")

AC_ARG_ENABLE(optimize,
    [  --enable-optimize       optimize compiled code (-O2).], 
    CXXFLAGS="$CXXFLAGS -O2")

AM_INIT_AUTOMAKE
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_LIBTOOL

AC_CHECK_LIB(xenctrl, xc_interface_open, , AC_MSG_ERROR([Could not find libxenctrl!]))
AC_CHECK_LIB(xenstore, xs_open, , AC_MSG_ERROR([Could not find libxenstore!]))

AC_CHECK_TYPE(int32_t, int)
AC_CHECK_TYPE(int16_t, short)
AC_CHECK_TYPE(uint16_t, unsigned short)
AC_CHECK_TYPE(uint32_t, unsigned int)
AC_CHECK_TYPE(uint64_t, unsigned long long)

AC_OUTPUT(Makefile src/Makefile include/Makefile)
