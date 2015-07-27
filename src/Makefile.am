AM_CPPFLAGS = -I$(top_srcdir)/include -I$(xendir)/include

lib_LTLIBRARIES = libbdvmi.la

libbdvmi_la_LDFLAGS = -L$(xendir)/lib -Wl,-rpath,$(xendir)/lib
libbdvmi_la_SOURCES = bdvmibackendfactory.cpp bdvmidomainwatcher.cpp \
    bdvmiexception.cpp bdvmixencache.cpp bdvmixendomainwatcher.cpp \
    bdvmixendriver.cpp  bdvmixeneventmanager.cpp
