AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = libbdvmi.la

noinst_HEADERS = dynamiclibfactory.h utils.h \
		 xcwrapper.h xenaltp2m.h \
		 xendomainwatcher.h xendriver.h \
		 xeneventmanager.h xswrapper.h

libbdvmi_la_SOURCES = bdvmibackendfactory.cpp bdvmidomainwatcher.cpp \
		      bdvmixendomainwatcher.cpp bdvmixendriver.cpp \
		      bdvmixeneventmanager.cpp bdvmistatscollector.cpp \
		      bdvmidriver.cpp bdvmidynamiclibfactory.cpp \
		      bdvmieventmanager.cpp bdvmipagecache.cpp \
		      bdvmiversion.cpp bdvmixcwrapper.cpp \
		      bdvmixenaltp2m.cpp bdvmixswrapper.cpp
