AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = libbdvmi.la

noinst_HEADERS = dynamiclibfactory.h utils.h \
		 xcwrapper.h xenaltp2m.h \
		 xendomainwatcher.h xendriver.h \
		 xeneventmanager.h xswrapper.h \
		 xenvmevent_v3.h xenvmevent_v4.h

libbdvmi_la_SOURCES = backendfactory.cpp domainwatcher.cpp \
		      xendomainwatcher.cpp xendriver.cpp \
		      xeneventmanager.cpp statscollector.cpp \
		      driver.cpp dynamiclibfactory.cpp \
		      eventmanager.cpp pagecache.cpp \
		      version.cpp xcwrapper.cpp \
		      xenaltp2m.cpp xswrapper.cpp \
		      logger.cpp
