AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = libbdvmi.la

noinst_HEADERS = dynamiclibfactory.h utils.h \
		 xcwrapper.h xenaltp2m.h \
		 xendomainwatcher.h xendriver.h \
		 xeneventmanager.h xswrapper.h \
		 xenvmevent_v3.h xenvmevent_v4.h \
		 xenvmevent_v5.h kvmdomainwatcher.h \
		 kvmdriver.h kvmeventmanager.h

libbdvmi_la_SOURCES = backendfactory.cpp domainwatcher.cpp \
		      xendomainwatcher.cpp xendriver.cpp \
		      xeneventmanager.cpp statscollector.cpp \
		      driver.cpp dynamiclibfactory.cpp \
		      eventmanager.cpp pagecache.cpp \
		      version.cpp xcwrapper.cpp \
		      xenaltp2m.cpp xswrapper.cpp \
		      logger.cpp

if KVMI
libbdvmi_la_SOURCES += kvmdomainwatcher.cpp kvmdriver.cpp \
		       kvmeventmanager.cpp
libbdvmi_la_CXXFLAGS = $(KVMI_CFLAGS) $(UUID_CFLAGS) $(CRYPTO_CFLAGS)
libbdvmi_la_LIBADD = $(KVMI_LIBS) $(UUID_LIBS) $(CRYPTO_LIBS)
endif

libbdvmi_la_LDFLAGS = -version-number 1:0 \
	-Wl,--version-script,$(srcdir)/version.ld
