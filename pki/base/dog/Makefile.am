# --- BEGIN COPYRIGHT BLOCK ---
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor,
# Boston, MA  02110-1301  USA 
# 
# Copyright (C) 2007 Red Hat, Inc.
# All rights reserved.
# --- END COPYRIGHT BLOCK ---

# look for included m4 files in the ./m4/ directory
ACLOCAL_AMFLAGS = -I m4

AUTOMAKE_OPTIONS = foreign
SUBDIRS =  . lib/perl/Pkidogclient
#------------------------
# Compiler Flags
#------------------------
DEBUG_DEFINES = @debug_defs@
PKIDOG_INCLUDES = @jni_inc@ -I$(srcdir)/build/include
# These paths are dependent on the settings of prefix and exec_prefix
# which may be specified at make time.  So we cannot use AC_DEFINE in
# the configure.ac because that would set the values prior to their
# being defined.  Defining them here ensures that they are properly
# expanded before use.  See create_instance.h for more details. The
# quoting ensures that the values are # quoted for the shell command,
# and the value expands to a quoted string value in the header file
# (e.g. - #define LOCALSTATEDIR "/var"; without the quotes, it would
#         be #define LOCALSTATEDIR /var which would be an error).
PATH_DEFINES = -DLOCALSTATEDIR="\"$(localstatedir)\"" \
	-DSYSCONFDIR="\"$(sysconfdir)\"" -DLIBDIR="\"$(libdir)\"" \
	-DBINDIR="\"$(bindir)\"" -DDATADIR="\"$(datadir)\"" \
	-DDOCDIR="\"$(docdir)\"" -DLIBEXECDIR="\"$(libexecdir)\""
AM_CPPFLAGS = $(DEBUG_DEFINES) $(PKIDOG_INCLUDES) $(PATH_DEFINES)
# We need to make sure that libpthread is linked before libc on HP-UX.
if HPUX
AM_LDFLAGS = -lpthread
endif

#------------------------
# Linker Flags
#------------------------
NSPR_LINK = @nspr_lib@ -lplc4 -lplds4 -lnspr4
SELINUX_LINK = -lselinux
LIBSOCKET=@LIBSOCKET@
LIBNSL=@LIBNSL@
LIBDL=@LIBDL@
LIBCSTD=@LIBCSTD@
LIBCRUN=@LIBCRUN@

#------------------------
# Install Paths
#------------------------
licensedir = $(prefix)@licensedir@
pkidog_jardir = $(prefix)@pkidog_jardir@


#------------------------
# Build Products
#------------------------
lib_LTLIBRARIES =	libpkidog.la libpkidog-jni.la
bin_PROGRAMS = pkidog

#------------------------
# Installed Files
#------------------------
license_DATA =  $(srcdir)/LICENSE

pkidog_jar_SCRIPTS = $(srcdir)/build/jars/pkidog.jar


#////////////////////////////////////////////////////////////////
#
#   Dynamic Libraries
#
#////////////////////////////////////////////////////////////////

#------------------------
# libpkidog
#------------------------
library_includedir=$(includedir)/pkidog
library_include_HEADERS = $(srcdir)/src/com/redhat/pkidog/WatchdogClient.h $(srcdir)/src/com/redhat/pkidog/wdservermessage.h \
			$(srcdir)/src/com/redhat/pkidog/WatchdogClientJNI.h
libpkidog_la_SOURCES =	src/com/redhat/pkidog/WatchdogClient.cpp          \
			src/com/redhat/pkidog/wdservermessage.cpp         \
			src/com/redhat/pkidog/wdutils.cpp                 \
                        src/com/redhat/pkidog/WatchdogClientCFunc.c

libpkidog_la_CPPFLAGS = $(AM_CPPFLAGS) @nspr_inc@
libpkidog_la_LDFLAGS = $(AM_LDFLAGS) -version-info $(GENERIC_LIBRARY_VERSION) --release $(VERSION)
libpkidog_la_LIBADD = $(NSPR_LINK) \
	$(LIBCSTD) $(LIBCRUN)

#--------------------------
# libpkidog-jni 
#--------------------------
libpkidog_jni_la_SOURCES =  src/com/redhat/pkidog/WatchdogClientJNI.cpp          

libpkidog_jni_la_CPPFLAGS = $(AM_CPPFLAGS) 
libpkidog_jni_la_LDFLAGS = $(AM_LDFLAGS) -avoid-version
libpkidog_jni_la_LIBADD = -lpkidog $(LIBCSTD) $(LIBCRUN)

#////////////////////////////////////////////////////////////////
#
#   Programs
#
#////////////////////////////////////////////////////////////////
pkidog_SOURCES = src/com/redhat/pkidog/watchdog.cpp \
			src/com/redhat/pkidog/wdconf.cpp \
			src/com/redhat/pkidog/wdsignals.cpp \
			src/com/redhat/pkidog/wdpwd.cpp \
			src/com/redhat/pkidog/wdlog.cpp \
			src/com/redhat/pkidog/wdservermessage.cpp \
			src/com/redhat/pkidog/wdlsmgr.cpp \
			src/com/redhat/pkidog/wdutils.cpp 
pkidog_CPPFLAGS = $(AM_CPPFLAGS) @nspr_inc@
pkidog_LDADD = $(NSPR_LINK) $(LIBCSTD) $(LIBCRUN) $(SELINUX_LINK)



#////////////////////////////////////////////////////////////////
#
#   Wrappers
#
#////////////////////////////////////////////////////////////////

