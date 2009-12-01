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

all-local:
	perl Makefile.PL && $(MAKE) -f Makefile.real all
check-local:
	$(MAKE) -f Makefile.real test
clean-local:
	$(MAKE) -f Makefile.real clean
     
install-data-local:
	$(MAKE) -f Makefile.real pure_install
install-exec-local:
	$(MAKE) -f Makefile.real pure_install 
uninstall-local:
	$(MAKE) -f Makefile.real uninstall
     
# Distribute files from here.
EXTRA_DIST = Nuxwdogclient.xs fallback/const-xs.inc \
	fallback/const-c.inc const-xs.inc \
	typemap t/Nuxwdogclient.t \
	README  Changes lib/Nuxwdogclient.pm \
	MANIFEST ppport.h Makefile.PL \
	const-c.inc

