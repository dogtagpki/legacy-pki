#!/bin/sh
# --- BEGIN COPYRIGHT BLOCK ---
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2011 Red Hat, Inc.
# All rights reserved.
# --- END COPYRIGHT BLOCK ---

if [ $# -lt 4 -o $# -gt 5 ] ; then
        echo "n=$#"
        echo "Usage:  $0 <user> <password> <hostname> <port> [<log_file>]"
        echo ""
        echo "        where:  user     - 'cn=Directory Manager'"
        echo "                password - a password"
        echo "                hostname - hostname"
        echo "                port     - port"
        echo "                log_file - log file name"
        echo
        exit 1
fi

java  -cp '.:./classes:/usr/share/java/ldapjdk.jar' UpgradeDB  "$@" 

