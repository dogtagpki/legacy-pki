/* --- BEGIN COPYRIGHT BLOCK ---
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301  USA 
 * 
 * Copyright (C) 2009 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include <nspr4/prtypes.h>

#include "ppport.h"

#include "../../../src/com/redhat/nuxwdog/WatchdogClient.h"

#include "const-c.inc"

MODULE = Nuxwdogclient		PACKAGE = Nuxwdogclient		

INCLUDE: const-xs.inc

PRStatus
call_WatchdogClient_init()

PRStatus
call_WatchdogClient_sendEndInit(numProcs)
        int numProcs

char *
call_WatchdogClient_getPassword(prompt, serial)
        char * prompt
        int serial

