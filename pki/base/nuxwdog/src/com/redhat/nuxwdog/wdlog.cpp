// --- BEGIN COPYRIGHT BLOCK ---
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation;
// version 2.1 of the License.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor,
// Boston, MA  02110-1301  USA
//
// Copyright (C) 2009 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

#include <stdio.h>
#include <sys/types.h>
#include <stdarg.h>
#include "wdlog.h"


void
watchdog_openlog(void)
{
  openlog("nuxwdog", LOG_PID|LOG_CONS|LOG_NOWAIT, LOG_DAEMON);
  setlogmask(LOG_UPTO(LOG_ERR));
  watchdog_log(LOG_INFO,
	       "logging initialized info");
}

void
watchdog_closelog(void)
{
  closelog();
}

void
watchdog_syslog(int priority, const char *fmt, ...)
{
  va_list args;
  syslog(priority, fmt, args);
}
