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

/*
 * wdconf.h Watchdog parsing code for server config files.
 */

#ifndef _WDCONF_H_
#define _WDCONF_H_

typedef struct watchdog_conf_info_t {
    char            *exeFile;          /* file to execute */
    char            *exeArgs;          /* args to execute */
    char            *tmpDir;           /* dir for socket files */
    char            *exeOut;           /* location of stdout */
    char            *exeErr;           /* location for stderr */
    int             exeBackground;     /* 1 for background process, 0 otherwise */
    char            *exeContext;       /* selinux type context */
    char            *pidFile;          /* pidFile */
    char            *childPidFile;     /* child pid file */
    int             childSecurity;     /* enforce child security */    
} watchdog_conf_info_t;

watchdog_conf_info_t *watchdog_parse(char *conf_file);
void watchdog_confinfo_free(watchdog_conf_info_t *info);

#endif /* _WDCONF_H_ */
