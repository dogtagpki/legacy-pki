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

/*
 * wdconf.cpp - Watchdog parsing code for server config files.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "wdconf.h"
#include "wdlog.h"

#define MAX_CONF_LINE_LENGTH 1024

/* Read config file line like util_getline() */
static int _watchdog_readconf_line(char *line, int maxlen, FILE *file)
{
    int len = 0;
    int nlseen = 0;
    int src;
    int dst;
    char *bufp = line;

    if (feof(file)) {
        return -1;
    }

    while (!nlseen && (len < maxlen - 1)) {

        if (!fgets(bufp, maxlen - len, file))
            break;

        /* Scan what was just read */
        for (dst = 0, src = 0; bufp[src]; ++src) {
            /* Remove CRs */
            if (bufp[src] != '\r') {

                /* Replace NL with NUL */
                if (bufp[src] == '\n') {
                    nlseen = 1;
                    break;
                }

                /* Copy if removing CRs */
                if (src != dst) {
                    bufp[dst] = bufp[src];
                }

                ++dst;
            }
        }

        if (dst > 0) {
            /* Check for continuation */
            if (nlseen && (bufp[dst-1] == '\\')) {
                dst -= 1;
                nlseen = 0;
            }

            len += dst;
            bufp += dst;
        }
    }
                
    if ((len <= 0) && !nlseen) {
        return -1;
    }

    line[len] = '\0';

    return len;
}

static int
_watchdog_parse_conffile(char *conffile, 
                         watchdog_conf_info_t *info)
{
    FILE *cfile;
    char line[MAX_CONF_LINE_LENGTH];
    char *name, *value;
    int len;

    cfile = fopen(conffile, "r");
    if (!cfile) {
        if(guse_stderr) {
           fprintf(stderr, "Unable to open %s\n", conffile);
        }
	watchdog_log(LOG_ERR,
		     "Unable to open %s",
		     conffile);
        return -1;
    }

    while ((len = _watchdog_readconf_line(line, MAX_CONF_LINE_LENGTH, cfile)) >= 0) {
        name = line;
        if ((*name) == '#')
            continue;
        while((*name) && (isspace(*name))) 
            ++name;  /* skip whitespace */
        if (!(*name))
            continue;                /* blank line */
        for(value=name;(*value) && !isspace(*value); ++value); /* skip name */
        *value++ = '\0';                    /* terminate the name string */
        while((*value) && (isspace(*value))) ++value;  /* skip whitespace */
        if (value[strlen(value)-1] == '\n')
            value[strlen(value)-1] = '\0';

        if (!strcasecmp(name, "ExeFile")) {
            info->exeFile = strdup(value);
        }
        if (!strcasecmp(name, "ExeArgs")) {
            info->exeArgs = strdup(value);
        }
        if (!strcasecmp(name, "TmpDir")) {
            info->tmpDir = strdup(value);
        }
        if (!strcasecmp(name, "ExeOut")) {
            info->exeOut = strdup(value);
        }
        if (!strcasecmp(name, "ExeErr")) {
            info->exeErr = strdup(value);
        }
        if (!strcasecmp(name, "ExeBackground")) {
            info->exeBackground = atoi(value);
        }
        if (!strcasecmp(name, "ExeContext")) {
            info->exeContext = strdup(value);
        }
        if (!strcasecmp(name, "PidFile")) {
            info->pidFile = strdup(value);
        }
        if (!strcasecmp(name, "ChildPidFile")) {
            info->childPidFile = strdup(value);
        }
        if (!strcasecmp(name, "ChildSecurity")) {
            info->childSecurity = atoi(value);
        }
    }

    fclose(cfile);

    return 0;
}

watchdog_conf_info_t *
watchdog_parse(char *conffile)
{
    watchdog_conf_info_t *info;

    info = (watchdog_conf_info_t *)malloc(sizeof(watchdog_conf_info_t));
    if (!info) {
        if (guse_stderr) {
            fprintf(stderr, "Out of memory allocating watchdog info\n");
        }
	watchdog_log(LOG_ERR,
		     "Out of memory allocating watchdog info\n");
        return NULL;
    }
    memset(info, 0, sizeof(watchdog_conf_info_t));

    if (_watchdog_parse_conffile(conffile, info) < 0) {
        watchdog_confinfo_free(info);
        return NULL;
    }

    return info;
}

void
watchdog_confinfo_free(watchdog_conf_info_t *info)
{
    if (info->exeFile) {
        free(info->exeFile);
    }

    if (info->exeArgs) {
        free(info->exeArgs);
    }

    if (info->tmpDir) {
        free(info->tmpDir);
    }

    if (info->exeOut) {
        free(info->exeOut);
    }

    if (info->exeErr) {
        free(info->exeErr);
    }

    if (info->exeContext) {
        free(info->exeContext);
    }

    if (info->pidFile) {
        free(info->pidFile);
    }

    if (info->childPidFile) {
        free(info->childPidFile);
    }

    free(info);
}
