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
