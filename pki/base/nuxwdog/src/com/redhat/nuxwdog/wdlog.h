/*
 * Log errors. 
 *
 */

#ifndef _WDLOG_H
#define _WDLOG_H

#include <syslog.h>

extern int guse_stderr;

void watchdog_openlog(void);
void watchdog_closelog(void);

#define watchdog_log watchdog_syslog
void watchdog_syslog(int priority, const char *fmt, ...);

#endif /* _WDLOG_H */
