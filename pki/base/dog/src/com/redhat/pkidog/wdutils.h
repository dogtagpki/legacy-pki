#ifndef _wdutils_h
#define _wdutils_h

// Routines to set/get the file descriptor limit
int maxfd_get(void);
int maxfd_getmax(void);
int maxfd_set(int num_files);
int setFDNonInheritable(const int fd);

#endif /* _wdutils_h */

