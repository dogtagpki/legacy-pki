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

#include <sys/time.h>
#include <sys/resource.h>          // getrlimit()
#include <fcntl.h>

int
maxfd_get(void)
{
        struct rlimit rlim;
        if ( getrlimit(RLIMIT_NOFILE, &rlim) < 0) {
                return -1;
        }
        return rlim.rlim_cur;
}

int
maxfd_getmax(void)
{
        struct rlimit rlim;
        if ( getrlimit(RLIMIT_NOFILE, &rlim) < 0) {
                return -1;
        }
        return rlim.rlim_max;
}

int
maxfd_set(int num_files)
{
        struct rlimit rlim;
        int maxfd;

        if ( (maxfd = maxfd_getmax()) < 0)
                return -1;
        if ( maxfd < num_files)
                return -1;

        rlim.rlim_max = maxfd;
        rlim.rlim_cur = num_files;

        if ( setrlimit(RLIMIT_NOFILE, &rlim) < 0)
                return -1;

        return rlim.rlim_cur;
}

/*
 * Prevent the file descriptor from being inherited across CGI fork/exec()s
 */
int
setFDNonInheritable(const int fd)
{
    int status = 0;
    /* OR the FD_CLOEXEC flag with the existing value of the flag */
    int flags = fcntl(fd, F_GETFD, 0);
    if(flags == -1)
        status = -1;
    else
    {
        flags |= FD_CLOEXEC;
        if (fcntl(fd, F_SETFD, flags) == -1)
            status = -1;
    }
    return status;
}

