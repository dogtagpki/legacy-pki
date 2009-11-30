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
**
** Watchdog Listen Socket Manager
**
** This module manages the list of sockets on which the server
** listens for requests.
**
**/

#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include "wdservermessage.h"
#include "wdlsmgr.h"
#include <nspr4/nspr.h>
#include <nspr4/private/pprio.h>        // PR_FileDesc2NativeHandle()

#define SOCKOPTCAST const char *

#ifndef AF_NCA
#define AF_NCA 28
#endif

wdLSmanager::wdLSmanager():
ls_table(NULL), pa_table(NULL),
ls_count(0), ls_table_size(INITIAL_LS_SIZE),
pa_count(0), pa_table_size(INITIAL_PA_SIZE),
default_ipaddress(NULL),
default_port(80)
{
}

wdLSmanager::~wdLSmanager()
{
    /* Close all the open Listen Sockets */
    unbind_all();
    ls_count = 0;
    /* Free up data structures */
    if (pa_table)
        free(pa_table);
    if (ls_table)
        free(ls_table);
}

void wdLSmanager::unbind_all(void)
{
    int i;
    if (ls_table != NULL) {
        for (i = 0; i < ls_count; i++) {
            if (ls_table[i].fd != -1) {
                close(ls_table[i].fd);
                ls_table[i].fd = -1;
            }
        }
    }
}

int wdLSmanager::create_new_LS(char *UDS_Name, char *new_IP, int new_port, int family)
{
    int one = 1; /* optval for setsockopt */
    int rv = 0;
    int new_fd;
    PRFileDesc *fd = NULL;

    /* Create and bind socket */
    if (family == AF_UNIX || family == AF_NCA) {
        /* Create an AF_UNIX or AF_NCA socket */
        new_fd = socket(family, SOCK_STREAM, 0);
        if (new_fd < 0) {
            return -errno;
        }

        /* Make the socket Non-Blocking */
        int flags = fcntl(new_fd, F_GETFL, 0);
        fcntl(new_fd, F_SETFL, (flags & ~O_NONBLOCK));

        setsockopt(new_fd, SOL_SOCKET, SO_REUSEADDR, (SOCKOPTCAST)&one, sizeof(one));

        if (family == AF_UNIX) {
            /* Bind to the appropriate AF_UNIX sockaddr */
            struct sockaddr_un suna;
            if (strlen(UDS_Name) > sizeof(suna.sun_path))
                return -ENAMETOOLONG;
            memset(&suna, 0, sizeof(suna));
            suna.sun_family = AF_UNIX;
            strcpy(suna.sun_path, UDS_Name);
            rv = bind(new_fd, (struct sockaddr*)&suna, sizeof(suna));
        } else {
            setsockopt(new_fd, IPPROTO_TCP, TCP_NODELAY, (SOCKOPTCAST)&one, sizeof(one));

            /* AF_NCA's sockaddr looks just like like AF_INET's */
            struct sockaddr_in sina;
            memset(&sina, 0, sizeof(sina));
            sina.sin_family = AF_NCA;
            sina.sin_addr.s_addr = new_IP ? inet_addr(new_IP) : htonl(INADDR_ANY);
            sina.sin_port = htons(new_port);
            rv = bind(new_fd, (struct sockaddr*)&sina, sizeof(sina));
        }

        if (rv < 0) {
            /* Error binding */
            close(new_fd);
            return -errno;
        }

    } else {
        /* PR_AF_INET or PR_AF_INET6 */
        PRNetAddr address;
        PRSocketOptionData optdata;

        PR_InitializeNetAddr(PR_IpAddrNull, new_port, &address);
        if (new_IP) {
            if (PR_StringToNetAddr(new_IP, &address) != PR_SUCCESS) {
                return -EINVAL;
            }
        } else {
            PR_SetNetAddr(PR_IpAddrAny, family, new_port, &address);
        }

        /* open a new socket using the address family of the IP address */
        PR_SetError(0, 0);
        fd = PR_OpenTCPSocket(address.raw.family);
        if (fd == NULL) {
            rv = PR_GetOSError();
            if (!rv)
                rv = EPROTONOSUPPORT;
            return -rv;
        }

        // this, of course, needs to be done before the bind()
        optdata.option = PR_SockOpt_Reuseaddr;
        optdata.value.reuse_addr = PR_TRUE;
        PR_SetSocketOption(fd, &optdata);

        // OSF1 V5.0 1094 won't bind to anything other than INADDR_ANY unless
        // we zero this.  NSPR 4.1.1-beta's PR_StringToNetAddr() writes junk in
        // here.
        if (address.raw.family == PR_AF_INET) {
            memset(address.inet.pad, 0, sizeof(address.inet.pad));
        }

        /* Bind socket address */
        PR_SetError(0, 0);
        if (PR_Bind(fd, &address) != PR_SUCCESS) {
            PR_Close(fd);
            rv = PR_GetOSError();
            if (!rv)
                rv = EPROTONOSUPPORT;
            return -rv;
        }

        new_fd = PR_FileDesc2NativeHandle(fd);
    }
    return new_fd;  /* Success */
}

void wdLSmanager::Initialize_new_ls_table(int table_start, int table_size)
{
    int i;
    for (i = table_start; i < table_size; i++) {
        ls_table[i].fd = -1;
        ls_table[i].port = -1;
        ls_table[i].ipaddress = NULL;
        ls_table[i].listen_queue_size = -1;
        ls_table[i].send_buff_size = -1;
        ls_table[i].recv_buff_size = -1;
    }
}

const char *wdLSmanager::InitializeLSmanager(char *UDS_Name)
{
    int i;

    /* allocate initial Listen Socket table */
    ls_table = (wdLS_entry *) malloc(sizeof(wdLS_entry) * ls_table_size);
    if (ls_table == NULL) {
        return "Allocate of Listen Socket table failed";
    }

    Initialize_new_ls_table(0, ls_table_size);

    /* open Listener on Unix domain socket */
    msg_listener_fd = create_new_LS(UDS_Name, NULL, 0, AF_UNIX);
    if (msg_listener_fd < 0) {
        if (msg_listener_fd == -ENAMETOOLONG) {
            errno = ENAMETOOLONG;
            return "Temporary directory path too long";
        }
        return "Failed to create Listen Socket for messages to server";
    }

    /* Listen on socket */
    if (listen(msg_listener_fd, 64) < 0) {
        return "Failed to listen on Listen Socket for messages to server";
    }

    /* Initialize Messages tables */
    msg_table = (msg_info *) malloc(pa_table_size * sizeof(msg_info));
                             // ^ - just make same size as Poll table
    if (msg_table == NULL) {
        return "Allocate of Messages table failed";
    }

    /* Initialize Poll table */
    pa_table =
        (struct pollfd *) malloc(pa_table_size * sizeof(struct pollfd));
    if (pa_table == NULL) {
        return "Allocate of Poll array failed";
    }

    /* Initialize table to mark fd as from Admin server */
    _heard_restart = (int *) malloc(pa_table_size * sizeof(int));
    if (_heard_restart == NULL) {
        return "Allocate of _heard_restart failed";
    }
    for (i = 0; i < pa_table_size; i++) {
        pa_table[i].fd = -1;
        pa_table[i].revents = 0;
        pa_table[i].events = 0;
        _heard_restart[i] = 0;
        msg_table[i].wdSM = NULL;
        msg_table[i]._waiting = 0;
    }
    if (Add_Poll_Entry(msg_listener_fd) == 0) {
        return "Failed to add first entry to Poll table";
    }
    return NULL;
}

int wdLSmanager::Wait_for_Message()
{
    int ready = poll(pa_table, pa_count, 10000 /* ten seconds */ );
    if (ready == 0)          /* Timeout - go back and loop       */
        return ready;
    else if (ready == -1) {  /* Error ?? */
        return ready;
    } else {                 /* > 0 means found events       */
        int i, count;
        count = ready;
        for (i = 0; i < pa_table_size; i++) {
            if (pa_table[i].fd > 0) {  // only look at valid entries
                if (pa_table[i].revents != 0) { // Found events
                    if (pa_table[i].revents & POLLHUP) { // Disconnect
                        msg_table[i]._waiting = -1;
                        // Delete msg_table object??
                    } else if ((i == 0) && (pa_table[i].revents & POLLIN)) {
                        // ready for Accept
                        int newfd = accept(pa_table[i].fd, NULL, 0);
                        if (newfd == -1) {
                            return -errno;
                        }
                        if (Add_Poll_Entry(newfd) == 0) {
                            return -3; // Error ??
                        }
                        ready--; // don't count this event as a message
                    } else if ((pa_table[i].revents & POLLRDBAND) ||
                               (pa_table[i].revents & POLLIN) ||
                               (pa_table[i].revents & POLLPRI)) {
                        // ready for Read 
                        assert(msg_table[i]._waiting == 0);
                        // shouldn't be one already waiting
                        /* Create messaging to server */
                        if (msg_table[i].wdSM == NULL) {
                            wdServerMessage *wdSM = new
                                wdServerMessage(pa_table[i].fd);
                            if (wdSM == NULL) {
                                // retstr="Failed to start message listener";
                                return -4;
                            } else {
                                msg_table[i].wdSM = wdSM;
                            }
                        }
                        msg_table[i]._waiting = 1;
                    }
                    pa_table[i].revents = 0;
                    count--;
                    if (count == 0)
                        break;
                }
            }
        }
        return ready;
    }
}

int wdLSmanager::Reset_Poll_Entry(int index)
{
    pa_table[index].fd = -1;
    pa_table[index].events = 0;
    return 1;
}

int wdLSmanager::Add_Poll_Entry(int socket)
{
    int i;
    for (i = 0; i < pa_table_size; i++) {
        if (pa_table[i].fd == -1) {
            // Found empty element: set it there
            pa_table[i].fd = socket;
            pa_table[i].events =
                (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI);
            pa_table[i].revents = 0;
            _heard_restart[i] = 0;
            if ((i + 1) > pa_count)
                pa_count = i + 1;
            return 1;
        }
    }
    // Ran out of poll entries without finding any empty- resize??
    return 0;
}

int wdLSmanager::lookupLS(char *new_ls_name, char *new_IP, int new_port,
                          int family)
{
    int i;
    char *pzServerIp;
    int serverPort;

    /* Lookup the entry */
    /* Only look at IP and Port */
    for (i = 0; i < ls_count; i++) {
        pzServerIp = ls_table[i].ipaddress;
        serverPort = ls_table[i].port;
        if (new_port == serverPort) {
            if (new_IP == NULL) {
                if (pzServerIp == NULL) {
                    return i; /* found it */
                }
            } else {
                if (pzServerIp && strcmp(new_IP, pzServerIp) == 0) {
                    return i; /* found it */
                }
            }
        }
    }
    /* No match - return not found */
    return -1;
}

int wdLSmanager::getNewLS(char *new_ls_name, char *new_IP, int new_port,
                          int family)
{
    int new_fd; /* socket temporary file descriptor */

    int i = lookupLS(new_ls_name, new_IP, new_port, family);
    if (i >= 0) {
        /* found it: return LS */
        return ls_table[i].fd;
    }

    /* Listen Socket not found: must add a new one */

    new_fd = create_new_LS(NULL, new_IP, new_port, family);
    if (new_fd < 0) {
        char *oserr = strerror(-new_fd);
        if (!oserr)
            oserr = "Unknown error";
        if (new_IP) {
            fprintf(stderr, 
                    "startup failure: could not bind to %s:%d (%s)\n",
                    new_IP, new_port, oserr);
        } else {
            fprintf(stderr,
                    "startup failure: could not bind to port %d (%s)\n",
                    new_port, oserr);
        }
        new_fd = -errno;
    } else {
        // Success: add to table 
        if (addLS(new_ls_name, new_IP, new_port, family, new_fd) == 0) {
            fprintf(stderr, "Could not add to LS table\n");
            new_fd = -new_fd;
        }
    }
    return new_fd;
}

int wdLSmanager::addLS(char *ls_name, char *ip, int port, int family, 
                       int new_fd)
{
    /* Add one Listen Socket to table */

    int i, index;

    /* First search for an empty table entry */
    for (i = 0; i < ls_count; i++) {
        if (ls_table[i].port == -1)
            break;
    }
    if (i < ls_count) {
        index = i;
    } else {
        /* None found - is table full? */
        if (ls_count >= ls_table_size) { /* then make some more */
#ifdef        FEAT_NOLIMITS
            int new_size = ls_table_size * 2;
            ls_table = (wdLS_entry *) realloc(ls_table,
                                              sizeof(wdLS_entry) *
                                              new_size);
            if (ls_table == NULL) {
                return 0;
            }
            Initialize_new_ls_table(ls_table_size, new_size);
            ls_table_size = new_size;
#else
            /* Don't allow more than fixed limit */
            return 0;
#endif
        }
        index = ls_count++;
    }
    ls_table[index].ls_name = strdup(ls_name);
    if (ip)
        ls_table[index].ipaddress = strdup(ip);
    else
        ls_table[index].ipaddress = ip;
    ls_table[index].port = port;
    ls_table[index].fd = new_fd;
    return 1;
}

int wdLSmanager::removeLS(char *new_ls_name, char *new_IP, int new_port,
                          int family)
{
    int i = lookupLS(new_ls_name, new_IP, new_port, family);
    if (i >= 0) {
        /* found it: close fd */
        close(ls_table[i].fd);
        /* remove from table : port will never match  */
        ls_table[i].port = -1;
        return 1;
    }
    /* Not found - return error */
    return i;
}
