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
**
** Watchdog Listen Socket Manager
**
** This module manages the list of sockets which the server
** listens on for requests.
**
**/

#ifndef _WDLSMANAGER_
#define _WDLSMANAGER_

#include <assert.h>
#ifdef Linux
/* Needed for extra defines */
#include <sys/poll.h>
# define POLLRDNORM     0x040           /* Normal data may be read.  */
# define POLLRDBAND     0x080           /* Priority data may be read.  */
# define POLLWRNORM     0x100           /* Writing now will not block.  */
# define POLLWRBAND     0x200           /* Priority data may be written.  */
# define POLLMSG        0x400
#else
#include <poll.h>
#endif

#include "wdservermessage.h"

#ifdef  FEAT_NOLIMITS
#define INITIAL_LS_SIZE 200
#else
/* This is a hard limit for FastTrack that won't be exceeded in the code */
#define INITIAL_LS_SIZE 5
#endif

#define INITIAL_PA_SIZE 200

typedef struct _wdLS_entry {
        char *  ls_name;
        char *  ipaddress;
        int     port;
        int     fd;
        int     listen_queue_size;
        int     send_buff_size;
        int     recv_buff_size;
} wdLS_entry;

typedef struct _msg_info {
        wdServerMessage * wdSM;
        int     _waiting;       /* message is waiting to be read                */
} msg_info;

class wdLSmanager {
  public:
        wdLSmanager();
        ~wdLSmanager();
        const char *  InitializeLSmanager     (char * UDS_Name);
        int     getNewLS                (char * new_ls_name, char * new_IP,
                                         int new_port, int family);
        int     removeLS                (char * new_ls_name, char * new_IP,
                                         int new_port, int family);
        wdLS_entry * ls_table;          /* Table of Listen Sockets      */

        int     Reset_Poll_Entry        (int index);
        int     Add_Poll_Entry          (int socket);
        int     Wait_for_Message        ();
        struct pollfd * pa_table;       /* Table of Poll fds            */
        int *   _heard_restart;         /* heard restart on this fd     */
        msg_info * msg_table;           /* Table of active messages     */

        void    unbind_all              (void);

  private:
        void    Initialize_new_ls_table (int table_start, int table_size);
        int     lookupLS                (char * new_ls_name, char * new_IP,
                                         int new_port, int family);
        int     addLS                   (char * ls_name, char * ip, 
                                         int port, int family, int new_fd); 
        int     create_new_LS           (char * UDS_Name, char * new_IP, 
                                         int new_port, int family);

        int     ls_count;               /* Number of entries entered    */
        int     ls_table_size;          /* Number of entries allocated  */
        int     msg_listener_fd;        /* socket for talking to server */

        int     pa_count;               /* Number of entries used       */
        int     pa_table_size;          /* Number of entries allocated  */

        /* Default values for entry fields */
        char *  default_ipaddress;
        int     default_port;
};

#endif /*       _WDLSMANAGER_   */
