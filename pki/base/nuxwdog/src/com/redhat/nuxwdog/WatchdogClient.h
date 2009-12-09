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

#ifndef _WatchdogClient_h_
#define _WatchdogClient_h_

#include <nspr4/nspr.h>                   // NSPR declarations
#include "wdservermessage.h"              // wdServerMessage class

/**
 * This class encapsulates the client-side communication of the watchdog
 * process that runs on Unix platforms.
 *
 * @author  $Author: chrisk $
 * @version $Revision: 1.1.2.13.4.1 $ $Date: 2002/03/08 16:27:04 $
 * @since   iWS5.0
 */

#ifdef __cplusplus
  class WatchdogClient
  {
        public:
        /**
         * Creates a listen socket binding it to the address specified in
         * the configuration. The watchdog process creates the listen sockets
         * on behalf of this method and passes the file descriptors to this
         * process.
         *
         * @returns      <code>PR_SUCCESS</code> if the initialization/creation 
         *               of the socket was successful. <code>PR_FAILURE</code> 
         *               if there was an error.
         */
        static PRStatus init(void);

        /**
         * Closes the watchdog connection.
         *
         * @returns <code>PR_SUCCESS</code> if the close
         *          of the socket was successful. <code>PR_FAILURE</code> 
         *          if there was an error.
         */
        static PRStatus close(void);

        /**
         * Reconnects to the watchdog (in a child process).
         *
         * @returns <code>PR_SUCCESS</code> if the reconnect was successful.
         *          <code>PR_FAILURE</code> if there was an error.
         */
        static PRStatus reconnect(void);

        /**
         * Sends the pathname of the PID file for this process to the watchdog.
         *
         * @param pidPath The pathname of the file containing the process ID
         * @returns       <code>PR_SUCCESS</code> if the path could be sent to
         *                the watchdog. <code>PR_FAILURE</code> if there was 
         *                an error.
         */
        static PRStatus sendPIDPath(const char* pidPath);

        /**
         * Asks the watchdog to create a listen socket on the specified IP
         * and port and return the file descriptor for the newly created
         * socket.
         *
         * @param lsName The ID of the listen socket in the configuration
         * @param ip     The address to which the listen socket should bind to
         *               or <code>NULL</code> if an <code>INADDR_ANY</code>
         *               socket is to be created
         * @param port   The port on which the newly created socket must listen
         *               for requests on.
         * @param family The address family, e.g. PR_AF_INET
         * @returns      A valid file descriptor corresponding to the listen
         *               socket. A negative value indicates that there was
         *               an error.
         */

        /* This does not compile on 64-bit.  Its currently unused so commenting
           out for now  - alee
        static PRInt32 getLS(const char* lsName, const char* ip,
                             const PRUint16 port, const PRUint16 family);
        */

        /**
         * Asks the watchdog to close the listen socket on the specified IP
         * and port.
         *
         * @param lsName The ID of the listen socket in the configuration
         * @param ip     The address to which the listen socket was bound to
         *               or <code>NULL</code> if an <code>INADDR_ANY</code>
         *               socket was created
         * @param port   The port on which the socket was listening for
         *               requests on.
         * @param family The address family, e.g. PR_AF_INET
         * @returns      <code>PR_SUCCESS</code> if the socket could be
         *               closed. <code>PR_FAILURE</code> indicates that there
         *               was an error.
         */
        static PRStatus closeLS(const char* lsName, const char* ip,
                             const PRUint16 port, const PRUint16 family);

        /**
         * Sends a message to the watchdog indicating that the server process
         * has completed its initialization.
         */
        static PRStatus sendEndInit(PRInt32 numprocs);

        /**
         * Requests a SSL module password from the watchdog.
         *
         * @param prompt   The prompt to use when asking for the password. Also
         *                 serves as an index in case the same password must be
         *                 retrieved multiple times (multiprocess mode/restart).
         * @param serial   Serial number of the password - the watchdog will 
         *                 reprompt if serial is greater than the one from the 
         *                 last one it stored
         * @param password Pointer to a string containing the password.
         * @returns        <code>PR_SUCCESS</code> if the password was received.
         *                 <code>PR_FAILURE</code> indicates that there was an 
         *                 error.
         */
        static PRStatus getPassword(const char *prompt, const PRInt32 serial,
                                    char **password);

        /**
         * Tell the watchdog that the server is finished with its business.
         *
         * @returns <code>PR_SUCCESS</code> if that watchdog acknowledged the
         *          terminate message. <code>PR_FAILURE</code> indicates that 
         *          there was an error.
         */
        static PRStatus sendTerminate(void);

        /**
         * Returns whether or not the watchdog process is running.
         */
        static PRBool isWDRunning(void);

        /**
         * Sends status from the reconfigure process to admin server via 
         * watchdog
         */
        static PRStatus sendReconfigureStatus(char *statusmsg);

        /**
         * Indicates server has finished reconfigure process to watchdog
         */
        static PRStatus sendReconfigureStatusDone();

        /**
         * Receive a message from the watchdog and return its message
         * type.
         */
        static WDMessages getAdminMessage(void);


        /**
         * Return the native file descriptor of the channel
         */
        static int getFD(void);

    private:

        /**
         * The communication channel to the watchdog process over which
         * commands are sent and responses received.
         */
        static wdServerMessage* wdMsg_;

        /**
         * Indicates whether the watchdog process is running or not.
         */
        static PRBool bIsWDRunning_;

        /**
         * Indicates whether the watchdog process is running or not.
         */
        static PRInt32 wdPID_;

       /**
        * Unix domain socket to connect to 
        */
        static char* udsName_;

        /**
         * Connects to the watchdog process via the Unix domain socket.
         *
         * This method assumes that the watchdog process is listening on
         * the Unix socket specified by <code>WDSOCKETNAME</code>.
         *
         * @returns <code>PR_SUCCESS</code> if the creation was successful.
         *          <code>PR_FAILURE</code> if an error occurred while
         *          connecting to the watchdog.
         */
        static PRStatus connectToWD(const PRInt32 pid);

	// Closes the specified connection to the watchdog

	static PRStatus closeWDConnection(wdServerMessage* wdConnection);

  };

  inline
  PRBool
  WatchdogClient::isWDRunning(void)
  {
      return WatchdogClient::bIsWDRunning_;
  }
#endif
     
#ifdef __cplusplus
extern "C" {
#endif

extern PRStatus cpp_call_WatchdogClient_init();

extern PRStatus cpp_call_WatchdogClient_sendEndInit(int numProcs);

extern char * cpp_call_WatchdogClient_getPassword(char *prompt, int serial);

extern PRStatus call_WatchdogClient_init();

extern PRStatus call_WatchdogClient_sendEndInit(int numProcs);

extern char * call_WatchdogClient_getPassword(char *prompt, int serial);

#ifdef __cplusplus
}
#endif
#endif /* _WatchdogClient_h_ */
