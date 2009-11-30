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
 * WatchdogClient class implementation.
 *
 * @author  $Author: chrisk $
 * @version $Revision: 1.1.2.21.4.1 $ $Date: 2002/03/08 16:27:08 $
 * @since   iWS5.0
 */

#include <stdlib.h>                          // getenv()
#include <string.h>                          // memset(), strcpy()
#include <unistd.h>                          // getppid()
#include <sys/socket.h>                      // socket()
#include <sys/un.h>                          // sockaddr_un

#include "wdutils.h"                 // setFDNonInheritable
#include "WatchdogClient.h"       // WatchdogClient class

PRBool WatchdogClient::bIsWDRunning_ = PR_FALSE;
wdServerMessage* WatchdogClient::wdMsg_ = NULL;
char *udsName = NULL;

PRInt32 WatchdogClient::wdPID_ = -1;

PRStatus
WatchdogClient::init(void)
{
    PRStatus status = PR_SUCCESS;

    if (getenv("WD_PIPE_FD") != NULL) {
        WatchdogClient::bIsWDRunning_ = PR_TRUE;
        WatchdogClient::wdPID_ = getppid();
    }

    udsName = getenv("WD_PIPE_NAME");

    if (WatchdogClient::isWDRunning())
    {
        // Save the existing connection
        wdServerMessage* oldConnection = WatchdogClient::wdMsg_;

        // Open a new connection
        status = WatchdogClient::connectToWD(WatchdogClient::wdPID_);

        // Close the old one
        if (oldConnection)
        {
            WatchdogClient::closeWDConnection(oldConnection);
        }
    }
    return status;
}


PRStatus
WatchdogClient::close(void)
{
    PRStatus status = WatchdogClient::closeWDConnection(WatchdogClient::wdMsg_);
    WatchdogClient::wdMsg_ = NULL;
    return status;
}


PRStatus
WatchdogClient::reconnect(void)
{
    // Save the existing connection
    wdServerMessage* oldConnection = WatchdogClient::wdMsg_;

    // Create a new connection
    // we might be in a child worker process, so reuse the PID
    PRStatus status = WatchdogClient::connectToWD(WatchdogClient::wdPID_);

    // Close the old connection
    if (WatchdogClient::closeWDConnection(oldConnection) != PR_SUCCESS)
        return PR_FAILURE;

    return status;
}


PRStatus
WatchdogClient::closeWDConnection(wdServerMessage* wdConnection)
{
    if (wdConnection)
        delete wdConnection;
    return PR_SUCCESS;
}


PRStatus
WatchdogClient::connectToWD(const PRInt32 pid)
{
    PRStatus status = PR_SUCCESS;
    struct sockaddr_un address;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd >= 0)
    {
        memset((char *)&address, 0, sizeof(address));
        address.sun_family = AF_UNIX;
        strcpy(address.sun_path, udsName);

        if (connect(fd, (struct sockaddr*)&address, sizeof(address)) >= 0)
        {
            // Prevent the Unix domain socket descriptor from being inherited by
            // forks such as CGIs
            if (setFDNonInheritable(fd) == 0)
            {
                // the wdServerMessage class closes the fd in its destructor
                WatchdogClient::wdMsg_ = new wdServerMessage(fd);
                if (WatchdogClient::wdMsg_ == NULL)
                {
                    ::close(fd);
                    status = PR_FAILURE;
                    printf("Failure: Failure to get message in connectToWD\n");
                }
            }
        }
        else
        {
            status = PR_FAILURE;
            printf("Failure: Failed to connect to %s\n", udsName);
        }
    }
    else
    {
        status = PR_FAILURE;
        printf("Failure: Failed to get socket\n");
    }

    return status;
}

/*  Does not compile on 64 bit - unused so commenting out for now -- alee
PRInt32
WatchdogClient::getLS(const char* lsName, const char* ip, const PRUint16 port, const PRUint16 family)
{
    PRInt32 fd = -1;
    if (WatchdogClient::isWDRunning())
    {
        if (WatchdogClient::wdMsg_)
        {
            char params[1024];
            if (ip && strcmp(ip, "0.0.0.0"))
                sprintf(params, "%s,%s,%d,%d", lsName, ip, port, family);
            else
                sprintf(params, "%s,,%d,%d", lsName, port, family);

            if (WatchdogClient::wdMsg_->SendToWD(wdmsgGetLS, params) == 1)
            {
                fd = (PRInt32)(WatchdogClient::wdMsg_->RecvFromWD());
                WDMessages msgType = WatchdogClient::wdMsg_->getLastMsgType();
                if (msgType != wdmsgGetLSreply)
                {
                    printf("Failure: Error receiving response from watchdog\n");
                    fd = -1;
                }
            }
            else
            {
                printf("Failure: Error sending message to watchdog\n");
            }
        }
        else
        {
            printf("Failure: WatchdogClient incorrectly initialized\n");
        }
    }
    return fd;
}
*/

PRStatus
WatchdogClient::closeLS(const char* lsName, const char* ip, const PRUint16 port, const PRUint16 family)
{
    PRStatus status = PR_SUCCESS;
    if (WatchdogClient::isWDRunning())
    {
        if (WatchdogClient::wdMsg_)
        {
            char params[1024];
            if (ip && strcmp(ip, "0.0.0.0"))
            {
                sprintf(params, "%s,%s,%d,%d", lsName, ip, port, family);
            }
            else
                sprintf(params, "%s,,%d,%d", lsName, port, family);

            if (WatchdogClient::wdMsg_->SendToWD(wdmsgCloseLS, params) == 1)
            {
                WatchdogClient::wdMsg_->RecvFromWD();
                WDMessages msgType = WatchdogClient::wdMsg_->getLastMsgType();
                if (msgType != wdmsgCloseLSreply)
                {
                    printf("Failure: Error receiving response from watchdog in closeLS");
                    status = PR_FAILURE;
                }
            }
            else
            {
                printf("Failure: Error sending message to watchdog in closeLS");
                status = PR_FAILURE;
            }
        }
        else
        {
            printf("Failure: WatchdogClient incorrectly initialized in closeLS\n");
            status = PR_FAILURE;
        }
    }
    return status;
}

PRStatus
WatchdogClient::sendPIDPath(const char* pidPath)
{
    PRStatus status = PR_SUCCESS;
    if (WatchdogClient::isWDRunning())
    {
        if (WatchdogClient::wdMsg_)
        {
            if (pidPath == NULL)
            {
                status = PR_FAILURE;
                printf("Failure: PID path not set\n");
            }
            else
            {
                if (WatchdogClient::wdMsg_->SendToWD(wdmsgSetPIDpath, pidPath) == 1)
                {
                    char* msg = WatchdogClient::wdMsg_->RecvFromWD();
                    WDMessages msgType = WatchdogClient::wdMsg_->getLastMsgType();
                    if (msgType != wdmsgSetPIDpathreply)
                    {
                        status = PR_FAILURE;
                        printf("Failure: Error receiving response from watchdog in sendPidPath\n");
                    }
                }
                else
                {
                    status = PR_FAILURE;
                    printf("Failure: Error sending message to watchdog in sendPidPath");
                }
            }
        }
        else
        {
            status = PR_FAILURE;
            printf("Failure: WatchdogClient incorrectly initialized\n");
        }
    }
    return status;
}

PRStatus
WatchdogClient::sendEndInit(PRInt32 numprocs)
{
    PRStatus status = PR_SUCCESS;
    if (WatchdogClient::isWDRunning())
    {
        if (WatchdogClient::wdMsg_)
        {
            char msgstr[42];
            sprintf(msgstr,"%d",numprocs);
            if (WatchdogClient::wdMsg_->SendToWD(wdmsgEndInit, msgstr) == 1)
            {
                char* msg = WatchdogClient::wdMsg_->RecvFromWD();
                WDMessages msgType = WatchdogClient::wdMsg_->getLastMsgType();
                if (msgType != wdmsgEndInitreply)
                {
                    status = PR_FAILURE;
                    printf("Failure: Error receiving response from watchdog in sendEndInit\n");
                }
            }
            else
            {
                status = PR_FAILURE;
                printf("Failure: Error sending message to watchdog in sendEndInit");
            }
        }
        else
        {
            status = PR_FAILURE;
            printf("Failure: WatchdogClient incorrectly initialized\n");
        }
    }
    return status;
}

PRStatus
WatchdogClient::getPassword(const char *prompt, const PRInt32 serial,
                            char **password)
{
    PRStatus status = PR_FAILURE;
    char *msg;
    WDMessages msgType;
    char buf[1024]; // ugh

    *password = NULL;
    if (!WatchdogClient::isWDRunning()) {
        status = PR_SUCCESS;
        goto cleanup;
    }

    if (!WatchdogClient::wdMsg_) {
        printf("Failure: WatchdogClient incorrectly initialized in getpassword\n");
        goto cleanup;
    }

    sprintf(buf, "%d,%s", serial, prompt ? prompt : "Password: ");
    if (WatchdogClient::wdMsg_->SendToWD(wdmsgGetPWD, buf) < 0) {
        printf("Failure: Error sending message to watchdog in getPassword");
        goto cleanup;
    }

    msg = WatchdogClient::wdMsg_->RecvFromWD();
    msgType = WatchdogClient::wdMsg_->getLastMsgType();
    if (msgType != wdmsgGetPWDreply || !msg) {
        printf("Failure: Error receiving response from watchdog in getPassword\n");
        goto cleanup;
    }
    *password = strdup(msg);

    status = PR_SUCCESS;

cleanup:
    return status;
}

PRStatus
WatchdogClient::sendTerminate(void)
{
    PRStatus status = PR_FAILURE;
    char *msg;
    WDMessages msgType;

    if (!WatchdogClient::isWDRunning()) {
        status = PR_SUCCESS;
        goto cleanup;
    }

    if (!WatchdogClient::wdMsg_) {
        printf("Failure: WatchdogClient incorrectly initialized\n");
        goto cleanup;
    }

    if (WatchdogClient::wdMsg_->SendToWD(wdmsgTerminate, NULL) < 0) {
        printf("Failure: Error sending message to watchdog in sendTerminate");
        goto cleanup;
    }

    msg = WatchdogClient::wdMsg_->RecvFromWD();
    msgType = WatchdogClient::wdMsg_->getLastMsgType();
    if (msgType != wdmsgTerminatereply) {
        printf("Failure: Error receiving response from watchdog in sendTerminate\n");
        goto cleanup;
    }
    if (msg != NULL) {
        printf("Failure: WatchdogClient - non-empty Terminate response\n");
        goto cleanup;
    }

    status = PR_SUCCESS;
cleanup:
    if (status == PR_FAILURE)
        printf("Failure: WatchdogClient - sendTerminate failed\n");
    return status;
}

PRStatus
WatchdogClient::sendReconfigureStatus(char *statusmsg)
{
    PRStatus status = PR_SUCCESS;
    if (WatchdogClient::isWDRunning())
    {
        if (WatchdogClient::wdMsg_)
        {
            if (WatchdogClient::wdMsg_->SendToWD(wdmsgReconfigStatus, statusmsg) == 1)
            {
                char* msg = WatchdogClient::wdMsg_->RecvFromWD();
                WDMessages msgType = WatchdogClient::wdMsg_->getLastMsgType();
                if (msgType != wdmsgReconfigStatusreply)
                {
                    status = PR_FAILURE;
                    printf("Failure: Error receiving response from watchdog in sendReconfigureStatus\n");
                }
            }
            else
            {
                status = PR_FAILURE;
                printf("Failure: Error sending message to watchdog in sendReconfigureStatus\n");
            }
        }
        else
        {
            status = PR_FAILURE;
            printf("Failure: WatchdogClient incorrectly initialized\n");
        }
    }
    if (status == PR_FAILURE)
        printf("Failure: WatchdogClient - sendReconfigureStatus failed\n");
    return status;
}

PRStatus
WatchdogClient::sendReconfigureStatusDone()
{
    PRStatus status = PR_SUCCESS;
    if (WatchdogClient::isWDRunning())
    {
        if (WatchdogClient::wdMsg_)
        {
            if (WatchdogClient::wdMsg_->SendToWD(wdmsgReconfigStatusDone, NULL) == 1)
            {
                char* msg = WatchdogClient::wdMsg_->RecvFromWD();
                WDMessages msgType = WatchdogClient::wdMsg_->getLastMsgType();
                if (msgType != wdmsgReconfigStatusDonereply)
                {
                    status = PR_FAILURE;
                    printf("Failure: Error receiving response from watchdog in sendReconfigureStatusDone\n");
                }
            }
            else
            {
                status = PR_FAILURE;
                printf("Failure: Error sending message to watchdog in sendReconfigureStatusDone\n");
            }
        }
        else
        {
            status = PR_FAILURE;
            printf("Failure: WatchdogClient incorrectly initialized\n");
        }
    }
    if (status == PR_FAILURE)
        printf("Failure: WatchdogClient - sendReconfigureStatusDone failed\n");
    return status;
}

WDMessages
WatchdogClient::getAdminMessage()
{
    WDMessages msgType = wdmsgEmptyRead;
    if (WatchdogClient::isWDRunning())
    {
        if (WatchdogClient::wdMsg_)
        {
            char* msg = WatchdogClient::wdMsg_->RecvFromWD();
            msgType = WatchdogClient::wdMsg_->getLastMsgType();
        }
        else
        {
            printf("Failure: WatchdogClient incorrectly initialized\n");
        }
    }
    return msgType;
}

int
WatchdogClient::getFD(void)
{
    int fd = -1;

    if (wdMsg_ != NULL)
        fd = wdMsg_->getFD();

    return fd;
}

PRStatus cpp_call_WatchdogClient_init() {
    return WatchdogClient::init();
}

PRStatus cpp_call_WatchdogClient_sendEndInit(int numProcs) {
    return WatchdogClient::sendEndInit(numProcs);
}

char * cpp_call_WatchdogClient_getPassword(char *prompt, int serial) {
    char *password = NULL;
    if (prompt== NULL) {
        return NULL;
    }

    PRStatus status = WatchdogClient::getPassword(prompt, serial, &password);

    if (status == PR_SUCCESS) {
        return password;
    } else {
        return NULL;
    }
}


