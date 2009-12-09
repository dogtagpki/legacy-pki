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

//
// File:    wdservermessage.h
//
// Description:
//      This header file is used to manage the message traffic
//	between the watchdog and server.
//

#ifndef __WDSERVERMESSAGE_H_ 
#define __WDSERVERMESSAGE_H_ 

//
//  this class encapsulates the access to messages send between the
//  watchdog and server processes.
//
// 	Server requests to watchdog

typedef enum {
	wdmsgFirst,			// unused
	wdmsgGetPWD,			// get Password from terminal
	wdmsgGetPWDreply,		// reply to Password request
	wdmsgGetLS,			// get Listen Socket, return fd
	wdmsgGetLSreply,		// reply to Listen Socket request
	wdmsgCloseLS,			// close Listen Socket
	wdmsgCloseLSreply,		// reply to close Listen Socket
	wdmsgEndInit,			// done with server initialization (can clean
					// 	up watchdog and terminal)
	wdmsgEndInitreply,		// reply to initialization done message
	wdmsgSetPIDpath,		// get PID path from server
	wdmsgSetPIDpathreply,		// reply to PID path request
	wdmsgRestart,			// Admin message to restart servers
	wdmsgRestartreply,		// reply to Admin message to restart servers
	wdmsgTerminate,			// clean shut down from server
	wdmsgTerminatereply,		// reply to server that Terminate received
	wdmsgReconfigure,		// Admin message to start a reconfiguration
	wdmsgReconfigurereply,		// reply to Admin reconfig message
	wdmsgGetReconfigStatus,		// get status from reconfiguration
	wdmsgGetReconfigStatusreply,	// reply to get status reconfig message
	wdmsgReconfigStatus,		// status from server from reconfiguration
	wdmsgReconfigStatusreply,	// reply to status from server
	wdmsgReconfigStatusDone,	// done sending status from reconfiguration
	wdmsgReconfigStatusDonereply,	// reply to done sending status
	wdmsgEmptyRead,			// Empty read receiving msg => closed socket
	wdmsgLast			// unused
} WDMessages;

#define WDMSGBUFFSIZE	2048

#define WDSOCKETNAME	"nuxwdog."

extern int ConnectToWDMessaging	(char * UDS_Name);

#ifdef __cplusplus
class wdServerMessage { 

  public:
    //  constructor; requires a valid fd as returned from a listener
    wdServerMessage(int osFd );
    ~wdServerMessage(void);

    int		getLastIOError()	{ return msgLastError;	}
    int		getNbrWrites()		{ return msgNbrWrites;	}
    WDMessages	getLastMsgType()	{ return msgType;	}

    //	These functions are used by the server to talk to the watchdog
    //
    int		SendToWD	(WDMessages msgtype, const char * msgstring);
    char *	RecvFromWD	();
    //
    //	These functions are used by the watchdog to talk to the server
    //
    int		SendToServer	(WDMessages msgtype, const char * msgstring);
    char *	RecvFromServer	(int child_security);


    // Returns the underlying handle to the socket
    int getFD(void) const;

    // Sets msgFd to an invalid value so that the descriptor will NOT
    // be closed in the destructor
    void invalidate(void);

  private:
    int		msgFd;			//  os fd
    int		msgLastError;		//  last errno
    int		msgNbrWrites;		//  number of WriteMsgs done 
    int		msgbytesRead;		//  number of bytes read
    int		msgNfds;		//  number of FDs received
    char	msgbuff[WDMSGBUFFSIZE];	//  recvmsg buffer

    WDMessages	msgType;		//  Type from last message received
    //  I/O operations
    //      these return a boolean indication of whether the 
    //      I/O was successful; if not, the child can be
    //      considered dead and should be set 'dead' and deleted
    //
    int	recvMsg			( int fdArray[], int fdArraySz, int child_security);
    int	writeMsg		( const void * buf, size_t writeLen, int * sentLen );
    int send_LS_to_Server	( int connfd, WDMessages msg_type, int ls_fd );
};
#endif

#endif // __WDSERVERMESSAGE_H_ 
