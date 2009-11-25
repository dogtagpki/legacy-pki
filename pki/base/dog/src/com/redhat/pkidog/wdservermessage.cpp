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

#include <assert.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <iostream>
#include "sys/socket.h"
#include "sys/un.h"
#include "wdutils.h"
#include "wdservermessage.h"
#include <strings.h>

int lastmsgtyperecv=0;
int lastmsgtypesent=0;

const char * wdmsgNames[] = {
	"First",
	"GetPWD",
	"GetPWDreply",
	"GetLS",
	"GetLSreply",
	"CloseLS",
	"CloseLSreply",
	"EndInit",
	"EndInitreply",
	"SetPIDpath",
	"SetPIDpathreply",
	"Restart",
	"Restartreply",
	"Terminate",
	"Terminatereply",
	"Reconfigure",
	"Reconfigurereply",
	"GetReconfigStatus",
	"GetReconfigStatusreply",
	"ReconfigStatus",
	"ReconfigStatusreply",
	"ReconfigStatusDone",
	"ReconfigStatusDonereply",
	"EmptyRead",
	"Last"
};

// Used by reply messages to verify presence of message string
// 	0 => do nothing (or ignore for non-reply messages)
//	1 => string must be empty
//	2 => string must NOT be empty
int wdmsgCheckLength[] = { 
	0,  0,  2,  0,  0,  
	0,  1,  0,  1,  0,
	1,  0,  0,  0,  1,
	0,  1,  0,  0,  0,  
	0,  0,  0,  0,  0
};

wdServerMessage::wdServerMessage(int osFd) :
		msgFd(osFd)
{
}

wdServerMessage::~wdServerMessage() 
{
    if (msgFd != -1)
        close(msgFd);
}

pid_t parent_pid(pid_t p) 
{
    int ppid;
    char fname[80];
    FILE *pFile;
    
    sprintf(fname, "/proc/%d/stat", p);
    pFile = fopen(fname, "r");
    if (pFile != NULL) { 
        fscanf(pFile, "%*d %*s %*c %d", &ppid);
        fclose(pFile);
        return ppid;
    } else {
        return 0;
    }
}

// is p1 an ancestor of p2?
bool ancestor(pid_t p1, pid_t p2) 
{
    pid_t tmp = p2;
    while ((tmp != p1) && (tmp != 1)) 
       tmp = parent_pid(tmp);

    if (tmp == p1) {
        return true;
    }
 
    return false;
}

 
void
wdServerMessage::invalidate(void)
{
    msgFd = -1;
}

#ifdef AIX
extern "C" ssize_t recvmsg(int, struct msghdr *, int);
#endif

//  read a chunk of data from a child; return an indication of whether it worked
int wdServerMessage::recvMsg( int fdArray[], int fdArraySz, int child_security)
{

    msgLastError	= 0;
    msgbytesRead	= 0;
    msgNfds		= 0;

    // Read the length of the data that needs to be read into the iov
    // buffer of the recvmsg call
    const int headerSize = sizeof(int);
    int nBytes = 0;
    int nRead = 0;
    int dataLength = 0;
    while (nRead < headerSize)
    {
        nBytes = read(msgFd, (char *)&dataLength + nRead, headerSize - nRead);
        assert((headerSize-nRead)>=nBytes);
        nRead += nBytes;
        if (nBytes <= 0)
            return 0;
    }

    assert(nRead == headerSize);
    assert(dataLength >= 0);
    assert(dataLength <= (int) sizeof(msgbuff));

    // make a CHDR for fdArraySz * sizeof(int)
    size_t clen = sizeof(struct cmsghdr) + fdArraySz * sizeof(int);
    struct cmsghdr *chdr = (struct cmsghdr *)malloc(clen);
    //  build the recvmsg struct
    struct msghdr	msg;
    struct iovec	iov[1];

    memset( (char*)&msg, 0, sizeof(struct msghdr));
    memset( (char*)iov, 0, sizeof(struct iovec));

    msg.msg_name	= NULL;
    msg.msg_namelen	= 0;
    iov[0].iov_base	= msgbuff;
    iov[0].iov_len	= dataLength;
    msg.msg_iov		= iov;
    msg.msg_iovlen	= 1;
    msg.msg_control	= chdr;
    msg.msg_controllen	= clen;
#ifdef swift_DEBUG
    fprintf(stderr, 
	"BEFORE: msg.msg_control = 0x%08x, msg.msg_controllen = %d\n", 
		 msg.msg_control,	   msg.msg_controllen);
#endif

    //  receive a response; note that as we expect an iovec WITH
    //  fds coming back (yes, this is NOT a general purpose 
    //  model), getting partial data won't happen (FD passing 
    //  being the weird thing that it is)
    msgbytesRead = recvmsg( msgFd, &msg, 0 );

    struct ucred cr;
    socklen_t cl=sizeof(cr);

    if (getsockopt(msgFd, SOL_SOCKET, SO_PEERCRED, &cr, &cl)==0) {
       // fprintf(stderr, "Peer's pid=%d, uid=%d, gid=%d\n",
       //    cr.pid, cr.uid, cr.gid);
       // fprintf(stderr, "My Pid: %d My ppid: %d Peer Parent Pid: %d \n", getpid(), getppid(), parent_pid(cr.pid));
    }
    if ((child_security ==1) && (! ancestor(getpid(), cr.pid)) && (! ancestor(cr.pid, getpid()))) {
       fprintf(stderr, "Request not between parent and child with child security enabled! Dropping message ..");
       free(chdr);
       return 0;
    }

    if (msgbytesRead <= 0 ) {
        msgLastError = errno;
#ifdef swift_DEBUG
        if ( msgLastError == 0 ) {
            cerr << "wdServerMessage::recvMsg -- child process [fd " 
                 << msgFd << " failed" << endl;
        } else {
            cerr << "wdServerMessage::recvMsg - system error " 
                 << msgLastError << " on I/O to child process fd "
                 << msgFd << " (receiving fds)" << endl;
        }
#endif // swift_DEBUG
	free(chdr);
        return 0;
    }

    assert(msgbytesRead == dataLength);
    assert((int) iov[0].iov_len == dataLength);

#ifdef swift_DEBUG
    fprintf(stderr, 
	"AFTER: msg.msg_control = 0x%08x, msg.msg_controllen = %d\n", 
		msg.msg_control,	  msg.msg_controllen);
    char *p = (char *)msg.msg_control;
    for (int i=0; i<msg.msg_controllen; i++) {
	fprintf(stderr, "%02x%c", p[i], ((i+1)%8 == 0)? '\n': ' ');
    }
    fprintf(stderr, "\n");
    fprintf(stderr, 
	"chdr->cmsg_level = %d, chdr->cmsg_len = %d, chdr->cmsg_type = %d\n",
	 chdr->cmsg_level,	chdr->cmsg_len,	     chdr->cmsg_type);
    p = (char *)chdr;
    for (int i=0; i<chdr->cmsg_len; i++) {
	fprintf(stderr, "%02x%c", p[i], ((i+1)%8 == 0)? '\n': ' ');
    }
    fprintf(stderr, "\n");
#endif

    if (chdr->cmsg_level != SOL_SOCKET || chdr->cmsg_type != SCM_RIGHTS) {
	// No File Descriptors, just return
	free(chdr);
	return 1;
    }
    msgNfds = ((int)chdr->cmsg_len - (int)sizeof(struct cmsghdr)) / (int)sizeof(int);
    if (msgNfds > 0) {
	memcpy(fdArray, CMSG_DATA(chdr), msgNfds * sizeof(int));
    }

#ifdef swift_DEBUG
    cerr << "wdServerMessage::recvMsg -- everything hunkydory" << endl;
#endif
    free(chdr);
    return 1;
}

//  write a chunk of data to a child; return an indication of whether it worked
int wdServerMessage::writeMsg( const void * buf, size_t writeLen, int * sentLen)
{
    //  build the sendmsg struct
    struct msghdr msg;
    struct iovec iov[1];

    memset( (char*)&msg, 0, sizeof(struct msghdr));
    memset( (char*)iov, 0, sizeof(struct iovec));

    msg.msg_name	= NULL;
    msg.msg_namelen	= 0;
    iov[0].iov_base	= (char*)buf;
    iov[0].iov_len	= writeLen;
    msg.msg_iov		= iov;
    msg.msg_iovlen	= 1;
    msg.msg_control	= NULL;
    msg.msg_controllen	= 0;

    // Write the length of the data that is being sent in the iov
    // buffer of the sendmsg call
    const int headerSize = sizeof(int);
    int nBytes = 0;
    int nWritten = 0;
    while (nWritten < headerSize)
    {
        nBytes = write(msgFd, (char *)&writeLen + nWritten,
                       headerSize - nWritten);
        nWritten += nBytes;
        if (nBytes <= 0)
            return 0;
    }
    int n = sendmsg( msgFd, &msg, 0 );
    assert(n == (int) writeLen);
    if (n != (int) writeLen )
    {
        return 0;
    }
    else
        return 1;
}

int wdServerMessage::send_LS_to_Server( int connfd, WDMessages msg_type, int ls_fd )
{
    struct msghdr       msg;
    struct iovec        iov[1];

    memset( (char*)&msg, 0, sizeof(struct msghdr));
    memset( (char*)iov, 0, sizeof(struct iovec));

    int			clen;
    struct cmsghdr *	chdr;
    ssize_t             nsent;
    struct msgstruct {
	int		rsp;
	char		msgstr[10];
    } amsg;
    int                 rsp_desc[2];
    int                 ndesc = 0;

    amsg.rsp		= msg_type;
    if (ls_fd < 0 ) {
	// Put error value into the message string
	memcpy(amsg.msgstr, &ls_fd, sizeof(ls_fd));
    } else {
	ndesc		= 1;
	rsp_desc[0]	= ls_fd;
	memset(amsg.msgstr, 0, sizeof(ls_fd));
    }

    msg.msg_name	= NULL;
    msg.msg_namelen	= 0;

    iov[0].iov_base	= (char *) &amsg;
    iov[0].iov_len	= sizeof( amsg );
    msg.msg_iov		= iov;
    msg.msg_iovlen	= 1;

    clen = sizeof(struct cmsghdr) + ndesc * sizeof(int);
    chdr = (struct cmsghdr *)malloc(clen);

    chdr->cmsg_len	= clen;
    chdr->cmsg_level	= SOL_SOCKET;
    chdr->cmsg_type	= SCM_RIGHTS;
#if 0
    fprintf(stderr, 
"STUB: chdr->cmsg_level = %d, chdr->cmsg_len = %d, chdr->cmsg_type = %d\n",
	chdr->cmsg_level, chdr->cmsg_len, chdr->cmsg_type);
#endif
    memcpy(CMSG_DATA(chdr), rsp_desc, sizeof(int) * ndesc);

    msg.msg_control	= chdr;
    msg.msg_controllen	= clen;

    // Write the length of the data that is being sent in the iov
    // buffer of the sendmsg call
    const int headerSize = sizeof(int);
    int nBytes = 0;
    int nWritten = 0;
    int dataLength = iov[0].iov_len;
    while (nWritten < headerSize)
    {
        nBytes = write(msgFd, (char *)&dataLength + nWritten,
                       headerSize - nWritten);
        nWritten += nBytes;
        if (nBytes <= 0)
            break;
    }

    if (nBytes > 0)
    {
        nsent = sendmsg( connfd, &msg, 0 );
        if ( nsent < 0 ) {
        fprintf(stderr, "failure: error %d passing listen socket to server\n", errno);
        }
    }

    free(chdr);
    return 1;
}

int wdServerMessage::SendToWD (WDMessages messageType, const char * msgstring) {
        lastmsgtypesent = messageType;
	int rc		= 0;
	int sentlen	= 0;
	int strlength	= 0;
	int msglen	= sizeof(WDMessages);
	struct msgstruct {
		int	msgT;
		char	buff[WDMSGBUFFSIZE];
	} amsg;
	if (msgstring) strlength = strlen(msgstring);
	assert(strlength< WDMSGBUFFSIZE);
	amsg.msgT = messageType;
	if (strlength) {
		memcpy (amsg.buff, msgstring, strlength);
		amsg.buff[strlength]=0;
		msglen = msglen+strlength;
	}
	if ((messageType <= wdmsgFirst) || (messageType >= wdmsgLast)) {
		fprintf(stderr, "in SendToWD: Unimplemented message: %d\n",
			messageType);
		return 0;
	} else {
		// if (strstr(msg_name, "reply")) {
			// got bad request replies don't belong here
		// }
		rc = writeMsg((const void *)&amsg, msglen, &sentlen);
	}
	if (rc!=1) {
		fprintf(stderr, "failure: error %d sending %s message to watchdog", rc, wdmsgNames[messageType]);
		return 0;
	}
	return 1;
}

int wdServerMessage::SendToServer (WDMessages messageType, const char * msgstring) {

        lastmsgtypesent = messageType;
	int rc		= 0;
	int sentlen	= 0;
	int strlength	= 0;
	int msglen	= sizeof(WDMessages);
	struct msgstruct {
		int	msgT;
		char	buff[WDMSGBUFFSIZE];
	} amsg;
	if (msgstring) strlength = strlen(msgstring);
	assert(strlength < WDMSGBUFFSIZE);
	amsg.msgT = messageType;
	if ((messageType <= wdmsgFirst) || (messageType >= wdmsgLast)) {
		fprintf(stderr, "in SendToServer: Unimplemented message: %d\n",
			messageType);
		return 0;
	} else {
		int do_check = wdmsgCheckLength[messageType];
		// if (!strstr(msg_name, "reply") {
			// got bad request - only replies belong here
		// }
		if (strlength>0) {
			memcpy (amsg.buff, msgstring, strlength);
			amsg.buff[strlength]=0;
			msglen = msglen + strlength;
		}
		if (do_check) {
			if (do_check==1) {
				assert(strlength==0);
			} else if (do_check==2) {
				assert(strlength>0);
			} else {
				assert(0); // should not get here
			}
		}
	}
	if (messageType == wdmsgGetLSreply) {
		/* Special case: not just a simple text message */
//	fprintf(stderr, " msgstring in send_LS_to_Server: %d",*(int *)msgstring );
		rc = send_LS_to_Server( msgFd, messageType, *(int *)msgstring );
	} else {
		rc = writeMsg((const void *)&amsg, msglen, &sentlen);
	} 
	if (rc!=1) {
		fprintf(stderr, "failure: error %d sending %s message to server", rc, wdmsgNames[messageType]);
		return 0;
	}
	return 1;
}


char *	wdServerMessage::RecvFromWD	() {
	int fd;
	int fdarray[2];		/* for LS */
	int rc = recvMsg(fdarray,1,0); // child_security enforced from WD side 
	if (rc == 0) {
	    if (msgbytesRead==0) {
		// Found an empty read - treat as end of file/closed socket
		lastmsgtyperecv = msgType = wdmsgEmptyRead;
	    }
	    return NULL;
	}
	lastmsgtyperecv = msgType = *(WDMessages *)msgbuff;
	if ((msgType <= wdmsgFirst) || (msgType >= wdmsgLast)) {
		fprintf(stderr, "in RecvFromWD: Unimplemented message: %d\n",
			msgType);
		return NULL;
	} else {
		// if (!strstr(msg_name, "reply") {
			// got bad request - only replies belong here
		// }
	    if (msgType == wdmsgGetLSreply) {
		/* get reply: Listen Socket fd */
		// return code value is in msg string
		memcpy(&fd, msgbuff + sizeof(WDMessages), sizeof(fd));
		if (fd == 0) { // No error
			// Expected exactly 1 fd 
			fd = fdarray[0];
		}
		return (char *)fd;
	    } else if (msgType == wdmsgGetPWDreply) {
		/* returned string is password */
    		msgbuff[msgbytesRead]=0; /* Terminate string in buffer */
		return (char *)(msgbuff+sizeof(WDMessages));
	    } else if (msgType == wdmsgRestartreply) {
		/* returned string is error message if any */
		if (msgbytesRead==sizeof(WDMessages)) return NULL;
    		msgbuff[msgbytesRead]=0; /* Terminate string in buffer */
		return (char *)(msgbuff+sizeof(WDMessages));
	    } else if (msgType == wdmsgGetReconfigStatusreply) {
    		msgbuff[msgbytesRead]=0; /* Terminate string in buffer */
		return (char *)(msgbuff+sizeof(WDMessages));
	    }
	/* OK, no action need for others: just needed for synching up */
	}
	return NULL;
}

char *	wdServerMessage::RecvFromServer	(int child_security) {
	int fdarray[2];
	int rc = recvMsg(fdarray,1, child_security);
	if (rc == 0) {
	    if (msgbytesRead==0) {
		// Found an empty read - treat as end of file/closed socket
		lastmsgtyperecv = msgType = wdmsgEmptyRead;
	    }
	    return NULL;
	}
	lastmsgtyperecv = msgType = *(WDMessages*)msgbuff;
	if ((msgType <= wdmsgFirst) || (msgType >= wdmsgLast)) {
		fprintf(stderr, "in RecvFromServer: Unimplemented message: %d\n",
			msgType);
	} else {
		// if (strstr(msg_name, "reply")) {
			// got bad request replies don't belong here
		// }
		if (msgbytesRead >= (int) sizeof(WDMessages)) {
			msgbuff[msgbytesRead]=0; /* Terminate string in buffer */
		}
		return msgbuff+(sizeof(msgType));
	}
	return NULL;
}

int
wdServerMessage::getFD(void) const
{
    return msgFd;
}

#define SA struct sockaddr
int	ConnectToWDMessaging	(char * UDS_Name)
{
#include <sys/un.h>
	sockaddr_un servaddr;
	/* Connect to the Unix Domain socket */
	int msgFd = socket(AF_UNIX, SOCK_STREAM, 0);
	if ( msgFd == -1 ) {
		return -1;	// Socket failure
	}
	memset( (char *)&servaddr, 0, sizeof( servaddr ));
	servaddr.sun_family = AF_UNIX;
	strcpy( servaddr.sun_path, UDS_Name );
	if ( connect(msgFd, (SA *)&servaddr, sizeof(servaddr)) < 0) {
		return -2;	// Connect failure
	}
	return msgFd;
}
