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
 * UNIX watchdog process
 *
 * The UNIX watchdog knows how to do the following
 *       - start the server
 *       - listen for specific messages from servers
 *       - create and destroy listen sockets
 *       - log its pid in the pidfile
 *       - detect a server crash and restart the server
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <pwd.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <grp.h>
#include <selinux/context.h>
#include <selinux/selinux.h>

#include <nspr4/nspr.h>
#include "wdutils.h"           
#include "wdconf.h"
#include "wdsignals.h"
#include "wdlog.h"
#include "wdlsmgr.h"

int _watchdog_death;
int _watchdog_sigterm_was_sent;
int _watchdog_server_init_done;
int _watchdog_server_death;
int _watchdog_server_restart;
int _watchdog_server_start_error = 1;
int _watchdog_stop_waiting_for_messages		= 0;
int _watchdog_admin_is_waiting_for_reply	= 0;
int _watchdog_admin_waiting_for_reconfig_status	= 0;
int n_reconfig  = 0;
int n_reconfigDone  = 0;
int guse_stderr = 0;

int server_pid = -1;

static char *pidpath = NULL;
static watchdog_conf_info_t *confinfo = NULL;
static char *tempdir = NULL;
int child_security = 0;

void watchdog_exit(int status);

char	UDS_NAME[PATH_MAX];
int	detach = 1;

wdLSmanager	LS;

char errmsgstr[1024];

#define RESTART_ON_EXIT_CODE    40

//
// The unix domain socket connection (to the primordial process) that 
// is used for sending Admin commands (e.g reconfigure) initiated by 
// the watchdog. Using the channel avoids having to use signals between
// the processes and also allows for returning status .
//
wdServerMessage* adminChannel = NULL;

void
watchdog_error(const char * msgstring)
{
    if (guse_stderr) {
        fprintf(stderr, "failure: %s (%s)\n" , msgstring, strerror(errno));
    }
    watchdog_log(LOG_ERR, msgstring); 
}

void
watchdog_check_status(int server_stat)
{
    /* See if the server exited */
    if (WIFEXITED(server_stat)) {
        int exit_code = WEXITSTATUS(server_stat);
        /*
         * If the server exited with non-zero status, terminate the
         * watchdog.
         */
        if (exit_code) {
            sprintf(errmsgstr, "server exit: status %d", exit_code);
            watchdog_error(errmsgstr);

            /* Maybe someone may need this option */
            if (getenv("UXWDOG_RESTART_ON_EXIT") || exit_code == RESTART_ON_EXIT_CODE) {
                /* Return to restart the server */
                return;
            }
            watchdog_exit(exit_code);
        }
    }

    /* See if the server died for reasons other than a restart */
    if (WIFSIGNALED(server_stat)) {
        int exit_sig = WTERMSIG(server_stat);

        /*
         * If the signal is not SIGTERM or the server is not being
         * restarted, report the signal, and if UXWDOG_NO_AUTOSTART
         * is set, terminate the watchdog.
         */

        if (!_watchdog_server_restart ||
            ( ( exit_sig != SIGTERM )
                )) {
            char *no_autostart = getenv("UXWDOG_NO_AUTOSTART");
            if (no_autostart) {
                sprintf(errmsgstr,
                        "server terminated (signal %d): watchdog exiting",
                        exit_sig);
                watchdog_error(errmsgstr);
                watchdog_exit(1);
            }
            sprintf(errmsgstr, "server terminated (signal %d)", exit_sig);
            if (_watchdog_server_init_done) {
                strcat(errmsgstr, ": watchdog is restarting it");
            }
            watchdog_error(errmsgstr);
            putenv((char *) "WD_RESTARTED=1");
        }
    }
}


int
_watchdog_logpid(char *path) 
{
    FILE *pidfile;
    int pid = getpid();
    char buff[24];
    int bytesWritten = -1;
    struct stat finfo;

    // First check if pidfile already exists:
    if(!stat(path, &finfo)) {
        FILE *p = fopen(path, "r");
        if(p) {
	    //  Is a watchdog already running here?
	    int z;
            if ((fscanf(p, "%d\n", &z)) != -1) {
                pid_t foundpid = (pid_t) z;
                if(kill(foundpid, 0) != -1)
                    /* watchdog is already running */
                    return -2;
            }
	    fclose(p);
        }
    }

    sprintf(buff, "%d\n", pid);
    pidfile = fopen(path, "w");
    if (pidfile == NULL) {
        return -1;
    }

    setbuf(pidfile, NULL); 
    bytesWritten = fprintf(pidfile, "%s", buff);
    fclose(pidfile);
    if (bytesWritten != (int) strlen(buff)) {
        return -1;
    }

    if (pidpath) {
        free(pidpath);
    }
    pidpath = strdup(path);

    return 0;
}

int 
_watchdog_logchildpid(char *path, int pid)
{
    FILE *pidfile;
    char buff[24];
    int bytesWritten = -1;
    struct stat finfo;

    // First check if pidfile already exists:
    if(!stat(path, &finfo)) {
        FILE *p = fopen(path, "r");
        if(p) {
            //  Is the server already running?
            int z;
            if ((fscanf(p, "%d\n", &z)) != -1) {
                pid_t foundpid = (pid_t) z;
                if(kill(foundpid, 0) != -1)
                    /* watchdog is already running */
                    return -2;
            }
            fclose(p);
        }
    }

    sprintf(buff, "%d\n", pid);
    pidfile = fopen(path, "w");
    if (pidfile == NULL) {
        return -1;
    }

    setbuf(pidfile, NULL);
    bytesWritten = fprintf(pidfile, "%s", buff);
    fclose(pidfile);
    if (bytesWritten != (int) strlen(buff)) {
        return -1;
    }

    return 0;
}


void
watchdog_exit(int status)
{
    if (pidpath) {
        unlink(pidpath);
    }
    if (_watchdog_admin_is_waiting_for_reply) {
	int i = _watchdog_admin_is_waiting_for_reply;
	_watchdog_admin_is_waiting_for_reply = 0;
	/* Send error reply if admin fd is still there */
	assert(LS._heard_restart[i] == i);
	assert(LS.msg_table[i].wdSM != NULL);
	char msgstring[100];
	sprintf(msgstring,"%d",status);
	if (LS.msg_table[i].wdSM->SendToServer( wdmsgRestartreply, msgstring) ==0) {
		fprintf(stderr, "Restartreply failed\n");
	}
    }
    if (UDS_NAME[0]!=0) {
	unlink(UDS_NAME);
    }
    if (server_pid != -1) {
        /* Take the server down with us */
        if (!_watchdog_sigterm_was_sent) {
            kill(server_pid, SIGTERM);
            _watchdog_sigterm_was_sent = 1;
        }
    }
    watchdog_closelog();
    exit(status);
}

int
_watchdog_exec(int server_starts, char *server_exe, char *args[], 
               char * envp[], int *spid)
{
    int server_background = 0;
    char *server_out = NULL;
    char *server_err = NULL;
    char *server_context = NULL;
    char *pidfile = NULL;

    int rv = 0;
    int child;
    if (spid) *spid = -1;

    /* extract additonal options from config data */
    pidfile = strdup(confinfo->pidFile);
    if (confinfo->exeOut) {
        server_out = strdup(confinfo->exeOut);
    }
    if (confinfo->exeErr) {
       server_err = strdup(confinfo->exeErr);
    }
    if (confinfo->exeBackground) {
       server_background = confinfo->exeBackground;
    }
    if (confinfo->exeContext) {
       server_context = strdup(confinfo->exeContext);
    }
    if (confinfo->childSecurity) {
       child_security = confinfo->childSecurity;
    }

    /* store pid file of server parent */
    int rc = _watchdog_logpid(pidfile);
    if (rc < 0) {
        if (rc == -2) {
            sprintf(errmsgstr, "could not log PID to pid file  %s, nuxwdog already running", pidfile);
        } else {
            sprintf(errmsgstr, "could not log PID to pid file %s", pidfile);
        }
        watchdog_error(errmsgstr);
        if (detach) {
            kill(getppid(), SIGUSR2);
        }
        watchdog_exit(1);
    }

    if (pidfile != NULL) {
        free(pidfile);
    }

    child = fork();
    if (child == 0) {
        char envbuf[64];
        /* Pass the watchdog pipe fd to the server */
        sprintf(envbuf, "WD_PIPE_FD=%d", 0); // pipe_fd_ptoc[0]);
        putenv(envbuf);

        if (server_starts > 0) {
            int fd;

            fd = open("/dev/null", O_RDWR, 0);
            if (fd >= 0) {
                if (fd != 0) {
                    dup2(fd, 0);
                }
                if (fd != 1) {
                    dup2(fd, 1);
                }
		if (fd != 2){
		  dup2(fd, 2);
		}
                if (fd > 2) {
                    close(fd);
                }
            }
            /*
            if (guse_stderr) {
                fd = open("/dev/console", O_WRONLY, 0);
                if ((fd >= 0) && (fd != 2)) {
                    dup2(fd, 2);
                    close(fd);
                }
            }
            */
        }

        if (server_background) {
            int fd;
            setsid();
            for(fd=0; fd<3; fd++) close(fd);
            open("/dev/null", O_RDONLY);
            if (server_out) {
                open(server_out, O_WRONLY);
            } else {
                open("/dev/null", O_WRONLY);
            }

            if (server_err) {
                open(server_err, O_WRONLY);
            } else {
                open("/dev/null", O_WRONLY);
            }
        }

        if (server_out != NULL) {
            free(server_out);
        }

        if (server_err != NULL) {
            free(server_err);
        }

        if (server_context) {
            /* set the selinux type context - what happens if selinux not enabled?*/
            context_t con = NULL;
            security_context_t cur_context= NULL;
            
            if (getcon(&cur_context) < 0) {
                watchdog_error("unable to get current selinux context");
                watchdog_exit(1);
            }
      
            con = context_new(cur_context);
            context_type_set(con, server_context);
            setexeccon(context_str(con));
            
            if (cur_context != NULL) {
                freecon(cur_context);
            }

            free(server_context);
        }

        rv = execv(server_exe, args);
        if (rv < 0) {
	    watchdog_error("could not execute server binary");
            watchdog_exit(1);
        }
    }
    else if (child > 0) {
        if (spid) *spid = child;
    }
    else {
        rv = child;
        if (server_starts == 0) {
	    watchdog_error("could not fork server process");
        }
    }

    return rv;
}

int watchdog_pwd_prompt	(const char *prompt, int serial, char **pwdvalue);
int watchdog_pwd_save	(char *pwdname, int serial, char *pwdvalue);
int watchdog_pwd_lookup	(char *pwdname, int serial, char **pwdvalue);

void parse_LS_message_string(char * message, char ** ls_name, char ** ip,
                             int * port, int * family)
{
    char * new_port;
    char * new_ip;
    new_port = message+strlen(message);
    while (*new_port!=',') new_port--;
    *family = atoi(new_port+1);
    *new_port=0;
    while (*new_port!=',') new_port--;
    assert(new_port>message);
    *port = atoi(new_port+1);
    *new_port=0;
    new_ip = message+strlen(message);
    while (*new_ip!=',') new_ip--;
    *new_ip=0;
    if (*(new_ip+1)==0)	new_ip=NULL;	/* Empty string */
            else 		new_ip=new_ip+1;
    *ls_name = message;
    *ip	 = new_ip;
}

void parse_PWD_message_string(char *message, char **prompt, int *serial)
{
    char *p;

    p = message;

    // look for the first comma
    while (*p != ',' && *p != '\0')
        p++;
    if (*p == '\0') {
        // oops, not found
        *serial = 0;
        *prompt = NULL;
        return;
    }
    // null the comma out
    *p = '\0';
    // serial is the number in front of the comma
    *serial = atoi(message);
    // prompt is the string after the comma
    *prompt = p + 1;
}

int lastmessage = 0; 

void process_server_messages(int nmessages, int server_starts)
{
    int			i, rv, count, newfd, efd, port, family;
    char *		new_ip;
    char *		ls_name;
    char *              prompt;
    int                 serial;
    wdServerMessage *	wdSM;

    if (nmessages==0) return;
    count = 0;
    for (i=0; count < nmessages; i++) {
	if (LS.msg_table[i]._waiting!=0) {	// Only look at these
	    count++;
	    if (LS.msg_table[i]._waiting == -1) {
		/* HUP seen on this socket */
		LS.msg_table[i]._waiting = 0;	// Clear it
		LS.pa_table[i].fd	 = -1;	// no more on this socket
		if(LS.msg_table[i].wdSM != NULL)	// might be null from EmptyRead
		    delete LS.msg_table[i].wdSM;
		LS.msg_table[i].wdSM = NULL;	// Clear it
	    } else {
		LS.msg_table[i]._waiting = 0;	// Clear it
		wdSM = LS.msg_table[i].wdSM;
		if (wdSM == NULL) {
			fprintf(stderr, " NULL wdSM in watchdog:process_server_messages: index=%d, nmessages=%d, count=%d\n",
				i, nmessages, count);
			watchdog_exit(46);
		}
		char * msgstring = wdSM->RecvFromServer(child_security);
		lastmessage = wdSM->getLastMsgType();
		switch (lastmessage) {
		    case wdmsgGetLS:
			/* Parse message string and create a Listen Socket */
			parse_LS_message_string(msgstring, &ls_name, &new_ip,
                                                &port, &family);
			newfd = LS.getNewLS(ls_name, new_ip, port, family);
			if (newfd<0) {
			    if (_watchdog_server_init_done==0)
				_watchdog_death = 1;	/* bad error - stop it all */
			}
			if (wdSM->SendToServer( wdmsgGetLSreply, (char *)&newfd)==0) {
				watchdog_error("GETLS: error communicating with server");
			}
			break;
		    case wdmsgCloseLS:
			/* Parse message string and close the Listen Socket */
			parse_LS_message_string(msgstring, &ls_name, &new_ip,
                                                &port, &family);
			newfd = LS.removeLS(ls_name, new_ip, port, family);
			if (wdSM->SendToServer( wdmsgCloseLSreply, NULL) ==0) {
				watchdog_error("CLOSELS: error communicating with server");
			}
			break;
		    case wdmsgEmptyRead:
			// Treat this as if an end of file happened on the socket
			// so it is like the HUP case
			LS.pa_table[i].fd	 = -1;	// no more on this socket
			assert(LS.msg_table[i].wdSM!=NULL);
                        if (adminChannel == LS.msg_table[i].wdSM)
                            adminChannel = NULL;
			delete LS.msg_table[i].wdSM;
			LS.msg_table[i].wdSM = NULL;	// Clear it
			break;
		    case wdmsgGetPWD:
			char * pwd_result;
			parse_PWD_message_string(msgstring, &prompt, &serial);
			rv = watchdog_pwd_lookup(prompt, serial, &pwd_result);
			if (rv == 0) {	/* did not find it */
			    if ((server_starts==0) &&
				(_watchdog_server_init_done==0)) {
				rv = watchdog_pwd_prompt(prompt, serial, &pwd_result);
				if (rv<0) {	/* errors */
				    const char * errstr;
				    switch (rv) {
					case -1:
					errstr = "end-of-file while reading password";
					break;
					case -2:
					errstr = "invalid password";
					break;
					default:
					errstr = "error while reading password";
					break;
				    }
				    watchdog_error(errstr);
				    // _watchdog_death = 1; ???
				}
				rv = watchdog_pwd_save(prompt, serial, pwd_result);
				// check error code??
			    }	// otherwise can fall through without prompting
			}
			if ((pwd_result==NULL) || (strlen(pwd_result)==0) || (_watchdog_server_init_done==1))
                            sprintf(pwd_result, "send-non-empty-message");
			if (wdSM->SendToServer(wdmsgGetPWDreply, pwd_result) == 0)
                            watchdog_error("GETPWD: error communicating with server");
			break;
		    case wdmsgSetPIDpath:
			if (pidpath == NULL) {	// First time: set it up 
			    int rc = _watchdog_logpid(msgstring);
			    if (rc < 0) {
				if (rc == -2)
				    sprintf(errmsgstr, "could not log PID to PidLog %s, server already running", msgstring);
				else
				    sprintf(errmsgstr, "could not log PID to PidLog %s", msgstring);
				watchdog_error(errmsgstr);
				if (detach)
			            kill(getppid(), SIGUSR2);
			        watchdog_exit(1);
			    }
			} else {
			    // Confirm it is the same as before
			    if (strncmp(pidpath,msgstring,strlen(msgstring))) {
				fprintf(stderr, "PidPath changed: is this an error?\n");
			    }
			}
			if (wdSM->SendToServer( wdmsgSetPIDpathreply, NULL) ==0) {
				watchdog_error("SETPIDPATH: error communicating with server");
			}
			break;
		    case wdmsgEndInit:
			_watchdog_server_init_done = 1;
			n_reconfig = atoi(msgstring);	// Maxprocs sent back
			if (wdSM->SendToServer(wdmsgEndInitreply, NULL) == 0)
                            watchdog_error("ENDINIT: error communicating with server");
                        // Only the primordial process send the EndInit message to
                        // the watchdog. Therefore, this channel is deemed to be the
                        // channel used by the watchdog to Administer the server 
                        // process(es)
                        adminChannel = wdSM;
			break;
		    case wdmsgTerminate:
			/* message indicates server has finished and will terminate */
                        if (adminChannel != NULL) {
                            // acknowledge the terminate command
                            _watchdog_death = 1;
                            if (wdSM->SendToServer(wdmsgTerminatereply, NULL) == 0)
                                watchdog_error("TERMINATE: error communicating with server");
                            if (adminChannel->SendToServer(wdmsgTerminate, NULL) == 0)
                                watchdog_error("TERMINATE: error communicating with admin channel");
                        }
			break;
		    case wdmsgRestart:
			/* message is the status file */
			/*
			 * The Admin Server CGI needs to be able to delete
			 * this file when it's done with it.
			 */
			efd = open(msgstring, (O_CREAT|O_TRUNC|O_WRONLY), 0666);
			if ((efd >= 0) && (efd != 2)) {
				/* Replace stderr with this file */
				dup2(efd, 2);
				close(efd);
				guse_stderr = 1;
			}
			LS._heard_restart[i] = i; /* mark fd => came from Admin */
			_watchdog_admin_is_waiting_for_reply = i;
			_watchdog_server_restart = 1;
			/* Reply is delayed until restart finishes */
			break;
		    case wdmsgReconfigure:
			_watchdog_admin_waiting_for_reconfig_status = i;
			// Set the number of done messages to expect
			n_reconfigDone = n_reconfig;
            if (adminChannel != NULL)
            {
                if (adminChannel->SendToServer(wdmsgReconfigure, NULL) == 0)
                {
                    watchdog_error("RECONFIGURE: error communicating with admin channel");
                }

                // acknowledge the reconfigure command (from the admin)
                if (wdSM->SendToServer( wdmsgReconfigurereply, NULL) ==0) {
                    watchdog_error("RECONFIGURE: error communicating with server");
                }
            }
			break;
		    case wdmsgGetReconfigStatus:
			_watchdog_admin_waiting_for_reconfig_status = i;
			break;
		    case wdmsgReconfigStatus:
			// Send message to admin that did last GetReconfigStatus
			if (_watchdog_admin_waiting_for_reconfig_status>0) {
			    wdServerMessage *	wdSM;
			    wdSM = LS.msg_table[_watchdog_admin_waiting_for_reconfig_status]
					.wdSM;
			    assert(msgstring!=NULL);
			    if (wdSM->SendToServer( wdmsgGetReconfigStatusreply, msgstring ) ==0) {
				watchdog_error("RECONFIGSTATUS: error communicating with admin channel");
			    }
			} else {
				// Error, or Admin no longer listening??
			}
			// and reply to server
			if (wdSM->SendToServer( wdmsgReconfigStatusreply, NULL ) ==0) {
				watchdog_error("RECONFIGSTATUS: error communicating with server");
			}
			break;
		    case wdmsgReconfigStatusDone:
			// Send admin done indication
			n_reconfigDone--;
			if (n_reconfigDone ==0) {
			    if (_watchdog_admin_waiting_for_reconfig_status>0) {
				wdServerMessage *	wdSM;
				wdSM = LS.msg_table[_watchdog_admin_waiting_for_reconfig_status]
					.wdSM;
				// Send a null status message to indicate done
				if (wdSM->SendToServer( wdmsgGetReconfigStatusreply, NULL) ==0) {
					watchdog_error("RECONFIGSTATUSDONE: error communicating with admin channel");
				}
			    } else {
				// error, or admin no longer listening?
			    }
			    _watchdog_admin_waiting_for_reconfig_status = 0;
			} else  {
			    // Ignore this potential error
			    //	assert(n_reconfigDone>0);
			}
			if (wdSM->SendToServer( wdmsgReconfigStatusDonereply, NULL ) ==0) {
				watchdog_error("RECONFIGSTATUSDONE: error communicating with server");
			}
			break;
		    default:
			fprintf(stderr,
				"Unknown message in process_server_messages: %d\n",
				wdSM->getLastMsgType());
		}
	    }
        }
	if (count==nmessages) break;
    }	// end of for
    assert(count==nmessages);
}

void wait_for_message(int server_starts)
{
    int nmsgs = LS.Wait_for_Message();
    if (nmsgs == 0) return;
    else if (nmsgs > 0) {
	process_server_messages(nmsgs,server_starts);
    } else {
        if (nmsgs==-1) {
	    if (errno!=EINTR) {
	        sprintf(errmsgstr, "error waiting for messages, errno = %d", errno);
                watchdog_error(errmsgstr);
	    }
	} else {
	    sprintf(errmsgstr, "Poll failed: nmsgs=%d, errno=%d",
                    nmsgs, errno);
            watchdog_error(errmsgstr);
	}

    }
}

int main(int argc, char **argv, char **envp)
{
    int rv;
    int c;
    int i;
    int fd;
    int ver=0;
    int server_starts;
    int server_stat;
    int server_background = 0;
    char *server_exe = NULL;
    char *server_args = NULL;
    char *conffile = NULL;
    char *pch;
    char *args[100];
    struct stat statbuf;
    UDS_NAME[0]=0;

    /*
     * Initialize logging through the syslog API
     */

    watchdog_openlog();

    maxfd_set(maxfd_getmax());

    while((c = getopt(argc,argv,"if:")) != -1) {
        switch(c) {
          case 'f':
            conffile = strdup(optarg);
            break;
          case 'i':
            detach = 0;
            break;
        }
    }
    if (!detach)
        guse_stderr = 1;

    /* Parse configuration */
    confinfo = watchdog_parse(conffile);
    if (!confinfo) {
        watchdog_exit(1);
    }

    if (conffile != NULL) {
        free(conffile);
    }

   /* executable */
    server_exe = strdup(confinfo->exeFile);
    rv = stat(server_exe, &statbuf);
    if (rv < 0) {
        sprintf(errmsgstr, "could not find %s", server_exe);
	watchdog_error(errmsgstr);
        watchdog_exit(1);
    }

    /* args */
    server_args = strdup(confinfo->exeArgs);
    pch = strtok(server_args, " ");
    i = 0;
    while (pch != NULL) {
        /*while (strcmp(pch, "") == 0) {
            pch=strtok(NULL, " ");
        }*/
        args[i]= strdup(pch);
        pch=strtok(NULL, " ");
        i++;
    }
    args[i] = NULL;

    if (server_args != NULL) {
        free(server_args);
    }

    /* tempdir */ 
    tempdir = confinfo->tmpDir;
    rv = PR_MkDir(tempdir, 0755);
    if (access(tempdir, W_OK)) {
        sprintf(errmsgstr, "temporary directory %s is not writable",
                          tempdir);
        watchdog_error(errmsgstr);
        watchdog_exit(1);
    }

    if (detach) {
        parent_watchdog_create_signal_handlers();

        /*
         * Set the watchdog up as session leader, but don't close
         * stdin, stdout, and stderr until after the server completes
         * its initialization for the first time.
         */

        if ((rv = fork()) < 0) {
	    watchdog_error("could not detach watchdog process");
            watchdog_exit(1);
        }

        if (rv > 0) {
            /* Parent exits normally when child signals it */
            watchdog_wait_signal();
            if(_watchdog_server_start_error)
                exit(1);
            exit(0);
        }

        /* Child leads a new session */
        rv = setsid();
        if (rv < 0) {
            if (guse_stderr) {
                fprintf(stderr,
                    "failure: could not setsid() for watchdog process (%s)\n",
                    strerror(errno));
            }
	    watchdog_log(LOG_WARNING,
			 "could not setsid() for watchdog process");
        }
    }

    // set up UNIX domain socket for WD commands
    sprintf(UDS_NAME,"%s/%s%d", tempdir, WDSOCKETNAME, getpid());
    unlink(UDS_NAME);

    char envbuf[128];
    sprintf(envbuf, "WD_PIPE_NAME=%s", UDS_NAME);
    putenv(envbuf);

    const char * resultstr = LS.InitializeLSmanager(UDS_NAME);
    if (resultstr != NULL) {
	sprintf(errmsgstr, "error %d initializing listen socket manager [%s]", errno, resultstr);
	watchdog_error(errmsgstr);
        watchdog_exit(1);
    }

    for (server_starts = 0;; ++server_starts) {

        _watchdog_death					= 0;
	_watchdog_sigterm_was_sent			= 0;
        _watchdog_server_init_done			= 0;
        _watchdog_server_death				= 0;
        _watchdog_server_restart			= 0;
	_watchdog_stop_waiting_for_messages		= 0;
	_watchdog_admin_waiting_for_reconfig_status	= 0;

        watchdog_create_signal_handlers();

        rv = _watchdog_exec(server_starts, server_exe, args, envp, &server_pid);

        if (server_pid < 0) {
            // exec failed:  kill parent if it's still waiting
            if (detach && (server_starts == 0))
                kill(getppid(), SIGUSR2);
            break;
        }

        
        if (confinfo->childPidFile) {
           int rc = _watchdog_logchildpid(confinfo->childPidFile, server_pid);
           if (rc < 0) {
               if (rc == -2) {
                   sprintf(errmsgstr, "could not log PID %d to PidLog %s, server already running", server_pid, confinfo->childPidFile);
               } else {
                   sprintf(errmsgstr, "could not log PID %d to PidLog %s", server_pid, confinfo->childPidFile);
               }
               watchdog_error(errmsgstr);
               if (detach) {
                   kill(getppid(), SIGUSR2);
               }
               watchdog_exit(1);
           }
        }

        /* Initialization loop:				*/
	/* Keep receiving requests from server until	*/
	/* it signals an error event or done with init	*/
	/* (PidLog and Password requests must happen	*/
	/* during this loop; some others are allowed	*/
	/* but NOT restart)				*/
        while (!_watchdog_server_init_done) {

            if (_watchdog_death) {
		if (!_watchdog_sigterm_was_sent) {
		    kill(server_pid, SIGTERM);
		    _watchdog_sigterm_was_sent = 1;
		}
            }

            if (_watchdog_server_death) {
                do {
                    rv = wait(&server_stat);
                } while ((rv < 0) && (errno == EINTR));

                if (getenv("WDOG_NO_WATCH_SIGCHLD")) {
                    // server is detaching itself and so will exit.
                    // the watchdog cannot therefore watch this server
                    // but needs to stick around for password requests

                    _watchdog_server_death = 0;
                    break;
                }

                if (ver) {
                    if (WIFEXITED(server_stat) && !WEXITSTATUS(server_stat)) {
                        // version/config test success
                        if (detach)
                            kill(getppid(), SIGUSR1);
                        watchdog_exit(0);
                    } else {
                        // config test failure
                        if (detach)
                            kill(getppid(), SIGUSR2);
                        watchdog_exit(1);
                    }
                } else {
                    if (detach && (server_starts == 0)) 
                        kill(getppid(), SIGUSR2);
                }

                if ((rv < 0) && (errno == ECHILD)) {
		    watchdog_error(
                       "wait() returned ECHILD during server initialization");
		} else {
		    watchdog_check_status(server_stat);
		    watchdog_error("Server initialization failed. See the errors log for more information.");
		}
                watchdog_exit(1);
            }

	    // if init not over and get a restart, don't restart servers, exit
	    if (_watchdog_server_restart) {
		watchdog_error("Restart not allowed during Server Initialization");
		watchdog_exit(1);
	    }
            /* Wait for a request from the server */
	    wait_for_message(server_starts);
        }	/* while (!_watchdog_server_init_done) */

        if (detach) {
            if (server_starts == 0) {
                fd = open("/dev/null", O_RDWR, 0);
                if (fd >= 0) {
                    if (fd != 0) {
                        dup2(fd, 0);
                    }
                    if (fd != 1) {
                        dup2(fd, 1);
                    }
		    /*
		     * Send stderr to /dev/null too.
		     */
		    if (fd != 2) {
		      dup2(fd, 2);
		    }
                    if (fd > 2) {
                        close(fd);
                    }
                }

                /* The parent watchdog can exit now */
                kill(getppid(), SIGUSR1);
            }
            else {
            /*
             * stderr may have been redirected to a temporary file.
             * If we're running detached, redirect it to /dev/null.
             */
                fflush(stderr);
                fd = open("/dev/null", O_WRONLY, 0);
                if ((fd >= 0) && (fd != 2)) {
                    dup2(fd, 2);
                    close(fd);
                }
            }
            guse_stderr = 0;  /* reset to 0 */
        }

	if (_watchdog_admin_is_waiting_for_reply) {
	    int i = _watchdog_admin_is_waiting_for_reply;
	    _watchdog_admin_is_waiting_for_reply = 0;
	    assert(LS._heard_restart[i] == i);
	    assert(LS.msg_table[i].wdSM != NULL);
            /* Send reply if admin fd is still there */
	    if (LS.msg_table[i].wdSM->SendToServer( wdmsgRestartreply, NULL)==0) {
		fprintf(stderr, "Restartreply failed\n");
	    }
	}

	/* Main Loop:					*/
	/* Just wait for requests from the server until	*/
	/*	a SIGCHLD or other action is signalled	*/
        while (!_watchdog_server_death) {
            if (_watchdog_death | _watchdog_server_restart) {
		if (!_watchdog_sigterm_was_sent) {
		    kill(server_pid, SIGTERM);
		    _watchdog_sigterm_was_sent = 1;
		}
                break;
            }
	    wait_for_message(server_starts);
        }

	if (_watchdog_server_death && !_watchdog_sigterm_was_sent) {
	    // server died but watchdog did not terminate it
	    if (n_reconfigDone > 0) {
		// possibly in the middle of a reconfigure - shut down
		// all Listen Sockets since might be all wrong now.
	 	LS.unbind_all();
	    }
	}

	/* Shutdown loop: ends when server terminates 	*/
	while (!_watchdog_server_death && !_watchdog_stop_waiting_for_messages) {
	    wait_for_message(server_starts);
	}

        do {
            rv = wait(&server_stat);
        } while ((rv < 0) && (errno == EINTR));

        if ((rv < 0) && (errno == ECHILD)) {
	    watchdog_error("wait() returned ECHILD unexpectedly");
            if (_watchdog_death) {
                watchdog_exit(1);
            }
        }

        if (_watchdog_death) {
            watchdog_exit(0);
        }

        /* watchdog_check_status(server_stat); */
        sleep(10);

        watchdog_delete_signal_handlers();
    }	/* for (server_starts = ...	*/

    watchdog_exit(1);
}
