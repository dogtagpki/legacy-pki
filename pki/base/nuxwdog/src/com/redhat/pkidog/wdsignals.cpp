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
 * wdsignals.c - Watchdog signal handling
 *
 *
 */

#include <unistd.h>
#include <signal.h>
#include "wdsignals.h"

/* Defined in watchdog.c */
extern int _watchdog_death;
extern int _watchdog_server_init_done;
extern int _watchdog_server_death;
extern int _watchdog_server_restart;
extern int _watchdog_server_start_error;

static int watchdog_pending_signal = 0;

static void
sig_term(int sig)
{
    _watchdog_death = 1;
    watchdog_pending_signal = 1;
}

static void
sig_usr1(int sig)
{
    watchdog_pending_signal = 1;
}

static void
sig_usr2(int sig)
{
    watchdog_pending_signal = 1;
}

static void
sig_hup(int sig)
{
    _watchdog_server_restart = 1;
    watchdog_pending_signal = 1;
}

static void
sig_chld(int sig)
{
    _watchdog_server_death = 1;
    watchdog_pending_signal = 1;
}

static void
parent_sig_chld(int sig)
{
    watchdog_pending_signal = 1;
}

static void
parent_sig_usr1(int sig)
{
    _watchdog_server_start_error = 0;
    watchdog_pending_signal = 1;
}

static void
parent_sig_usr2(int sig)
{
    watchdog_pending_signal = 1;
}

void
parent_watchdog_create_signal_handlers(void)
{
    struct sigaction sa;

    sa.sa_handler = parent_sig_usr1;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGUSR1);
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, NULL);

    sa.sa_handler = parent_sig_usr2;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask,SIGUSR2);
    sa.sa_flags = 0;
    sigaction(SIGUSR2, &sa, NULL);

    sa.sa_handler = parent_sig_chld;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGCHLD);
#ifdef SA_NOCLDSTOP
    sa.sa_flags = SA_NOCLDSTOP;
#else
    sa.sa_flags = 0;
#endif /* SA_NOCLDSTOP */
    sigaction(SIGCHLD, &sa, NULL);
}


void
watchdog_create_signal_handlers(void)
{
    struct sigaction sa;

    sa.sa_handler = sig_term;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGTERM);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGPIPE);
    sa.sa_flags = 0;
    sigaction(SIGPIPE, &sa, NULL);

    sa.sa_handler = sig_usr1;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGUSR1);
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, NULL);

    sa.sa_handler = sig_usr2;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGUSR2);
    sa.sa_flags = 0;
    sigaction(SIGUSR2, &sa, NULL);

    sa.sa_handler = sig_hup;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGHUP);
    sa.sa_flags = 0;
    sigaction(SIGHUP, &sa, NULL);

    sa.sa_handler = sig_chld;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGCHLD);
#ifdef SA_NOCLDSTOP
    sa.sa_flags = SA_NOCLDSTOP;
#else
    sa.sa_flags = 0;
#endif /* SA_NOCLDSTOP */
    sigaction(SIGCHLD, &sa, NULL);
}

void
watchdog_delete_signal_handlers(void)
{
    struct sigaction sa;

    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGUSR1);
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGUSR2);
    sa.sa_flags = 0;
    sigaction(SIGUSR2, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGHUP);
    sa.sa_flags = 0;
    sigaction(SIGHUP, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGCHLD);
    sa.sa_flags = 0;
    sigaction(SIGCHLD, &sa, NULL);
}

void
watchdog_wait_signal()
{
    sigset_t entryset;
    sigset_t holdset;

    sigfillset(&holdset);
    sigdelset(&holdset, SIGTERM);
    sigdelset(&holdset, SIGCHLD);
    sigdelset(&holdset, SIGHUP);
    sigdelset(&holdset, SIGUSR1);
    sigdelset(&holdset, SIGUSR2);
    sigprocmask(SIG_SETMASK, &holdset, &entryset);

    for (;;) {
        if (watchdog_pending_signal) {
            watchdog_pending_signal = 0;
            sigprocmask(SIG_SETMASK, &entryset, NULL);
            break;
        }
        sigsuspend(&holdset);
    }
}
