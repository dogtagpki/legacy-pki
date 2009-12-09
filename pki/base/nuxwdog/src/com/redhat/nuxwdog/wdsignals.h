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
 * wdsignal.h - Watchdog signal handling
 *
 *
 */

#ifndef _WDSIGNAL_H_
#define _WDSIGNAL_H_

void parent_watchdog_create_signal_handlers(void);
void watchdog_create_signal_handlers(void);
void watchdog_delete_signal_handlers(void);
void watchdog_wait_signal(void);

#endif /* _WDSIGNAL_H_ */
