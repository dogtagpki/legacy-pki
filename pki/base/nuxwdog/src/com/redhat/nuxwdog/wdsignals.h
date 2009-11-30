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
