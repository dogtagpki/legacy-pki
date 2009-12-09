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

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_redhat_nuxwdog_WatchdogClient
 * Method:    init
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_redhat_nuxwdog_WatchdogClient_init
  (JNIEnv *, jclass );

/*
 * Class:     com_redhat_nuxwdog_WatchdogClient
 * Method:    sendEndInit
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_com_redhat_nuxwdog_WatchdogClient_sendEndInit
  (JNIEnv *, jclass, jint);

/*
 * Class:     com_redhat_nuxwdog_WatchdogClient
 * Method:    getPassword
 * Signature: (Ljava/lang/String;I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_redhat_nuxwdog_WatchdogClient_getPassword
  (JNIEnv *, jclass, jstring, jint);

#ifdef __cplusplus
}
#endif

