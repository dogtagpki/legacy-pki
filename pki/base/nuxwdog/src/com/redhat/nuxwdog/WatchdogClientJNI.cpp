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

#include "WatchdogClient.h"
#include "WatchdogClientJNI.h"

extern "C" JNIEXPORT jint JNICALL
Java_com_redhat_nuxwdog_WatchdogClient_init
(JNIEnv *env, jclass this2) {
    return WatchdogClient::init();
}

extern "C" JNIEXPORT jint JNICALL
Java_com_redhat_nuxwdog_WatchdogClient_sendEndInit
(JNIEnv *env, jclass this2, jint numProcs) {
    return WatchdogClient::sendEndInit(numProcs);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_redhat_nuxwdog_WatchdogClient_getPassword
(JNIEnv *env, jclass this2, jstring prompt, jint serial) {
    char *password = NULL;
    const char *_prompt = env->GetStringUTFChars(prompt, 0);
    if (_prompt== NULL) {
        return NULL;
    }

    PRStatus status = WatchdogClient::getPassword(_prompt, serial, &password);
    env->ReleaseStringUTFChars(prompt, _prompt);

    if (status == PR_SUCCESS) {
        return env->NewStringUTF((const char *) password);
    } else {
        return NULL;
    }
}

