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

