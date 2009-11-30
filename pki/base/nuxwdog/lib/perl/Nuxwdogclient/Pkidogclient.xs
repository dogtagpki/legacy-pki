#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include <nspr4/prtypes.h>

#include "ppport.h"

#include "../../../src/com/redhat/pkidog/WatchdogClient.h"

#include "const-c.inc"

MODULE = Pkidogclient		PACKAGE = Pkidogclient		

INCLUDE: const-xs.inc

PRStatus
call_WatchdogClient_init()

PRStatus
call_WatchdogClient_sendEndInit(numProcs)
        int numProcs

char *
call_WatchdogClient_getPassword(prompt, serial)
        char * prompt
        int serial

