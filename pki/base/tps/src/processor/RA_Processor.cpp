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
// Copyright (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

#include "cert.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "plstr.h"

#include "secder.h"
#include "pk11func.h"
#include "cryptohi.h"
#include "keyhi.h"
#include "base64.h"
#include "nssb64.h"


#include "engine/RA.h"
#include "authentication/LDAP_Authentication.h"
#include "main/Buffer.h"
#include "main/Base.h"
#include "main/Util.h"
#include "main/RA_Session.h"
#include "main/RA_Msg.h"
#include "main/Login.h"
#include "main/SecureId.h"
#include "main/Util.h"
#include "httpClient/httpc/http.h"
#include "httpClient/httpc/request.h"
#include "httpClient/httpc/response.h"
#include "httpClient/httpc/engine.h"
#include "processor/RA_Processor.h"
#include "cms/HttpConnection.h"
#include "cms/CertEnroll.h"
#include "msg/RA_Status_Update_Request_Msg.h"
#include "msg/RA_Status_Update_Response_Msg.h"
#include "msg/RA_Login_Request_Msg.h"
#include "msg/RA_Login_Response_Msg.h"
#include "msg/RA_Extended_Login_Request_Msg.h"
#include "msg/RA_Extended_Login_Response_Msg.h"
#include "msg/RA_ASQ_Request_Msg.h"
#include "msg/RA_ASQ_Response_Msg.h"
#include "msg/RA_New_Pin_Request_Msg.h"
#include "msg/RA_New_Pin_Response_Msg.h"
#include "msg/RA_SecureId_Request_Msg.h"
#include "msg/RA_SecureId_Response_Msg.h"
#include "msg/RA_Token_PDU_Request_Msg.h"
#include "msg/RA_Token_PDU_Response_Msg.h"
#include "apdu/Lifecycle_APDU.h"
#include "apdu/Format_Muscle_Applet_APDU.h"
#include "apdu/Initialize_Update_APDU.h"
#include "apdu/Get_Version_APDU.h"
#include "apdu/External_Authenticate_APDU.h"
#include "apdu/Create_Object_APDU.h"
#include "apdu/Get_Status_APDU.h"
#include "apdu/Get_Data_APDU.h"
#include "apdu/Set_Pin_APDU.h"
#include "apdu/Read_Buffer_APDU.h"
#include "apdu/Write_Object_APDU.h"
#include "apdu/List_Objects_APDU.h"
#include "apdu/Generate_Key_APDU.h"
#include "apdu/List_Pins_APDU.h"
#include "apdu/Create_Pin_APDU.h"
#include "apdu/Put_Key_APDU.h"
#include "apdu/Select_APDU.h"
#include "apdu/APDU_Response.h"
#include "channel/Secure_Channel.h"
#include "main/Memory.h"
#include "main/PKCS11Obj.h"

#if 0
#ifdef __cplusplus
extern "C"
{
#endif
#include "tus/tus_db.h"
#ifdef __cplusplus
}
#endif
#endif

/**
 * Constructs a base processor.
 */
RA_Processor::RA_Processor ()
{
    totalAvailableMemory = 0;
    totalFreeMemory = 0;
}


/**
 * Destructs processor.
 */
RA_Processor::~RA_Processor ()
{
}

AuthenticationEntry *RA_Processor::GetAuthenticationEntry(
            const char *prefix, const char * a_configname, const char *a_tokenType)
{
    AuthenticationEntry *auth = NULL;
                                                                                
    if (!RA::GetConfigStore()->GetConfigAsBool(a_configname, false))
            return NULL;
                                                                                
        RA::Debug("RA_Processor::GetAuthenticationEntry",
                "Authentication enabled");
    char configname[256];
    PR_snprintf((char *)configname, 256, "%s.%s.auth.id", prefix, a_tokenType);
    const char *authid = RA::GetConfigStore()->GetConfigAsString(configname);
    if (authid == NULL) {
        goto loser;
    }
    auth = RA::GetAuth(authid);
        return auth;
loser:
    return NULL;
}


void RA_Processor::StatusUpdate(RA_Session *a_session,  
		NameValueSet *a_extensions,
    int a_status, const char *a_info)
{
    if (a_extensions != NULL) {
		if (a_extensions->GetValue("statusUpdate") != NULL) {
        	StatusUpdate(a_session, a_status, a_info);
		}
    }
}

void RA_Processor::StatusUpdate(RA_Session *session,  
    int status, const char *info)
{
    RA_Status_Update_Request_Msg *status_update_request_msg = NULL;
    RA_Status_Update_Response_Msg *status_update_response_msg = NULL;

    RA::Debug(LL_PER_PDU, "RA_Processor::StatusUpdate",
        "RA_Processor::StatusUpdate");

    status_update_request_msg = new RA_Status_Update_Request_Msg(
        status, info);
    session->WriteMsg(status_update_request_msg);

    RA::Debug(LL_PER_PDU, "RA_Processor::StatusUpdate",
        "Sent status_update_msg");

    status_update_response_msg = (RA_Status_Update_Response_Msg *)
        session->ReadMsg();
    if (status_update_response_msg == NULL)
    {
        RA::Error(LL_PER_PDU, "RA_Processor::StatusUpdate",
            "No Status Update Response Msg Received");
        goto loser;
    }
    if (status_update_response_msg->GetType() != MSG_STATUS_UPDATE_RESPONSE) {
            RA::Error("Secure_Channel::StatusUpdate",
            "Invalid Msg Type");
            goto loser;
    }

loser:
    if( status_update_request_msg != NULL ) {
        delete status_update_request_msg;
        status_update_request_msg = NULL;
    }
    if( status_update_response_msg != NULL ) {
        delete status_update_response_msg;
        status_update_response_msg = NULL;
    }

} /* StatusUpdate */

/**
 * Requests login ID and password from user.
 */
AuthParams *RA_Processor::RequestExtendedLogin(RA_Session *session,  
    int invalid_pw, int blocked,
    char **parameters, int len, char *title, char *description)
{
    RA_Extended_Login_Request_Msg *login_request_msg = NULL;
    RA_Extended_Login_Response_Msg *login_response_msg = NULL;
    AuthParams *login = NULL;
    AuthParams *c = NULL;
    int i = 0;

    RA::Debug(LL_PER_PDU, "RA_Processor::RequestExtendedLogin",
        "RA_Processor::RequestExtendedLogin %s %s", 
        title, description);

    login_request_msg = new RA_Extended_Login_Request_Msg(
        invalid_pw, blocked, parameters, len, title, description);
    session->WriteMsg(login_request_msg);
    RA::Debug(LL_PER_PDU, "RA_Processor::RequestExtendedLogin",
        "Sent login_request_msg");

    login_response_msg = (RA_Extended_Login_Response_Msg *)
        session->ReadMsg();
    if (login_response_msg == NULL)
    {
        RA::Error(LL_PER_PDU, "RA_Processor::RequestExtendedLogin",
            "No Extended Login Response Msg Received");
        goto loser;
    }
    if (login_response_msg->GetType() != MSG_EXTENDED_LOGIN_RESPONSE) {
            RA::Error("Secure_Channel::Login_Request",
            "Invalid Msg Type");
            goto loser;
    }

    login = new AuthParams();
    c = login_response_msg->GetAuthParams();
    for (i = 0; i < c->Size(); i++) {
      login->Add(c->GetNameAt(i), c->GetValue(c->GetNameAt(i)));
    }

loser:
    if( login_request_msg != NULL ) {
        delete login_request_msg;
        login_request_msg = NULL;
    }
    if( login_response_msg != NULL ) {
        delete login_response_msg;
        login_response_msg = NULL;
    }

    return login;
} /* RequestExtendedLogin */

/**
 * Requests login ID and password from user.
 */
AuthParams *RA_Processor::RequestLogin(RA_Session *session,  
    int invalid_pw, int blocked)
{
    RA_Login_Request_Msg *login_request_msg = NULL;
    RA_Login_Response_Msg *login_response_msg = NULL;
    AuthParams *login = NULL;

    RA::Debug(LL_PER_PDU, "RA_Processor::Login_Request",
        "RA_Processor::Login_Request");

    login_request_msg = new RA_Login_Request_Msg(
        invalid_pw, blocked);
    session->WriteMsg(login_request_msg);
    RA::Debug(LL_PER_PDU, "RA_Processor::Login_Request",
        "Sent login_request_msg");

    login_response_msg = (RA_Login_Response_Msg *)
        session->ReadMsg();
    if (login_response_msg == NULL)
    {
        RA::Error(LL_PER_PDU, "RA_Processor::Login_Request",
            "No Login Response Msg Received");
        goto loser;
    }
    if (login_response_msg->GetType() != MSG_LOGIN_RESPONSE) {
            RA::Error("Secure_Channel::Login_Request",
            "Invalid Msg Type");
            goto loser;
    }
    login = new AuthParams();
    login->Add("UID", login_response_msg->GetUID());
    login->Add("PASSWORD", login_response_msg->GetPassword());

loser:
    if( login_request_msg != NULL ) {
        delete login_request_msg;
        login_request_msg = NULL;
    }
    if( login_response_msg != NULL ) {
        delete login_response_msg;
        login_response_msg = NULL;
    }

    return login;
} /* RequestLogin */

/**
 * Upgrade the applet to the current session with the new version.
 */
int RA_Processor::UpgradeApplet(RA_Session *session, char *prefix, char *tokenType, BYTE major_version, BYTE minor_version, const char *new_version, const char *applet_dir, SecurityLevel security_level, const char *connid,
		NameValueSet *extensions,
		int start_progress,
		int end_progress, 
                char **key_version)
{
        Buffer *NetKeyAID = RA::GetConfigStore()->GetConfigAsBuffer(
			RA::CFG_APPLET_NETKEY_INSTANCE_AID,
		        RA::CFG_DEF_NETKEY_INSTANCE_AID);
        Buffer *OldAAID = RA::GetConfigStore()->GetConfigAsBuffer(
			RA::CFG_APPLET_NETKEY_OLD_INSTANCE_AID,
		        RA::CFG_DEF_NETKEY_OLD_INSTANCE_AID);
        Buffer *OldPAID = RA::GetConfigStore()->GetConfigAsBuffer(
			RA::CFG_APPLET_NETKEY_OLD_FILE_AID,
		        RA::CFG_DEF_NETKEY_OLD_FILE_AID);
        Buffer *NetKeyPAID = RA::GetConfigStore()->GetConfigAsBuffer(
			RA::CFG_APPLET_NETKEY_FILE_AID,
		        RA::CFG_DEF_NETKEY_FILE_AID);
        Buffer *PIN = RA::GetConfigStore()->GetConfigAsBuffer(
			RA::CFG_APPLET_SO_PIN,
		        RA::CFG_DEF_APPLET_SO_PIN);
        Buffer empty;
	PRFileDesc *f = NULL;
	char path[4096];
	char configname[4096];
	PRFileInfo info;
	PRStatus status;
	int rc = 0;
        Secure_Channel *channel = NULL;
	int size_to_send = 0;
	char *dataf = NULL;
	int block_size;
	BYTE refControl;
	int count;
	Buffer programFile;
        Buffer tag;
        Buffer length;
        Buffer tbsProgramFile;
        unsigned int totalLen;
	int num_loops;
	float progress_block_size;
	int x_blocksize;
	int instance_size;
        int applet_memory_size;
	int defKeyVer;
	int defKeyIndex;
	char *ext;

	if (applet_dir == NULL) {
                RA::Error(LL_PER_PDU, "RA_Processor::UpgradeApplet", 
				"Failed to get upgrade.directory");
		goto loser;		
	}
	sprintf(configname, "general.applet_ext");
	ext = (char*)RA::GetConfigStore()->GetConfigAsString(configname, "ijc");
	sprintf(path, "%s/%s.%s", applet_dir, new_version, ext);
	RA::Debug("RA_Processor::UpgradeApplet", "path = %s", path);
	status = PR_GetFileInfo(path, &info);
	if (status != PR_SUCCESS) {
                RA::Error(LL_PER_PDU, "RA_Processor::UpgradeApplet", 
				"Failed to get file info");
		goto loser;		
	}
	f = PR_Open(path, PR_RDONLY, 400);
	if (f == NULL) {
                RA::Error(LL_PER_PDU, "RA_Processor::UpgradeApplet", 
			"Failed to open '%s'", path);
		goto loser;		
	}
	dataf = (char *)malloc(info.size);
	PR_Read(f, dataf, info.size);
    if( f != NULL ) {
	    PR_Close( f );
        f = NULL;
    }

	/* Select Applet - Select Card manager */
	SelectCardManager(session, prefix, tokenType);

    PR_snprintf((char *)configname, 256,"channel.blockSize");
    x_blocksize = RA::GetConfigStore()->GetConfigAsInt(configname, 0xf8);
    PR_snprintf((char *)configname, 256,"channel.instanceSize");
    instance_size = RA::GetConfigStore()->GetConfigAsInt(configname, 18000);

    PR_snprintf((char *)configname, 256,"channel.appletMemorySize");

    applet_memory_size = RA::GetConfigStore()->GetConfigAsInt(configname, 5000);

    PR_snprintf((char *)configname, 256,"channel.defKeyVersion");
    defKeyVer = RA::GetConfigStore()->GetConfigAsInt(configname, 0x0);
    PR_snprintf((char *)configname, 256,"channel.defKeyIndex");
    defKeyIndex = RA::GetConfigStore()->GetConfigAsInt(configname, 0x0);
	channel = SetupSecureChannel(session, defKeyVer, defKeyIndex, security_level, connid);
	if (channel == NULL) {
             RA::Error(LL_PER_PDU, "RA_Processor::UpgradeApplet", 
		  "channel creation failure");
             rc = -1;
	     goto loser;
	}

        // get keyVersion
        if (channel != NULL) {
            *key_version = Util::Buffer2String(channel->GetKeyInfoData());
        }

	if (channel->ExternalAuthenticate() == -1) {
             RA::Error(LL_PER_PDU, "RA_Processor::UpgradeApplet", 
		  "failed to external authenticate during upgrade");
	     goto loser;
	}

	/* Delete File - Delete 627601ff000000 (CoolKey Instance) */
        rc = channel->DeleteFileX(session, NetKeyAID);
	if (rc != 1) {
	     /* it is ok to fail to delete file */
             RA::DebugBuffer(LL_PER_PDU, "RA_Processor::UpgradeApplet", 
		  "Warning: failed to delete file", NetKeyAID);
	}

	if (RA::GetConfigStore()->GetConfigAsBool(RA::CFG_APPLET_DELETE_NETKEY_OLD, true)) {
	    /* Delete File - Delete a00000000101 */
            rc = channel->DeleteFileX(session, OldAAID);
	    if (rc != 1) {
	       /* it is ok to fail to delete file */
               RA::DebugBuffer(LL_PER_PDU, "RA_Processor::UpgradeApplet", 
		  "Warning: failed to delete file", OldAAID);
	    }
	    /* Delete File - Delete a000000001 */
            rc = channel->DeleteFileX(session, OldPAID);
	    if (rc != 1) {
               RA::DebugBuffer(LL_PER_PDU, "RA_Processor::UpgradeApplet", 
		  "Warning: failed to delete file", OldPAID);
	    }
	}

	/* Delete File - Delete 627601ff0000 */
        channel->DeleteFileX(session, NetKeyPAID);

	/* Install Applet - Install applet instance */
        channel->InstallLoad(session, 
			*NetKeyPAID,
			empty,
			info.size);

	/* Multiple Load Program File - Load 627601ff0000 */
	programFile = Buffer ((BYTE *)dataf, info.size);
	if( dataf != NULL ) {
        free( dataf );
        dataf = NULL;
	}
        tag = Buffer(1, 0xC4);
        tbsProgramFile = tag + length + programFile;
        totalLen = tbsProgramFile.size();
        if( programFile.size() < 128 ) {
            length = Buffer(1, programFile.size());
        } else if( programFile.size() <= 255 ) {
            length = Buffer(2, 0);
            ((BYTE*)length)[0] = 0x81;
	    ((BYTE*)length)[1] = programFile.size();
	} else {
            length = Buffer(3, 0);
            ((BYTE*)length)[0] = 0x82;
            ((BYTE*)length)[1] = (programFile.size() >> 8) & 0xff;
            ((BYTE*)length)[2] = programFile.size() & 0xff;
        }
        tbsProgramFile = tag + length + programFile;
        totalLen = tbsProgramFile.size();

	size_to_send = totalLen;
	if (security_level == SECURE_MSG_MAC_ENC) {
	  // need leave room for possible encryption padding
	  block_size = x_blocksize - 0x10;
	} else {
	  block_size = x_blocksize - 8;
	}

	// rough number is good enough
	num_loops = size_to_send / block_size;
	progress_block_size = (float) (end_progress - start_progress) / num_loops;

	count = 0;
	refControl = 0x00; // intermediate block
	do {
		if (size_to_send < block_size) {
			block_size = size_to_send;
			// last block		
			refControl = 0x80;
		}
		if (size_to_send - block_size == 0) {
			// last block		
			refControl = 0x80;
		}
		Buffer d = tbsProgramFile.substr(totalLen - size_to_send, block_size);
                channel->LoadFile(session, (BYTE)refControl, (BYTE)count,  &d);

		size_to_send -= block_size;

		// send status update to the client
		if (extensions != NULL && 
		    extensions->GetValue("statusUpdate") != NULL) {
		  StatusUpdate(session, 
			start_progress + (count * progress_block_size) /* progress */, 
			"PROGRESS_APPLET_BLOCK");
		}
		count++;
	} while (size_to_send > 0);


	/* Install Applet - Install applet instance */
        channel->InstallApplet(session, 
			*NetKeyPAID,
			*NetKeyAID,
			0 /* appPrivileges */,
			instance_size /* instanceSize */,
                        applet_memory_size /* appletMemorySize */);

	/* Select File - Select 627601ff000000 */
        SelectApplet(session, 0x04, 0x00, NetKeyAID);

	rc = 1;
loser:
    if( NetKeyAID != NULL ) {
        delete NetKeyAID;
        NetKeyAID = NULL;
    }
    if( OldAAID != NULL ) {
        delete OldAAID;
        OldAAID = NULL;
    }
    if( OldPAID != NULL ) {
        delete OldPAID;
        OldPAID = NULL;
    }
    if( NetKeyPAID != NULL ) {
        delete NetKeyPAID;
        NetKeyPAID = NULL;
    }
    if( PIN != NULL ) {
        delete PIN;
        PIN = NULL;
    }
    if( channel != NULL ) {
        delete channel;
        channel = NULL;
    }
    if( dataf != NULL ) {
        free( dataf );
        dataf = NULL;
    }

	return rc;
}

char *RA_Processor::MapPattern(NameValueSet *nv, char *pattern)
{
        int i=0,x=0,j=0,z=0;
        unsigned int q = 0;
        char token[4096];
        char result[4096];
	char *value;

	if (pattern == NULL)
		return NULL;
        i = strlen(pattern);
        for (x = 0; x < i; x++) {
                if (pattern[x] == '$') {
                  if (pattern[x+1] == '$') {
                        result[z] = pattern[x];
			z++;
                        x++;
                  } else {
                          x++;
                          j = 0;
                          while (pattern[x] != '$') {
                                  token[j] = pattern[x];
                                  j++;
                                  x++;
                          }
                          token[j] = '\0';
			  value = nv->GetValue(token);
			  if (value != NULL) {
                             for (q = 0; q < strlen(value); q++) {
                                 result[z] = value[q];
				 z++;
			     }

			  }
                  }
                } else {
                        result[z] = pattern[x];
			z++;
                }
        }
	result[z] = '\0';

	return PL_strdup(result);
}

int RA_Processor::FormatMuscleApplet(RA_Session *session,
        unsigned short memSize,
        Buffer &PIN0, BYTE pin0Tries,
        Buffer &unblockPIN0, BYTE unblock0Tries,
        Buffer &PIN1, BYTE pin1Tries,
        Buffer &unblockPIN1, BYTE unblock1Tries,
        unsigned short objCreationPermissions,
        unsigned short keyCreationPermissions,
        unsigned short pinCreationPermissions)
{   
    int rc = 0;
    APDU_Response *format_response = NULL;
    RA_Token_PDU_Request_Msg *format_request_msg = NULL;
    RA_Token_PDU_Response_Msg *format_response_msg = NULL;
    Format_Muscle_Applet_APDU *format_apdu = NULL;
    // Buffer *mac = NULL;

    RA::Debug(LL_PER_PDU, "RA_Processor::FormatMuscle",
        "RA_Processor::FormatMuscle");

    format_apdu = new Format_Muscle_Applet_APDU(memSize, PIN0, pin0Tries,
                                unblockPIN0, unblock0Tries,
                                PIN1, pin1Tries,
                                unblockPIN1, unblock1Tries,
                                objCreationPermissions,
                                keyCreationPermissions,
                                pinCreationPermissions);
    format_request_msg =
        new RA_Token_PDU_Request_Msg(format_apdu);
    session->WriteMsg(format_request_msg);

    RA::Debug(LL_PER_PDU, "RA_Processor::FormatMuscle",
        "Sent format_request_msg");

    format_response_msg = (RA_Token_PDU_Response_Msg *)
        session->ReadMsg();
    if (format_response_msg == NULL)
    {
        RA::Error(LL_PER_PDU, "RA_Processor::FormatMuscle",
            "No Token PDU Response Msg Received");
        goto loser;
    }
    if (format_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
	   RA::Error(LL_PER_PDU, "RA_Processor::FormatMuscle", 
		"Invalid Message Type");
           goto loser;
    }
    format_response = format_response_msg->GetResponse();
    if (!(format_response->GetSW1() == 0x90 && 
        format_response->GetSW2() == 0x00)) {
    	RA::Error(LL_PER_PDU, "RA_Processor::FormatMuscle",
            "Bad Response");
	goto loser;
    }
    rc = 1;

loser:
    if( format_request_msg != NULL ) {
        delete format_request_msg;
        format_request_msg = NULL;
    }
    if( format_response_msg != NULL ) {
        delete format_response_msg;
        format_response_msg = NULL;
    }

    return rc;
}

/**
 * Determine the Token Type. The user can set up mapping rules in the 
 * config file which allow different operations depending on the
 * CUID, applet version, ATR, etc.
 */
bool RA_Processor::GetTokenType(const char *prefix, int major_version, int minor_version, const char *cuid, const char *msn, NameValueSet *extensions, 
	RA_Status &o_status /* out */, const char *&o_tokenType /* out */)
{
	const char *e_tokenATR = NULL;
	const char *tokenATR = NULL;
	const char *e_tokenType = NULL;
	const char *tokenType = NULL;
	const char *tokenCUIDStart = NULL;
	const char *tokenCUIDEnd = NULL;
	const char *targetTokenType = NULL;
	const char *majorVersion = NULL;
	const char *minorVersion = NULL;
	const char *order = NULL;
	char *order_x = NULL;
	const char *mappingId = NULL;
	char configname[256];
	int start_pos = 0, done = 0;
	unsigned int end_pos = 0;
	const char *cuid_x = NULL;

	cuid_x = cuid;

	sprintf(configname, "%s.mapping.order", prefix);
	order = RA::GetConfigStore()->GetConfigAsString(configname);
	if (order == NULL) {
		RA::Error("RA_Processor::GetTokenType", "Token type is not found");
    	o_status = STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND;
		RA::Debug(LL_PER_PDU, "RA_Processor::GetTokenType", 
				"cannot find config ", configname);
		return false; /* no mapping found */
	}

	RA::Debug(LL_PER_PDU, "RA_Processor::GetTokenType",
			"Starting:");
	order_x = PL_strdup(order);

	start_pos = 0;
	end_pos = 0;
	done = 0;
	while (1) 
	{
		if (done) {
			break;
		}
		end_pos = start_pos;
		while ((end_pos < strlen(order)) && (order_x[end_pos] != ',')) {
			end_pos++;
		}
		if (end_pos < strlen(order)) {
			order_x[end_pos] = '\0';
			done = 0;
		} else {
			done = 1;
		}
		mappingId = &order_x[start_pos];
		RA::Debug(LL_PER_PDU, "RA_Processor::GetTokenType", 
				"mappingId='%s'", mappingId);

		start_pos = end_pos + 1;

		sprintf(configname, "%s.mapping.%s.target.tokenType", prefix, 
				mappingId);
		targetTokenType = RA::GetConfigStore()->GetConfigAsString(configname);


		if (targetTokenType == NULL) {
			break;
		}
		sprintf(configname, "%s.mapping.%s.filter.tokenType", prefix, 
				mappingId);
		tokenType = RA::GetConfigStore()->GetConfigAsString(configname);

		RA::Debug(LL_PER_PDU, "RA_Processor::GetTokenType",
				"tokenType: %s",tokenType);

		if (tokenType != NULL && strlen(tokenType) > 0) {
			if (extensions == NULL) {
				continue; /* mapping not matched, next mapping */
			}
			e_tokenType = extensions->GetValue("tokenType");
			if (e_tokenType == NULL) {
				continue; /* mapping not matched, next mapping */
			}
			if (strcmp(tokenType, e_tokenType) != 0) {
				continue; /* mapping not matched, next mapping */
			}
		}
		sprintf(configname, "%s.mapping.%s.filter.tokenATR", prefix, 
				mappingId);
		tokenATR = RA::GetConfigStore()->GetConfigAsString(configname);
		if (tokenATR != NULL && strlen(tokenATR) > 0) {
			if (extensions == NULL) {
				continue; /* mapping not matched, next mapping */
			}
			e_tokenATR = extensions->GetValue("tokenATR");
			if (e_tokenATR == NULL) {
				continue; /* mapping not matched, next mapping */
			}
			if (strcmp(tokenATR, e_tokenATR) != 0) {
				continue; /* mapping not matched, next mapping */
			}
		}
		sprintf(configname, "%s.mapping.%s.filter.tokenCUID.start", prefix, 
				mappingId);
		tokenCUIDStart = RA::GetConfigStore()->GetConfigAsString(configname);
		if (tokenCUIDStart != NULL && strlen(tokenCUIDStart) > 0) {
			if (cuid_x == NULL) {
				continue; /* mapping not matched, next mapping */
			}
			RA::Debug(LL_PER_PDU, "RA_Processor::GetTokenType", 
					"cuid_x=%s tokenCUIDStart=%s %d", cuid_x, tokenCUIDStart, 
					PL_strcasecmp(cuid_x, tokenCUIDStart));

			if(strlen(tokenCUIDStart) != 20)
			{
				RA::Debug(LL_PER_PDU, "RA_Processor::GetTokenType",
						"Invalid tokenCUIDStart: %s",tokenCUIDStart);
				continue;
			}

			char *pend = NULL;
			strtol((const char *) tokenCUIDStart, &pend, 16);

			if(*pend != '\0')
			{
				RA::Debug(LL_PER_PDU, "RA_Processor::GetTokenType",
						"Invalid tokenCUIDStart: %s",tokenCUIDStart);

				continue;
			}

			if (PL_strcasecmp(cuid_x, tokenCUIDStart) < 0) {
				continue; /* mapping not matched, next mapping */
			}
		}
		sprintf(configname, "%s.mapping.%s.filter.tokenCUID.end", prefix, 
				mappingId);
		tokenCUIDEnd = RA::GetConfigStore()->GetConfigAsString(configname);
		if (tokenCUIDEnd != NULL && strlen(tokenCUIDEnd) > 0) {
			if (cuid_x == NULL) {
				continue; /* mapping not matched, next mapping */
			}
			RA::Debug(LL_PER_PDU, "RA_Processor::GetTokenType", 
					"cuid_x=%s tokenCUIDEnd=%s %d", cuid_x, tokenCUIDEnd, 
					PL_strcasecmp(cuid_x, tokenCUIDEnd));

			if(strlen(tokenCUIDEnd) != 20)
			{
				RA::Debug(LL_PER_PDU, "RA_Processor::GetTokenType",
						"Invalid tokenCUIDEnd: %s",tokenCUIDEnd);
				continue;
			}

			char *pend = NULL;
			strtol((const char *) tokenCUIDEnd, &pend, 16);

			if(*pend != '\0')
			{

				RA::Debug(LL_PER_PDU, "RA_Processor::GetTokenType",
						"Invalid tokenCUIDEnd: %s",tokenCUIDEnd);

				continue;
			}

			if (PL_strcasecmp(cuid_x, tokenCUIDEnd) > 0) {
				continue; /* mapping not matched, next mapping */
			}
		}
		sprintf(configname, "%s.mapping.%s.filter.appletMajorVersion", 
				prefix, mappingId);
		majorVersion = RA::GetConfigStore()->GetConfigAsString(configname);
		if (majorVersion != NULL && strlen(majorVersion) > 0) {
			if (major_version != atoi(majorVersion)) {
				continue; /* mapping not matched, next mapping */
			}
		}
		sprintf(configname, "%s.mapping.%s.filter.appletMinorVersion", 
				prefix, mappingId);
		minorVersion = RA::GetConfigStore()->GetConfigAsString(configname);
		if (minorVersion != NULL && strlen(minorVersion) > 0) {
			if (minor_version != atoi(minorVersion)) {
				continue; /* mapping not matched, next mapping */
			}
		}

		if( order_x != NULL ) {
			PL_strfree( order_x );
			order_x = NULL;
		}
	    RA::Debug("RA_Processor::GetTokenType",
                        "Selected Token type is '%s'", targetTokenType);
		o_tokenType = targetTokenType;
		return true;
	}


	if( order_x != NULL ) {
		PL_strfree( order_x );
		order_x = NULL;
	}
	RA::Error("RA_Processor::GetTokenType", "Token type is not found");
    o_status = STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND;
	
	return false;
}

int RA_Processor::SelectCardManager(RA_Session *session, char *prefix, char *tokenType)
{
    char configname[256];
    int rc;
    PR_snprintf((char *)configname, 256, "%s.%s.cardmgr_instance", prefix, tokenType);
    const char *cardmgr_instance = 
          RA::GetConfigStore()->GetConfigAsString(configname);
    Buffer *CardManagerAID = RA::GetConfigStore()->GetConfigAsBuffer(
           cardmgr_instance, RA::CFG_DEF_CARDMGR_INSTANCE_AID);
    rc = SelectApplet(session, 0x04, 0x00, CardManagerAID);
    if( CardManagerAID != NULL ) {
        delete CardManagerAID;
        CardManagerAID = NULL;
    }
    return rc;
}

/**
 * GetData  
 */
Buffer *RA_Processor::GetData(RA_Session *session)
{
    Buffer data;
    Buffer *status = NULL;
    APDU_Response *get_data_response = NULL;
    RA_Token_PDU_Request_Msg *get_data_request_msg = NULL;
    RA_Token_PDU_Response_Msg *get_data_response_msg = NULL;
    Get_Data_APDU *get_data_apdu = NULL;
    Buffer get_status_data;

    get_data_apdu =
        new Get_Data_APDU();
    get_data_request_msg =
        new RA_Token_PDU_Request_Msg(get_data_apdu);
    session->WriteMsg(get_data_request_msg);
    RA::Debug(LL_PER_PDU, "RA_Processor::GetData",
        "Sent get_data_request_msg");

    get_data_response_msg = (RA_Token_PDU_Response_Msg *)
        session->ReadMsg();
    if (get_data_response_msg == NULL)
    {
        RA::Error(LL_PER_PDU, "RA_Processor::GetData",
            "No Token PDU Response Msg Received");
        goto loser;
    }
    if (get_data_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
	   RA::Error(LL_PER_PDU, "RA_Processor::GetData", 
		"Invalid Message Type");
           goto loser;
    }
    get_data_response =
        get_data_response_msg->GetResponse();
    if (get_data_response == NULL) { 
	   RA::Error(LL_PER_PDU, "Secure_Channel::GetData", 
		"No Response From Token");
           goto loser;
    }
    data = get_data_response->GetData();

    if (!(get_data_response->GetSW1() == 0x90 && 
        get_data_response->GetSW2() == 0x00)) {
    	RA::Error(LL_PER_PDU, "RA_Processor::GetData",
            "Bad Response");
	goto loser;
    }

    status = new Buffer(data.substr(0, data.size()));

loser:

    if( get_data_request_msg != NULL ) {
        delete get_data_request_msg;
        get_data_request_msg = NULL;
    }
    if( get_data_response_msg != NULL ) {
        delete get_data_response_msg;
        get_data_response_msg = NULL;
    }

    return status;
}

Buffer *RA_Processor::ListObjects(RA_Session *session, BYTE seq)
{
    Buffer data;
    Buffer *status = NULL;
    APDU_Response *response = NULL;
    RA_Token_PDU_Request_Msg *request_msg = NULL;
    RA_Token_PDU_Response_Msg *response_msg = NULL;
    List_Objects_APDU *list_objects_apdu = NULL;
    Buffer get_status_data;

    list_objects_apdu =
        new List_Objects_APDU(seq);
    request_msg =
        new RA_Token_PDU_Request_Msg(list_objects_apdu);
    session->WriteMsg(request_msg);
    RA::Debug(LL_PER_PDU, "RA_Processor::ListObjects",
        "Sent request_msg");

    response_msg = (RA_Token_PDU_Response_Msg *)
        session->ReadMsg();
    if (response_msg == NULL)
    {
        RA::Error(LL_PER_PDU, "RA_Processor::ListObjects",
            "No Token PDU Response Msg Received");
        goto loser;
    }
    if (response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
	   RA::Error(LL_PER_PDU, "RA_Processor::ListObjects", 
		"Invalid Message Type");
           goto loser;
    }
    response = response_msg->GetResponse();
    if (response == NULL) { 
	   RA::Error(LL_PER_PDU, "Secure_Channel::ListObjects", 
		"No Response From Token");
           goto loser;
    }

    if (!(response->GetSW1() == 0x90 && 
        response->GetSW2() == 0x00)) {
  //  	RA::Error(LL_PER_PDU, "RA_Processor::ListObjects",
  //         "Bad Response");
	goto loser;
    }

    data = response->GetData();

    status = new Buffer(data.substr(0, data.size()));

loser:

    if( request_msg != NULL ) {
        delete request_msg;
        request_msg = NULL;
    }
    if( response_msg != NULL ) {
        delete response_msg;
        response_msg = NULL;
    }

    return status;
}

/**
 * GetStatus  
 */
Buffer *RA_Processor::GetStatus(RA_Session *session, BYTE p1, BYTE p2)
{
    Buffer data;
    Buffer *status = NULL;
    APDU_Response *get_status_response = NULL;
    RA_Token_PDU_Request_Msg *get_status_request_msg = NULL;
    RA_Token_PDU_Response_Msg *get_status_response_msg = NULL;
    Get_Status_APDU *get_status_apdu = NULL;
    Buffer get_status_data;

    get_status_apdu =
        new Get_Status_APDU();
    get_status_request_msg =
        new RA_Token_PDU_Request_Msg(get_status_apdu);
    session->WriteMsg(get_status_request_msg);
    RA::Debug(LL_PER_PDU, "RA_Processor::GetStatus",
        "Sent get_status_request_msg");

    get_status_response_msg = (RA_Token_PDU_Response_Msg *)
        session->ReadMsg();
    if (get_status_response_msg == NULL)
    {
        RA::Error(LL_PER_PDU, "RA_Processor::GetStatus",
            "No Token PDU Response Msg Received");
        goto loser;
    }
    if (get_status_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
	   RA::Error(LL_PER_PDU, "RA_Processor::GetStatus", 
		"Invalid Message Type");
           goto loser;
    }
    get_status_response =
        get_status_response_msg->GetResponse();
    if (get_status_response == NULL) { 
	   RA::Error(LL_PER_PDU, "Secure_Channel::GetStatus", 
		"No Response From Token");
           goto loser;
    }
    data = get_status_response->GetData();

    if (!(get_status_response->GetSW1() == 0x90 && 
        get_status_response->GetSW2() == 0x00)) {
    	RA::Error(LL_PER_PDU, "RA_Processor::GetStatus",
            "Bad Response");
	goto loser;
    }

    status = new Buffer(data.substr(0, data.size()));

loser:

    if( get_status_request_msg != NULL ) {
        delete get_status_request_msg;
        get_status_request_msg = NULL;
    }
    if( get_status_response_msg != NULL ) {
        delete get_status_response_msg;
        get_status_response_msg = NULL;
    }

    return status;
}

int RA_Processor::CreatePin(RA_Session *session, BYTE pin_number, 
		BYTE max_retries, char *pin)
{
    int rc = -1;
    Create_Pin_APDU *create_pin_apdu = NULL;
    APDU_Response *response = NULL;
    RA_Token_PDU_Request_Msg *token_pdu_request_msg = NULL;
    RA_Token_PDU_Response_Msg *token_pdu_response_msg = NULL;
    Buffer *mac = NULL;

    RA::Debug("Secure_Channel::IsPinPresent",
        "Secure_Channel::IsPinPresent");
    Buffer pin_buffer = Buffer((BYTE*)pin, strlen(pin));
    create_pin_apdu = new Create_Pin_APDU(pin_number, max_retries, 
		    pin_buffer);

    /*
    mac = ComputeAPDUMac(set_pin_apdu);
    set_pin_apdu->SetMAC(*mac);
    */
    token_pdu_request_msg = new RA_Token_PDU_Request_Msg(
        create_pin_apdu);
    session->WriteMsg(token_pdu_request_msg);
    RA::Debug("Secure_Channel::CreatePin",
        "Sent token_pdu_request_msg");

    token_pdu_response_msg = (RA_Token_PDU_Response_Msg *)
        session->ReadMsg();
    if (token_pdu_response_msg == NULL)
    {
        RA::Error("Secure_Channel::CreatePin",
            "No Token PDU Response Msg Received");
        goto loser;
    }
    if (token_pdu_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
	   RA::Error(LL_PER_PDU, "RA_Processor::CreatePin", 
		"Invalid Message Type");
           goto loser;
    }
    response = token_pdu_response_msg->GetResponse();
    if (response == NULL) {
        RA::Error("Secure_Channel::CreatePin",
            "No Response From Token");
        goto loser;
    }

    rc = 1;
loser:
    if( mac != NULL ) {
        delete mac;
        mac = NULL;
    }
    if( token_pdu_request_msg != NULL ) {
        delete token_pdu_request_msg;
        token_pdu_request_msg = NULL;
    }
    if( token_pdu_response_msg != NULL ) {
        delete token_pdu_response_msg;
        token_pdu_response_msg = NULL;
    }

    return rc;
}
int RA_Processor::IsPinPresent(RA_Session *session, BYTE pin_number)
{
    int rc = -1;
    Buffer data;
    List_Pins_APDU *list_pins_apdu = NULL;
    APDU_Response *response = NULL;
    RA_Token_PDU_Request_Msg *token_pdu_request_msg = NULL;
    RA_Token_PDU_Response_Msg *token_pdu_response_msg = NULL;
    Buffer *mac = NULL;

    RA::Debug("Secure_Channel::IsPinPresent",
        "Secure_Channel::IsPinPresent");
    list_pins_apdu = new List_Pins_APDU(2);

    /*
    mac = ComputeAPDUMac(set_pin_apdu);
    set_pin_apdu->SetMAC(*mac);
    */
    token_pdu_request_msg = new RA_Token_PDU_Request_Msg(
        list_pins_apdu);
    session->WriteMsg(token_pdu_request_msg);
    RA::Debug("Secure_Channel::IsPinPresent",
        "Sent token_pdu_request_msg");

    token_pdu_response_msg = (RA_Token_PDU_Response_Msg *)
        session->ReadMsg();
    if (token_pdu_response_msg == NULL)
    {
        RA::Error("Secure_Channel::IsPinReset",
            "No Token PDU Response Msg Received");
        goto loser;
    }
    if (token_pdu_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
	   RA::Error(LL_PER_PDU, "RA_Processor::IsPinReset", 
		"Invalid Message Type");
           goto loser;
    }
    response = token_pdu_response_msg->GetResponse();
    if (response == NULL) {
        RA::Error("Secure_Channel::IsPinReset",
            "No Response From Token");
        goto loser;
    }
    data = response->GetData();
    if (data.size() < 2) { 
  	RA::Error(LL_PER_PDU, "Secure_Channel::IsPinReset", 
		"Invalid Response From Token");
          goto loser;
    }

    if (pin_number < 8) {
       rc = ((((BYTE*)data)[1] & (1 << pin_number)) > 0);
    } else {
       rc = ((((BYTE*)data)[0] & (1 << (pin_number - 8))) > 0);
    }

loser:
    if( mac != NULL ) {
        delete mac;
        mac = NULL;
    }
    if( token_pdu_request_msg != NULL ) {
        delete token_pdu_request_msg;
        token_pdu_request_msg = NULL;
    }
    if( token_pdu_response_msg != NULL ) {
        delete token_pdu_response_msg;
        token_pdu_response_msg = NULL;
    }

    return rc;
}

/**
 * Select applet.
 *
 * Global Platform Open Platform Card Specification 
 * Version 2.0.1 Page 9-22
 *
 * Sample Data:
 *
 * _____________ CLA
 * |  __________ INS
 * |  |  _______ P1
 * |  |  |  ____ P2
 * |  |  |  |  _ Len
 * |  |  |  |  |
 * 00 A4 04 00 07
 * 53 4C 42 47 49 4E 41
 */
int RA_Processor::SelectApplet(RA_Session *session, BYTE p1, BYTE p2, Buffer *aid)
{
    int rc = 0;
    APDU_Response *select_response = NULL;
    RA_Token_PDU_Request_Msg *select_request_msg = NULL;
    RA_Token_PDU_Response_Msg *select_response_msg = NULL;
    Select_APDU *select_apdu = NULL;

    if (aid != NULL) {
      RA::DebugBuffer(LL_PER_PDU, "RA_Processor::SelectApplet",
		      "RA_Processor::SelectApplet with aid= ", aid);
    }

    select_apdu = new Select_APDU(p1, p2, *aid);
    select_request_msg =
        new RA_Token_PDU_Request_Msg(select_apdu);
    session->WriteMsg(select_request_msg);

    RA::Debug(LL_PER_PDU, "RA_Processor::SelectApplet",
        "Sent select_request_msg");

    select_response_msg = (RA_Token_PDU_Response_Msg *)
        session->ReadMsg();
    if (select_response_msg == NULL)
    {
        RA::Error(LL_PER_PDU, "RA_Processor::SelectApplet",
            "No Token PDU Response Msg Received");
        goto loser;
    }
    if (select_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
	   RA::Error(LL_PER_PDU, "Secure_Channel::SelectApplet", 
		"Invalid Message Type");
           goto loser;
    }
    select_response = select_response_msg->GetResponse();
    if (select_response == NULL) { 
	   RA::Error(LL_PER_PDU, "Secure_Channel::SelectApplet", 
		"No Response From Token");
           goto loser;
    }
    if (select_response->GetData().size() < 2) { 
  	RA::Error(LL_PER_PDU, "Secure_Channel::SelectApplet", 
		"Invalid Response From Token");
          goto loser;
    }
    if (!(select_response->GetSW1() == 0x90 && 
        select_response->GetSW2() == 0x00)) {
    	RA::Error(LL_PER_PDU, "RA_Processor::SelectApplet",
            "Bad Response");
	goto loser;
    }


loser:
    if( select_request_msg != NULL ) {
        delete select_request_msg;
        select_request_msg = NULL;
    }
    if( select_response_msg != NULL ) {
        delete select_response_msg;
        select_response_msg = NULL;
    }

    return rc;
}

/**
 * Get Build ID from Net Key Applet.
 * @returns a buffer with 4 bytes of data. This is the applet ID. 
 *    The caller is responsible for freeing the buffer with 
 *    the 'delete' operator.
 */
Buffer *RA_Processor::GetAppletVersion(RA_Session *session)
{
    Buffer data;
    Buffer *buildID = NULL;
    APDU_Response *get_version_response = NULL;
    RA_Token_PDU_Request_Msg *get_version_request_msg = NULL;
    RA_Token_PDU_Response_Msg *get_version_response_msg = NULL;
    Get_Version_APDU *get_version_apdu = NULL;
    Buffer get_version_data;

    get_version_apdu =
        new Get_Version_APDU();
    get_version_request_msg =
        new RA_Token_PDU_Request_Msg(get_version_apdu);
    session->WriteMsg(get_version_request_msg);
    RA::Debug(LL_PER_PDU, "RA_Processor::GetAppletVersion",
        "Sent get_version_request_msg");

    get_version_response_msg = (RA_Token_PDU_Response_Msg *)
        session->ReadMsg();
    if (get_version_response_msg == NULL)
    {
        RA::Error(LL_PER_PDU, "RA_Processor::GetAppletVersion",
            "No Token PDU Response Msg Received");
        goto loser;
    }
    if (get_version_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
	   RA::Error(LL_PER_PDU, "RA_Processor::GetAppletVersion", 
		"Invalid Message Type");
           goto loser;
    }
    get_version_response =
        get_version_response_msg->GetResponse();
    if (get_version_response == NULL) { 
	   RA::Error(LL_PER_PDU, "Secure_Channel::GetAppletVersion", 
		"No Response From Token");
           goto loser;
    }
    data = get_version_response->GetData();
    if (!(get_version_response->GetSW1() == 0x90 && 
        get_version_response->GetSW2() == 0x00)) {
    	RA::Error(LL_PER_PDU, "RA_Processor::GetAppletVersion",
            "Bad Response");
	goto loser;
    }

    /* Sample: 3FBAB4BF9000 */
    if (data.size() != 6) {
	   RA::Error(LL_PER_PDU, "Secure_Channel::GetAppletVersion", 
		"Invalid Applet Version data.size %d",data.size());
           RA::DebugBuffer(LL_PER_PDU, "RA_Processor::GetAppletVersion",
                "Bad Applet Version: ",
           &data);

	    goto loser;
    }

    buildID = new Buffer(data.substr(0, 4));

/*
    buildID = (get_version_data[0] << 24) | (get_version_data[1] << 16) |
	      (get_version_data[2] << 8) | get_version_data[3];

*/ 

loser:

    if( get_version_request_msg != NULL ) {
        delete get_version_request_msg;
        get_version_request_msg = NULL;
    }
    if( get_version_response_msg != NULL ) {
        delete get_version_response_msg;
        get_version_response_msg = NULL;
    }
    return buildID;
}

/*
 * this one sets the security level
 */
Secure_Channel *RA_Processor::SetupSecureChannel(RA_Session *session, 
     BYTE key_version, BYTE key_index, SecurityLevel security_level,
     const char *connId)
{
    Secure_Channel *channel = SetupSecureChannel(session, key_version, key_index, connId);
    RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel","Resetting security level ...");

    /* Bugscape Bug #55774: Prevent NetKey RA from crashing . . . */
    if( channel != NULL ) {
        channel->SetSecurityLevel(security_level);
    } else {
        RA::Error( LL_PER_PDU, "RA_Processor::SetupSecureChannel", "%s %s",
			       "Failed to create a secure channel - potentially due to an",
                   "RA/TKS key mismatch or differing RA/TKS key versions." );
    }
    return channel;
  
}

int RA_Processor::InitializeUpdate(RA_Session *session, 
     BYTE key_version, BYTE key_index, 
     Buffer &key_diversification_data,
     Buffer &key_info_data,
     Buffer &card_challenge,
     Buffer &card_cryptogram,
     Buffer &host_challenge, const char *connId)
{
    int rc = -1;
    APDU_Response *initialize_update_response = NULL;
    RA_Token_PDU_Request_Msg *initialize_update_request_msg = NULL;
    RA_Token_PDU_Response_Msg *initialize_update_response_msg = NULL;
    Initialize_Update_APDU *initialize_update_apdu = NULL;
    Buffer update_response_data;
    char configname[256];

    RA::Debug(LL_PER_PDU, "RA_Processor::InitializeUpdate",
        "RA_Processor::InitializeUpdate");


    PR_snprintf((char *) configname, 256, "conn.%s.generateHostChallenge", connId);
    bool gen_host_challenge_tks  = RA::GetConfigStore()->GetConfigAsBool(configname, true);

    if(gen_host_challenge_tks) {
        RA::Debug(LL_PER_PDU, "RA_Processor::InitializeUpdate",
        "Generate host challenge on TKS.");
        rc = ComputeRandomData(host_challenge, (int) host_challenge.size(), connId);
    } else {
        rc = Util::GetRandomChallenge(host_challenge);
    }

    if(rc == -1) {
        RA::Debug(LL_PER_PDU, "RA_Processor::InitializeUpdate",
            "Failed to generate host challenge");
        goto loser;

    }

    RA::DebugBuffer(LL_PER_PDU, "RA_Processor::InitializeUpdate",
        "Generated Host Challenge",
        &host_challenge);

    initialize_update_apdu =
        new Initialize_Update_APDU(key_version, key_index, host_challenge);
    initialize_update_request_msg =
        new RA_Token_PDU_Request_Msg(initialize_update_apdu);
    session->WriteMsg(initialize_update_request_msg);
    RA::Debug(LL_PER_PDU, "RA_Processor::InitializeUpdate",
        "Sent initialize_update_request_msg");

    initialize_update_response_msg = (RA_Token_PDU_Response_Msg *)
        session->ReadMsg();
    if (initialize_update_response_msg == NULL)
    {
    	RA::Error(LL_PER_PDU, "RA_Processor::InitializeUpdate",
            "No Token PDU Response Msg Received");
        goto loser;
    }
    if (initialize_update_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
	   RA::Error(LL_PER_PDU, "RA_Processor::InitializeUpdate", 
		"Invalid Message Type");
           goto loser;
    }
    initialize_update_response =
        initialize_update_response_msg->GetResponse();
    update_response_data = initialize_update_response->GetData();

    if (!(initialize_update_response->GetSW1() == 0x90 && 
        initialize_update_response->GetSW2() == 0x00)) {
    	RA::Debug(LL_PER_PDU, "RA_Processor::InitializeUpdate",
            "Key version mismatch - key changeover to follow");
	goto loser;
    }

    RA::DebugBuffer(LL_PER_PDU, "RA_Processor::InitializeUpdate",
        "Update Response Data", &update_response_data);

    /**
     * Initialize Update response:
     *   Key Diversification Data - 10 bytes
     *   Key Information Data - 2 bytes
     *   Card Challenge - 8 bytes
     *   Card Cryptogram - 8 bytes
     */
    if (initialize_update_response->GetData().size() < 10) {
    	RA::Error(LL_PER_PDU, "RA_Processor::InitializeUpdate",
            "Invalid Initialize Update Response Size");
	goto loser;
    }
    key_diversification_data = Buffer(update_response_data.substr(0, 10));
    RA::DebugBuffer(LL_PER_PDU, "RA_Processor::InitializeUpdate",
        "Key Diversification Data", &key_diversification_data);
    key_info_data = Buffer(update_response_data.substr(10, 2));
    RA::DebugBuffer(LL_PER_PDU, "RA_Processor::InitializeUpdate",
        "Key Info Data", &key_info_data);
    card_challenge = Buffer(update_response_data.substr(12, 8));
    RA::DebugBuffer(LL_PER_PDU, "RA_Processor::InitializeUpdate",
        "Card Challenge", &card_challenge);
    card_cryptogram = Buffer(update_response_data.substr(20, 8));
    RA::DebugBuffer(LL_PER_PDU, "RA_Processor::InitializeUpdate",
        "Card Cryptogram", &card_cryptogram);

    rc = 1;

loser:
    if( initialize_update_request_msg != NULL ) {
        delete initialize_update_request_msg;
        initialize_update_request_msg = NULL;
    }
    if( initialize_update_response_msg != NULL ) {
        delete initialize_update_response_msg;
        initialize_update_response_msg = NULL;
    }

    return rc;
}

/**
 * Setup secure channel between RA and the token.
 */
Secure_Channel *RA_Processor::SetupSecureChannel(RA_Session *session, 
     BYTE key_version, BYTE key_index, const char *connId)
{
    Secure_Channel *channel = NULL;
    APDU_Response *initialize_update_response = NULL;
    RA_Token_PDU_Request_Msg *initialize_update_request_msg = NULL;
    RA_Token_PDU_Response_Msg *initialize_update_response_msg = NULL;
    Initialize_Update_APDU *initialize_update_apdu = NULL;
    Buffer update_response_data;
    Buffer host_challenge = Buffer(8, (BYTE)0);
    Buffer key_diversification_data;
    Buffer key_info_data;
    Buffer card_challenge;
    Buffer card_cryptogram;
    char configname[256];

    RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
        "RA_Processor::Setup_Secure_Channel");

    PR_snprintf((char *) configname, 256, "conn.%s.generateHostChallenge", connId);
    bool gen_host_challenge_tks  = RA::GetConfigStore()->GetConfigAsBool(configname, false);

    int rc = 0;
    if(gen_host_challenge_tks) {
        RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
        "Generate host challenge on TKS.");
        rc = ComputeRandomData(host_challenge, (int) host_challenge.size(), connId);
    } else {
        rc = Util::GetRandomChallenge(host_challenge); 
    }

    if(rc == -1) {
        RA::Debug(LL_PER_PDU, "RA_Processor::SetupSecureChannel",
            "Failed to generate host challenge");
        goto loser;

    }



 /*   if (Util::GetRandomChallenge(host_challenge) != PR_SUCCESS)
    {
        RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
            "Failed to generate host challenge");
        goto loser;
    }

*/
    RA::DebugBuffer(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
        "Generated Host Challenge",
        &host_challenge);

    initialize_update_apdu =
        new Initialize_Update_APDU(key_version, key_index, host_challenge);
    initialize_update_request_msg =
        new RA_Token_PDU_Request_Msg(initialize_update_apdu);
    session->WriteMsg(initialize_update_request_msg);
    RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
        "Sent initialize_update_request_msg");

    initialize_update_response_msg = (RA_Token_PDU_Response_Msg *)
        session->ReadMsg();
    if (initialize_update_response_msg == NULL)
    {
    	RA::Error(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
            "No Token PDU Response Msg Received");
        goto loser;
    }
    if (initialize_update_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
	   RA::Error(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel", 
		"Invalid Message Type");
           goto loser;
    }
    initialize_update_response =
        initialize_update_response_msg->GetResponse();
    update_response_data = initialize_update_response->GetData();

    if (!(initialize_update_response->GetSW1() == 0x90 && 
        initialize_update_response->GetSW2() == 0x00)) {
    	RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
            "Key version mismatch - key changeover to follow");
	goto loser;
    }

    RA::DebugBuffer(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
        "Update Response Data", &update_response_data);

    /**
     * Initialize Update response:
     *   Key Diversification Data - 10 bytes
     *   Key Information Data - 2 bytes
     *   Card Challenge - 8 bytes
     *   Card Cryptogram - 8 bytes
     */
    if (initialize_update_response->GetData().size() < 28) {
    	RA::Error(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
            "Invalid Initialize Update Response Size");
	goto loser;
    }
    key_diversification_data = Buffer(update_response_data.substr(0, 10));
    RA::DebugBuffer(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
        "Key Diversification Data", &key_diversification_data);
    key_info_data = Buffer(update_response_data.substr(10, 2));
    RA::DebugBuffer(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
        "Key Info Data", &key_info_data);
    card_challenge = Buffer(update_response_data.substr(12, 8));
    RA::DebugBuffer(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
        "Card Challenge", &card_challenge);
    card_cryptogram = Buffer(update_response_data.substr(20, 8));
    RA::DebugBuffer(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
        "Card Cryptogram", &card_cryptogram);

    channel = GenerateSecureChannel(
        session, connId,
        key_diversification_data,
        key_info_data,
        card_challenge,
        card_cryptogram,
        host_challenge);

loser:
    if( initialize_update_request_msg != NULL ) {
        delete initialize_update_request_msg;
        initialize_update_request_msg = NULL;
    }
    if( initialize_update_response_msg != NULL ) {
        delete initialize_update_response_msg;
        initialize_update_response_msg = NULL;
    }

    return channel;
} /* SetupSecureChannel */

/**
 * Requests secure ID.
 */
SecureId *RA_Processor::RequestSecureId(RA_Session *session)
{
    SecureId *secure_id = NULL;
    RA_SecureId_Request_Msg *secureid_request_msg = NULL;
    RA_SecureId_Response_Msg *secureid_response_msg = NULL;
    char *value;
    char *pin;

    RA::Debug(LL_PER_PDU, "RA_Processor::SecureId_Request",
        "RA_Processor::SecureId_Request");

    secureid_request_msg = new RA_SecureId_Request_Msg(
        0 /* pin_required */, 0 /* next_value */);
    session->WriteMsg(secureid_request_msg);
    RA::Debug(LL_PER_PDU, "RA_Processor::SecureId_Request",
        "Sent secureid_request_msg");

    secureid_response_msg = (RA_SecureId_Response_Msg *)
        session->ReadMsg();
    if (secureid_response_msg == NULL)
    {
        RA::Error(LL_PER_PDU, "RA_Processor::SecureId_Request",
            "No SecureID Response Msg Received");
        goto loser;
    }

    if (secureid_response_msg->GetType() != MSG_SECUREID_RESPONSE) {
            RA::Error("Secure_Channel::SecureId_Request",
            "Invalid Msg Type");
            goto loser;
    }

    value = secureid_response_msg->GetValue();
    pin = secureid_response_msg->GetPIN();

    secure_id = new SecureId(value, pin);

loser:

    if( secureid_request_msg != NULL ) {
        delete secureid_request_msg;
        secureid_request_msg = NULL;
    }
    if( secureid_response_msg != NULL ) {
        delete secureid_response_msg;
        secureid_response_msg = NULL;
    }
    return secure_id;
} /* RequestSecureId */

/**
 * Requests new pin for token.
 */
char *RA_Processor::RequestNewPin(RA_Session *session, unsigned int min, unsigned int max)
{
    char *new_pin = NULL;
    RA_New_Pin_Request_Msg *new_pin_request_msg = NULL;
    RA_New_Pin_Response_Msg *new_pin_response_msg = NULL;

    RA::Debug(LL_PER_PDU, "RA_Processor::New_Pin_Request",
        "RA_Processor::New_Pin_Request");

    new_pin_request_msg = new RA_New_Pin_Request_Msg(
        min, max);
    session->WriteMsg(new_pin_request_msg);
    RA::Debug(LL_PER_PDU, "RA_Processor::New_Pin_Request",
        "Sent new_pin_request_msg");

    new_pin_response_msg = (RA_New_Pin_Response_Msg *)
        session->ReadMsg();
    if (new_pin_response_msg == NULL)
    {
        RA::Error(LL_PER_PDU, "RA_Processor::New_Pin_Request",
            "No New Pin Response Msg Received");
        goto loser;
    }

    if (new_pin_response_msg->GetType() != MSG_NEW_PIN_RESPONSE) {
        RA::Error(LL_PER_PDU, "RA_Processor::New_Pin_Request",
            "Invalid Message Type");
        goto loser;
    }

    if (new_pin_response_msg->GetNewPIN() == NULL) {
        RA::Error(LL_PER_PDU, "RA_Processor::New_Pin_Request",
            "No New Pin");
        goto loser;
    }

    new_pin = PL_strdup(new_pin_response_msg->GetNewPIN());

    if (strlen(new_pin) < min) {
        RA::Error(LL_PER_PDU, "RA_Pin_Reset_Processor::Process",
          "The length of the new pin is shorter than the mininum length (%d)", min);
        if( new_pin != NULL ) {
            PL_strfree( new_pin );
            new_pin = NULL;
        }
        new_pin = NULL;
        goto loser;
    } else if (strlen(new_pin) > max) {
        RA::Error(LL_PER_PDU, "RA_Pin_Reset_Processor::Process",
          "The length of the new pin is longer than the maximum length (%d)", max);
        if( new_pin != NULL ) {
            PL_strfree( new_pin );
            new_pin = NULL;
        }
        new_pin = NULL;
        goto loser;
    }

loser:

    if( new_pin_request_msg != NULL ) {
        delete new_pin_request_msg;
        new_pin_request_msg = NULL;
    }
    if( new_pin_response_msg != NULL ) {
        delete new_pin_response_msg;
        new_pin_response_msg = NULL;
    }

    return new_pin;
} /* RequestNewPin */

/**
 * Requests A Security Question (ASQ) from user.
 */
char *RA_Processor::RequestASQ(RA_Session *session, char *question)
{
    char *answer = NULL;
    RA_ASQ_Request_Msg *asq_request_msg = NULL;
    RA_ASQ_Response_Msg *asq_response_msg = NULL;

    RA::Debug(LL_PER_PDU, "RA_Processor::ASQ_Request",
        "RA_Processor::ASQ_Request");

    asq_request_msg = new RA_ASQ_Request_Msg(question);
    session->WriteMsg(asq_request_msg);
    RA::Debug(LL_PER_PDU, "RA_Processor::ASQ_Request",
        "Sent asq_request_msg");

    asq_response_msg = (RA_ASQ_Response_Msg *)
        session->ReadMsg();
    if (asq_response_msg == NULL)
    {
        RA::Error(LL_PER_PDU, "RA_Processor::ASQ_Request",
            "No ASQ Response Msg Received");
        goto loser;
    }
    if (asq_response_msg->GetType() != MSG_ASQ_RESPONSE) {
        RA::Error(LL_PER_PDU, "RA_Processor::ASQ_Request",
            "Invalid Message Type");
        goto loser;
    }

    if (asq_response_msg->GetAnswer() == NULL) {
        RA::Error(LL_PER_PDU, "RA_Processor::ASQ_Request",
            "No ASQ Answer");
        goto loser;
    }
    answer = PL_strdup(asq_response_msg->GetAnswer());

loser:
    if( asq_request_msg != NULL ) {
        delete asq_request_msg;
        asq_request_msg = NULL;
    }
    if( asq_response_msg != NULL ) {
        delete asq_response_msg;
        asq_response_msg = NULL;
    }

    return answer;
} /* RequestASQ */

/**
 * Creates a secure channel between RA and the token.
 * challenges are sent to TKS which generates
 * host cryptogram, and session key.
 */
Secure_Channel *RA_Processor::GenerateSecureChannel(
    RA_Session *session, const char *connId,
    Buffer &key_diversification_data, /* CUID */
    Buffer &key_info_data,
    Buffer &card_challenge,
    Buffer &card_cryptogram,
    Buffer &host_challenge)
{
    PK11SymKey *session_key = NULL;
    Buffer *host_cryptogram = NULL;
    char configname[256];

    RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
        "RA_Processor::GenerateSecureChannel");

    PK11SymKey *enc_session_key = NULL;


    // desKey_s will be assigned to channel and will be destroyed when channel closed
    char *drm_desKey_s = NULL;
    char *kek_desKey_s = NULL;
    char *keycheck_s = NULL;

    session_key = RA::ComputeSessionKey(session, key_diversification_data, 
                                        key_info_data, card_challenge,
                                        host_challenge, &host_cryptogram, 
		                                card_cryptogram, &enc_session_key,
                                        &drm_desKey_s, &kek_desKey_s,
                                        &keycheck_s, connId);
    if (session_key == NULL) {
      RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
	  "RA_Processor::GenerateSecureChannel - did not get session_key");
         return NULL;
    }

    // is serversideKeygen on?
    PR_snprintf((char *) configname, 256, "conn.%s.serverKeygen", connId);
    bool serverKeygen = RA::GetConfigStore()->GetConfigAsBool(configname, false);

    if (serverKeygen) {
      if ((drm_desKey_s == "") || (drm_desKey_s == NULL)) {
	RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
		  "RA_Processor::GenerateSecureChannel - did not get drm_desKey_s");
	return NULL;
      } else {
	RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
		  "RA_Processor::GenerateSecureChannel - drm_desKey_s = %s", drm_desKey_s);
      }
      if ((kek_desKey_s == "") || (kek_desKey_s == NULL)) {
	RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
		  "RA_Processor::GenerateSecureChannel - did not get kek_desKey_s");
	return NULL;
      } else {
	RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
		  "RA_Processor::GenerateSecureChannel - kek_desKey_s = %s", kek_desKey_s);
      }
      if ((keycheck_s == "") || (keycheck_s == NULL)) {
	RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
		  "RA_Processor::GenerateSecureChannel - did not get keycheck_s");
	return NULL;
    }

    if (enc_session_key == NULL) {
      RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
	  "RA_Processor::GenerateSecureChannel - did not get enc_session_key");
         return NULL;
    }
    if (host_cryptogram == NULL) {
      RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
	  "RA_Processor::GenerateSecureChannel - did not get host_cryptogram");
         return NULL;
      } else {
	RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
		  "RA_Processor::GenerateSecureChannel - keycheck_s = %s", keycheck_s);
      }
    }
/*
    host_cryptogram = RA::ComputeHostCryptogram(
        card_challenge, host_challenge);
*/


    Secure_Channel *channel = new Secure_Channel(session, session_key,
						 enc_session_key,
						 drm_desKey_s, kek_desKey_s, keycheck_s,
        key_diversification_data, key_info_data,
        card_challenge, card_cryptogram,
        host_challenge, *host_cryptogram);

    if( host_cryptogram != NULL ) {
      delete host_cryptogram;
      host_cryptogram = NULL;
    }

    if (channel != NULL) {
        // this can be overridden by individual processor later
        channel->SetSecurityLevel(RA::GetGlobalSecurityLevel());
    } else {
        if( session_key != NULL ) {
            PK11_FreeSymKey( session_key );
            session_key = NULL;
        }
        if( enc_session_key != NULL ) {
            PK11_FreeSymKey( enc_session_key );
            enc_session_key = NULL;
        }

    }

    RA::Debug(LL_PER_PDU, "RA_Processor::GenerateSecureChannel", "complete");
    return channel;
} /* GenerateSecureChannel */

int RA_Processor::CreateKeySetData(Buffer &CUID, Buffer &version, 
  Buffer &NewMasterVer, Buffer &out, const char *connid)
{
    char body[5000];
    char configname[256];
    HttpConnection *tksConn = NULL;
    tksConn = RA::GetTKSConn(connid);
    if (tksConn == NULL) {
        RA::Debug(LL_PER_PDU, "RA_Processor::CreateKeySetData", "Failed to get TKSConnection %s", connid);
        RA::Error(LL_PER_PDU, "RA_Processor::CreateKeySetData", "Failed to get TKSConnection %s", connid);
        return -1;
    } else {
        // PRLock *tks_lock = RA::GetTKSLock();
        int tks_curr = RA::GetCurrentIndex(tksConn);
        int currRetries = 0;
        char *cuid = Util::SpecialURLEncode(CUID);
        char *versionID = Util::SpecialURLEncode(version);
        char *masterV = Util::SpecialURLEncode(NewMasterVer);

        PR_snprintf((char *)configname, 256, "conn.%s.keySet", connid);
        const char *keySet = RA::GetConfigStore()->GetConfigAsString(configname);

        PR_snprintf((char *)body, 5000,
           "newKeyInfo=%s&CUID=%s&KeyInfo=%s&keySet=%s", masterV, cuid, versionID,keySet);

        PR_snprintf((char *)configname, 256, "conn.%s.servlet.createKeySetData", connid);
        const char *servletID = RA::GetConfigStore()->GetConfigAsString(configname);

        if( cuid != NULL ) {
            PR_Free( cuid );
            cuid = NULL;
        }
        if( versionID != NULL ) {
            PR_Free( versionID );
            versionID = NULL;
        }
        if( masterV != NULL ) {
            PR_Free( masterV );
            masterV = NULL;
        }

        tks_curr = RA::GetCurrentIndex(tksConn);

        PSHttpResponse * response = tksConn->getResponse(tks_curr, servletID, body);
        ConnectionInfo *connInfo = tksConn->GetFailoverList();
        char **hostport = connInfo->GetHostPortList();

        if (response == NULL)
            RA::Debug(LL_PER_PDU, "The CreateKeySetData response from TKS ",
              "at %s is NULL.", hostport[tks_curr]);
        else
            RA::Debug(LL_PER_PDU, "The CreateKeySetData response from TKS ",
              "at % is not NULL.", hostport[tks_curr]);

        while (response == NULL) {
            RA::Failover(tksConn, connInfo->GetHostPortListLen());
            tks_curr = RA::GetCurrentIndex(tksConn);

            RA::Debug(LL_PER_PDU, "RA is reconnecting to TKS ",
              "at %s for createKeySetData.", hostport[tks_curr]);

            if (++currRetries >= tksConn->GetNumOfRetries()) {
                RA::Debug(LL_PER_PDU, "Used up all the retries. Response is NULL","");
                RA::Error(LL_PER_PDU, "RA_Processor::CreateKeySetData","Failed connecting to TKS after %d retries", currRetries);
                if (tksConn != NULL) {
                    RA::ReturnTKSConn(tksConn);
                }
                return -1;
            }
            response = tksConn->getResponse(tks_curr, servletID, body);
        }

        int status = 0;

        Buffer *keydataset = NULL;
        if (response != NULL) {
            RA::Debug(LL_PER_PDU,"Response is not ","NULL");
            char * content = response->getContent();
            if (content == NULL) {
                RA::Debug(LL_PER_PDU,"TKSConnection::CreateKeySetData","Content Is NULL");
            } else {
                RA::Debug(LL_PER_PDU,"TKSConnection::CreateKeySetData","Content Is '%s'",
                                        content);
            }
            if (content != NULL) {
                char *statusStr = strstr((char *)content, "status=0&");
                if (statusStr == NULL) {
                    status = 1;
                    char *p = strstr((char *)content, "status=");
                    if(p != NULL) {
                        status = int(p[7]) - 48;
		    } else {
			status = 4;
                        return -1;
		    }
                } else {
                    status = 0;
                    char *p = &content[9];
                    char *rcStr = strstr((char *)p, "keySetData=");
                    if (rcStr != NULL) {
                        rcStr = &rcStr[11];
                        if (!strcmp(rcStr, "%00")) {
                            return -1;
                        }
                        keydataset = Util::URLDecode(rcStr);
                    }
                }
            }
        }

        if (keydataset == NULL)
        {
            RA::Debug(LL_PER_PDU, "RA_Processor:CreateKeySetData",
              "Key Set Data is NULL");

               return -1;
        }

        RA::Debug(LL_PER_PDU, "RA_Processor:CreateKeySetData", "Status of CreateKeySetData=%d", status);
        RA::Debug(LL_PER_PDU, "finish CreateKeySetData", "");

        if (status > 0) {
	    if (tksConn != NULL) {
                RA::ReturnTKSConn(tksConn);
	    }
            return -1;
	} else {
            out = *keydataset;
            if( keydataset != NULL ) {
                delete keydataset;
                keydataset = NULL;
            }
        }

        if( response != NULL ) {
            response->freeContent();
            delete response;
            response = NULL;
        }

	if (tksConn != NULL) {
            RA::ReturnTKSConn(tksConn);
	}
        return 1;
    }
        BYTE kek_key[] = {
                0x40, 0x41, 0x42, 0x43,
                0x44, 0x45, 0x46, 0x47,
                0x48, 0x49, 0x4a, 0x4b,
                0x4c, 0x4d, 0x4e, 0x4f
        };
        BYTE key[] = {
                0x40, 0x41, 0x42, 0x43,
                0x44, 0x45, 0x46, 0x47,
                0x48, 0x49, 0x4a, 0x4b,
                0x4c, 0x4d, 0x4e, 0x4f
        };
    Buffer old_kek_key(kek_key, 16);
    Buffer new_auth_key(key, 16);
    Buffer new_mac_key(key, 16);
    Buffer new_kek_key(key, 16);


        Util::CreateKeySetData(
             NewMasterVer,
             old_kek_key,
             new_auth_key,
             new_mac_key,
             new_kek_key,
             out);

	if (tksConn != NULL) {
		RA::ReturnTKSConn(tksConn);
	}
   return 1;
}


/**
 * Input data wrapped by KEK key in TKS.
 */
int RA_Processor::EncryptData(Buffer &CUID, Buffer &version, Buffer &in, Buffer &out, const char *connid)
{
    char body[5000];
    char configname[256];
#define PLAINTEXT_CHALLENGE_SIZE 16
	// khai, here we wrap the input with the KEK key
	// in TKS
        HttpConnection *tksConn = NULL;
        char kek_key[16] = {
                0x40, 0x41, 0x42, 0x43,
                0x44, 0x45, 0x46, 0x47,
                0x48, 0x49, 0x4a, 0x4b,
                0x4c, 0x4d, 0x4e, 0x4f
        };
    int status = 0;

    tksConn = RA::GetTKSConn(connid);
    if (tksConn == NULL) {
        RA::Debug(LL_PER_PDU, "RA_Processor::EncryptData", "Failed to get TKSConnection %s", connid);
        RA::Debug(LL_PER_PDU, "RA_Processor::EncryptData", "Failed to get TKSConnection %s", connid);
        return -1;
    } else {
        int tks_curr = RA::GetCurrentIndex(tksConn);
        int currRetries = 0;
        char *data = NULL;
        Buffer *zerob = new Buffer(PLAINTEXT_CHALLENGE_SIZE, (BYTE)0);
        if (!(in == *zerob))
          data = Util::SpecialURLEncode(in);
        else
          RA::Debug(LL_PER_PDU, "RA_Processor::EncryptData","Challenge to be generated on TKS");

        if (zerob != NULL) {
            delete zerob;
        }

        char *cuid = Util::SpecialURLEncode(CUID);
        char *versionID = Util::SpecialURLEncode(version);

        PR_snprintf((char *)configname, 256, "conn.%s.keySet", connid);
        const char *keySet = RA::GetConfigStore()->GetConfigAsString(configname);

        PR_snprintf((char *)body, 5000, "data=%s&CUID=%s&KeyInfo=%s&keySet=%s",
          ((data != NULL)? data:""), cuid, versionID,keySet);
        PR_snprintf((char *)configname, 256, "conn.%s.servlet.encryptData", connid);
        const char *servletID = RA::GetConfigStore()->GetConfigAsString(configname);

        if( cuid != NULL ) {
            PR_Free( cuid );
            cuid = NULL;
        }
        if( versionID != NULL ) {
            PR_Free( versionID );
            versionID = NULL;
        }

        PSHttpResponse *response = tksConn->getResponse(tks_curr, servletID, body);
        ConnectionInfo *connInfo = tksConn->GetFailoverList();
        char **hostport = connInfo->GetHostPortList();
        if (response == NULL)
            RA::Debug(LL_PER_PDU, "The encryptedData response from TKS ",
              "at %s is NULL.", hostport[tks_curr]);
        else
            RA::Debug(LL_PER_PDU, "The encryptedData response from TKS ",
              "at %s is not NULL.", hostport[tks_curr]);

        while (response == NULL) {
            RA::Failover(tksConn, connInfo->GetHostPortListLen());
            tks_curr = RA::GetCurrentIndex(tksConn);
            RA::Debug(LL_PER_PDU, "RA is reconnecting to TKS ",
              "at %s for encryptData.", hostport[tks_curr]);

            if (++currRetries >= tksConn->GetNumOfRetries()) {
                RA::Debug(LL_PER_PDU, "Used up all the retries. Response is NULL","");
                RA::Error(LL_PER_PDU, "RA_Processor::EncryptData", "Failed connecting to TKS after %d retries", currRetries);
                if (tksConn != NULL) {
		          RA::ReturnTKSConn(tksConn);
	            }
                return -1;
            }
            response = tksConn->getResponse(tks_curr, servletID, body);
        }

        Buffer *encryptedData = NULL;
        // preEncData is only useful when data is null, and data is to be randomly
        // generated on TKS
        Buffer *preEncData = NULL;
        status = 0;
        if (response != NULL) {
            RA::Debug(LL_PER_PDU, "EncryptData Response is not ","NULL");
            char *content = response->getContent();
            if (content != NULL) {
                char *statusStr = strstr((char *)content, "status=0&");
                if (statusStr == NULL) {
                    char *p = strstr((char *)content, "status=");

                    if(p != NULL) {
                        status = int(p[7]) - 48;
		    } else {
			status = 4;
                        return -1;
		    }
                } else {
                    status = 0;
                    char *p = &content[9];
                    // get pre-encryption data
                    char *preStr = strstr((char *)p, "data=");
                    if (preStr != NULL) {
                      p = &preStr[5];
                      char pstr[PLAINTEXT_CHALLENGE_SIZE*3+1];
                      strncpy(pstr, p, PLAINTEXT_CHALLENGE_SIZE*3); 
                      pstr[PLAINTEXT_CHALLENGE_SIZE*3] = '\0';
                      preEncData = Util::URLDecode(pstr);
//RA::DebugBuffer("RA_Processor::EncryptData", "preEncData=", preEncData);
                    }

                    // get encrypted data
                    p = &content[9];
                    char *rcStr = strstr((char *)p, "encryptedData=");
                    if (rcStr != NULL) {
                        rcStr = &rcStr[14];
                        encryptedData = Util::URLDecode(rcStr);
//RA::DebugBuffer("RA_Processor::EncryptData", "encryptedData=", encryptedData);
                    }
                }
            }
        }
        if (encryptedData == NULL)
            RA::Debug(LL_PER_PDU, "RA_Processor:GetEncryptedData",
                "Encrypted Data is NULL");

        RA::Debug(LL_PER_PDU, "EncryptedData ", "status=%d", status);
        RA::Debug(LL_PER_PDU, "finish EncryptedData", "");
        if ((status > 0) || (preEncData == NULL) || (encryptedData == NULL)) {
            if (tksConn != NULL) {
                RA::ReturnTKSConn(tksConn);
	        }
            if( data != NULL ) {
                PR_Free( data );
                data = NULL;
            }
            return -1;   
	    } else {
            out = *encryptedData;
            if( encryptedData != NULL ) {
                delete encryptedData;
                encryptedData = NULL;
            }
            if (data != NULL) {
                RA::Debug(LL_PER_PDU, "EncryptedData ", "challenge overwritten by TKS");
                PR_Free( data );
                data = NULL;
            }
            in = *preEncData;

            if( preEncData != NULL ) {
                delete preEncData;
                preEncData = NULL;
            }
        }
        if( response != NULL ) {
            response->freeContent();
            delete response;
            response = NULL;
        }

        if (tksConn != NULL) {
            RA::ReturnTKSConn(tksConn);
	    }
        return 1;
    }

	Buffer kek_buffer = Buffer((BYTE*)kek_key, 16);
	status = Util::EncryptData(kek_buffer, in, out);
#if 0
        RA::DebugBuffer(LL_PER_PDU, "RA_Processor::EncryptData", "Encrypted Data",
		&out);
        Buffer out1 = Buffer(16, (BYTE)0);
	status = Util::DecryptData(kek_buffer, out, out1);
        RA::DebugBuffer(LL_PER_PDU, "RA_Processor::EncryptData", "Clear Data",
		&out1);
#endif
        if (tksConn != NULL) {
	    RA::ReturnTKSConn(tksConn);
	}
	return status;
}

int RA_Processor::ComputeRandomData(Buffer &data_out, int dataSize,  const char *connid)
{
    char body[5000];
    char configname[256];
    HttpConnection *tksConn = NULL;
    int status = -1;
    Buffer *decodedRandomData = NULL;
    PSHttpResponse *response = NULL;

    //check for absurd dataSize values
    if(dataSize <= 0 || dataSize > 1024) {
        RA::Debug(LL_PER_PDU, "RA_Processor::ComputeRandomData", "Invalid dataSize requested %d", dataSize);
        return -1;
    }

    tksConn = RA::GetTKSConn(connid);
    if (tksConn == NULL) {
        RA::Debug(LL_PER_PDU, "RA_Processor::ComputeRandomData", "Failed to get TKSConnection %s", connid);
        return -1;
    } else {
        int tks_curr = RA::GetCurrentIndex(tksConn);
        int currRetries = 0;
        char *data = NULL;

        PR_snprintf((char *)body, 5000, "dataNumBytes=%d"
          , dataSize );

        PR_snprintf((char *)configname, 256, "conn.%s.servlet.computeRandomData", connid);
        const char *servletID = RA::GetConfigStore()->GetConfigAsString(configname);

        response = tksConn->getResponse(tks_curr, servletID, body);
        ConnectionInfo *connInfo = tksConn->GetFailoverList();
        char **hostport = connInfo->GetHostPortList();
        if (response == NULL)
            RA::Debug(LL_PER_PDU, "The ComputeRandomData response from TKS ",
              "at %s is NULL.", hostport[tks_curr]);
        else
            RA::Debug(LL_PER_PDU, "The ComputeRandomData response from TKS ",
              "at %s is not NULL.", hostport[tks_curr]);

        while (response == NULL) {
            RA::Failover(tksConn, connInfo->GetHostPortListLen());
            tks_curr = RA::GetCurrentIndex(tksConn);
            RA::Debug(LL_PER_PDU, "RA_Processor::ComputeRandomData: RA is reconnecting to TKS ",
              "at %s for ComputeRandomData.", hostport[tks_curr]);

            if (++currRetries >= tksConn->GetNumOfRetries()) {
                RA::Debug(LL_PER_PDU, "RA_Processor::ComputeRandomData: Used up all the retries. Response is NULL","");
                RA::Error(LL_PER_PDU, "RA_Processor::ComputeRandomData", "Failed connecting to TKS after %d retries", currRetries);
                if (tksConn != NULL) {
		          RA::ReturnTKSConn(tksConn);
	            }
                status = -1;
                goto loser;
            }
            response = tksConn->getResponse(tks_curr, servletID, body);
        }

        Buffer *randomData = NULL;
        status = 0;
        if (response != NULL) {
            RA::Debug(LL_PER_PDU, "RA_Processor::ComputeRandomData Response is not ","NULL");
            char *content = response->getContent();
            if (content != NULL) {
                char *statusStr = strstr((char *)content, "status=0&");
                if (statusStr == NULL) {
                    char *p = strstr((char *)content, "status=");

                    if(p != NULL) {
                        status = int(p[7]) - 48;

                        RA::Debug(LL_PER_PDU, "RA_Processor::ComputeRandomData status from TKS is ","status %d",status);
                        status = -1;
		    } else {
			status = -1;
                        goto loser;
		    }
                } else {
                    status = 0;
                    // skip over "status=0&"
                    char *p = &content[9];

                    // get random data
                    char *dataStr = strstr((char *)p, "DATA=");
                    if (dataStr != NULL) {
                      // skip over "DATA="
                      p = &dataStr[5];

                      char *dstr = new char[ dataSize *3 + 1];
                      if(!dstr) {
                          status = -1;
                          goto loser;
                      }
                      strncpy(dstr, p, dataSize * 3); 
                      dstr[dataSize*3] = '\0';
                      decodedRandomData = Util::URLDecode(dstr);
                      RA::DebugBuffer("RA_Processor::ComputeRandomData", "decodedRandomData=", decodedRandomData);

                      if(dstr) {
                          data_out = *decodedRandomData;
                          delete [] dstr;
                          dstr = NULL;
                      }
                      if(decodedRandomData) {
                         delete decodedRandomData;
                         decodedRandomData = NULL;
                      }
                }
            }
        }
    }
  }
loser:
    if( response != NULL ) {
        response->freeContent();
        delete response;
        response = NULL;
    }

    if (tksConn != NULL) {
       RA::ReturnTKSConn(tksConn);
    }

    return status;
}

bool RA_Processor::RevokeCertificates(RA_Session *session, char *cuid,char *audit_msg, 
                                	char *final_applet_version, 
                                	char *keyVersion, 
                                	char *tokenType,
                                        char *userid,
                                        RA_Status &status )
{
        char *OP_PREFIX = "op.format";
        char *statusString = NULL;
        char configname[256];
        char filter[512];
        char activity_msg[512];
        char serial[100];
        int rc = 0;
        int statusNum;
        LDAPMessage  *result = NULL;
        LDAPMessage *e = NULL;
        bool revocation_failed = false;

        RA::Debug("RA_Processor::RevokeCertificates","RevokeCertificates! cuid %s",cuid);
        PR_snprintf((char *)filter, 256, "(tokenID=%s)", cuid);
        rc = RA::ra_find_tus_certificate_entries_by_order(filter, 100, &result, 1);
        if (rc == 0) {
            CertEnroll *certEnroll = new CertEnroll();
            for (e = RA::ra_get_first_entry(result); e != NULL; e = RA::ra_get_next_entry(e)) {
                char *attr_status = RA::ra_get_cert_status(e);
                if (strcmp(attr_status, "revoked") == 0) {
                    if (attr_status != NULL) {
                        PL_strfree(attr_status);
                        attr_status = NULL;
                    }
                    rc = RA::ra_delete_certificate_entry(e);
                    continue;
                }

                char *attr_serial= RA::ra_get_cert_serial(e);
                /////////////////////////////////////////////////
                // Raidzilla Bug #57803:
                // If the certificate is not originally created for this
                // token, we should not revoke the certificate here.
                //
                // To figure out if this certificate is originally created
                // for this token, we check the tokenOrigin attribute.
                /////////////////////////////////////////////////
                char *origin = RA::ra_get_cert_attr_byname(e, "tokenOrigin");
                if (origin != NULL) {
                  RA::Debug("RA_Processor::RevokeCertificates", "Origin is %s, Current is %s", origin, cuid);
                  if (strcmp(origin, cuid) != 0) {
                    // skip this certificate, no need to do nothing
                    // We did not create this originally

                    rc = RA::ra_delete_certificate_entry(e);
                    continue;
                  }
                } else {
                  RA::Debug("RA_Processor::RevokeCertificates", "Origin is not present");
                }

                PR_snprintf((char *)configname, 256, "%s.%s.revokeCert", OP_PREFIX, tokenType);
                bool revokeCert = RA::GetConfigStore()->GetConfigAsBool(configname, true);
                if (revokeCert) {
                    char *attr_cn = RA::ra_get_cert_cn(e);
                    PR_snprintf((char *)configname, 256, "%s.%s.ca.conn", OP_PREFIX,
                      tokenType);
                    char *connid = (char *)(RA::GetConfigStore()->GetConfigAsString(configname));
                    if (connid == NULL) {
                       RA::Debug(LL_PER_PDU, "RA_Processor::RevokeCertificates", "Failed to get connection.");
                       status = STATUS_ERROR_REVOKE_CERTIFICATES_FAILED;
                       PR_snprintf(audit_msg, 512, "Failed to connect to CA, status = STATUS_ERROR_REVOKE_CERTIFICATES_FAILED");
            
                       revocation_failed = true;           
                       goto loser;
                    }
                    PR_snprintf(serial, 100, "0x%s", attr_serial);
         
                    // if the certificates are revoked_on_hold, dont do 
                    // anything because the certificates may be referenced
                    // by more than one token.
                    if (strcmp(attr_status, "revoked_on_hold") == 0) {
                        RA::Debug("RA_Processor::RevokeCertificates", "This is revoked_on_hold certificate, skip it.");
                        if (attr_status != NULL) {
                            PL_strfree(attr_status);
                            attr_status = NULL;
                        }
                        if (attr_serial != NULL) {
                            PL_strfree(attr_serial);
                            attr_serial = NULL;
                        }
                        if (attr_cn != NULL) {
                            PL_strfree(attr_cn);
                            attr_cn = NULL;
                        }

                        rc = RA::ra_delete_certificate_entry(e);
                        continue;
                    }

                    CERTCertificate **attr_certificate= RA::ra_get_certificates(e);
                    statusNum = certEnroll->RevokeCertificate(
                        true,
                        attr_certificate[0],
                        "1", serial, connid, statusString);
                    if (attr_certificate[0] != NULL)
                        CERT_DestroyCertificate(attr_certificate[0]);

                    RA::Debug("RA_Processor::RevokeCertificates", "Revoke cert %s status %d",serial,statusNum);
                    if (statusNum == 0) {
                        RA::Audit(EV_FORMAT, AUDIT_MSG_CERT_STATUS_CHANGE, userid,
                                      "Success", "revoke", serial, connid, "");
                        PR_snprintf(activity_msg, 512, "certificate %s revoked", serial);
                        RA::tdb_activity(session->GetRemoteIP(), cuid, "format", "success", activity_msg, "", tokenType); 
                        RA::ra_update_cert_status(attr_cn, "revoked");
                    } else {
                        RA::Audit(EV_FORMAT, AUDIT_MSG_CERT_STATUS_CHANGE, userid,
                                      "Failure", "revoke", serial, connid, statusString);
                        PR_snprintf(activity_msg, 512, "error in revoking certificate %s: %s", serial, statusString);
                        RA::tdb_activity(session->GetRemoteIP(), cuid, "format", "failure", activity_msg, "", tokenType);
                        revocation_failed = true;
                    }

                    if (attr_status != NULL) {
                        PL_strfree(attr_status);
                        attr_status = NULL;
                    }
                    if (attr_serial != NULL) {
                        PL_strfree(attr_serial);
                        attr_serial = NULL;
                    }
                    if (attr_cn != NULL) {
                        PL_strfree(attr_cn);
                        attr_cn = NULL;
                    }
                    if (statusString != NULL) {
                        PR_Free(statusString);
                        statusString = NULL;
                    }
                }
                rc = RA::ra_delete_certificate_entry(e);
            }
            if (result != NULL)
                ldap_msgfree(result);
            if (certEnroll != NULL) 
                delete certEnroll;
        } else {
            RA::Debug(LL_PER_PDU, "RA_Processor::RevokeCertificates", "Failed to revoke certificates on this token. Certs not found.");
            status = STATUS_ERROR_REVOKE_CERTIFICATES_FAILED;
            PR_snprintf(audit_msg, 512, "Failed to revoke certificates on this token. Certs not found. status = STATUS_ERROR_REVOKE_CERTIFICATES_FAILED");
            revocation_failed = true;
            goto loser;
        }

        rc = 0;
        if (keyVersion != NULL) {
            //Do this in format case only, could be called from a RE_ENROLL operation
            rc = RA::tdb_update("", cuid, (char *)final_applet_version, keyVersion, "uninitialized", "", tokenType);
        }

        if (rc != 0) {
            RA::Debug(LL_PER_PDU, "RA_Processor::RevokeCertificates",
	      "Failed to update the token database");
            status = STATUS_ERROR_UPDATE_TOKENDB_FAILED;
            PR_snprintf(audit_msg, 512, "Revoked certificates but failed to update the token database, status = STATUS_ERROR_UPDATE_TOKENDB_FAILED");
            goto loser;
        }

loser:

    return !revocation_failed;
}


/**
 * Request Login info and user id from user, if necessary
 * This call will allocate a new Login structure,
 * and a char* for the user id. The caller is responsible
 * for freeing this memory
 * @return true of success, false if failure
 */
bool RA_Processor::RequestUserId(
    const char *a_prefix,
    RA_Session * a_session,
    NameValueSet *a_extensions,
    const char * a_configname, 
    const char * a_tokenType, 
    char *a_cuid,
    AuthParams *& o_login, const char *&o_userid, RA_Status &o_status) 
{

    const char *FN = "RA_Processor::RequestUserId";
    //isExternalReg
    bool isExternalReg = false;
    const char *authid = NULL;
    const char *op = NULL;
    char configname[512] = "";
    if (strcmp(a_prefix, "op.enroll") == 0) {
        op = "enrollment";
    } else if (strcmp(a_prefix, "op.format") == 0) {
        op = "format";
    } else if (strcmp(a_prefix, "op.pinReset") == 0) {
        op = "pinReset";
    } else {
        op = "unknown";
    }

    PR_snprintf((char *)configname, 256, "externalReg.enable");
    isExternalReg = RA::GetConfigStore()->GetConfigAsBool(configname, 0);

    /*
     * if a_configname is null, bypass the loginRequest.enable check
     *   and always do loginRequest.
     * otherwise it checks for the config set in a_configname
     *   e.g."externalReg.format.loginRequest.enable"
     */
    if (a_configname != NULL) {
        /* loginRequest.enable is false */
        RA::Debug(FN, "checking %s", a_configname);
        if (!RA::GetConfigStore()->GetConfigAsBool(a_configname, 1)) {
            RA::Debug(FN, "no Login required");
            return true;
        }
    }
    RA::Debug(FN, "Login required");

    if (a_extensions != NULL && 
        a_extensions->GetValue("extendedLoginRequest") != NULL) {
        // XXX - extendedLoginRequest
        RA::Debug(FN, "Extended Login Request detected");
        //isExternalReg get it from global auth id
        AuthenticationEntry *entry = NULL;
        if (!isExternalReg){
            entry = GetAuthenticationEntry(
            a_prefix, a_configname, a_tokenType);
        } else {
            PR_snprintf((char *)configname, 256, "externalReg.authId");
            authid = (char *) RA::GetConfigStore()->GetConfigAsString(configname);
            entry = RA::GetAuth(authid);
            /* a "fake" tokenType that will be reassigned once we reach ldap */
            a_tokenType = "externalRegNoTokenTypeYet";
        }
        char **params = NULL;
        char pb[1024];
        char *locale = NULL;
        if (a_extensions != NULL && 
            a_extensions->GetValue("locale") != NULL) {
            locale = a_extensions->GetValue("locale");
        } else {
            locale = ( char * ) "en"; /* default to english */
        }
        int n = entry->GetAuthentication()->GetNumOfParamNames();
        if (n > 0) {
            RA::Debug(FN, "Extended Login Request detected n=%d", n);
            params = (char **) PR_Calloc(n, sizeof(char *));
            for (int i = 0; i < n; i++) {
                sprintf(pb,"id=%s&name=%s&desc=%s&type=%s&option=%s",
                    entry->GetAuthentication()->GetParamID(i),
                    entry->GetAuthentication()->GetParamName(i, locale),
                    entry->GetAuthentication()->GetParamDescription(i, locale),
                    entry->GetAuthentication()->GetParamType(i),
                    entry->GetAuthentication()->GetParamOption(i)
                    );
                params[i] = PL_strdup(pb);
                RA::Debug(FN, "params[i]=%s", params[i]);
            }
        }
        RA::Debug(FN,
            "Extended Login Request detected calling RequestExtendedLogin() locale=%s", locale);

        char *title = PL_strdup(entry->GetAuthentication()->GetTitle(locale));
        RA::Debug(FN, "title=%s", title);
        char *description = PL_strdup(entry->GetAuthentication()->GetDescription(locale));
        RA::Debug(FN, "description=%s", description);
        o_login = RequestExtendedLogin(a_session, 0 /* invalid_pw */, 0 /* blocked */, params, n, title, description);

        if (params != NULL) {
            for (int nn=0; nn < n; nn++) {
                if (params[nn] != NULL) {
                    PL_strfree(params[nn]);
                    params[nn] = NULL;
                }
            }
            free(params);
            params = NULL;
        }

        if (title != NULL) {
            PL_strfree(title);
            title = NULL;
        }

        if (description != NULL) {
            PL_strfree(description);
            description = NULL;
        }

        if (o_login == NULL) {
            RA::Error(FN, "login not provided");
            o_status = STATUS_ERROR_LOGIN;
            RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, 
                op, "failure", "login not found", "", a_tokenType);
            return false;
        }

        RA::Debug(FN,
            "Extended Login Request detected calling RequestExtendedLogin() login=%x", o_login);
        o_userid = PL_strdup( o_login->GetUID() );
        RA::Debug(FN, "userid = '%s'", o_userid);
        } else {
            o_login = RequestLogin(a_session, 0 /* invalid_pw */, 0 /* blocked */);
        }

        if (o_login == NULL) {
            RA::Error(FN, "login not provided");
            o_status = STATUS_ERROR_LOGIN;
            RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, 
                op, "failure", "login not found", o_userid, a_tokenType);
              return false;
        }
        o_userid = PL_strdup( o_login->GetUID() );
        RA::Debug(FN, "userid = '%s'", o_userid);
        return true;
}


/**
 * Authenticate user with LDAP plugin
 * @return true if authentication was successful
 */
bool RA_Processor::AuthenticateUserLDAP(
        const char *op,
        RA_Session *a_session,
        NameValueSet *a_extensions,
        char *a_cuid,
        AuthenticationEntry *a_auth,
        AuthParams *&login,
        RA_Status &o_status,
        const char *a_token_type)
{
    const char *FN = "RA_Processor::AuthenticateUserLDAP";
    int retry_limit = a_auth->GetAuthentication()->GetNumOfRetries();
    int retries = 0;
    int rc;
    bool r=false;
    char configname[256]; 
    ExternalRegAttrs *regAttrs = NULL;

    PR_snprintf((char *)configname, 256, "externalReg.enable");
    bool isExternalReg = RA::GetConfigStore()->GetConfigAsBool(configname, 0);
    const char *tokenType = NULL;

    RA::Debug(LL_PER_PDU, FN, "LDAP_Authentication is invoked.");
    LDAP_Authentication *ldapAuth = (LDAP_Authentication *)a_auth->GetAuthentication();
    if (isExternalReg ) {
        PR_snprintf((char *)configname, 256, 
            "externalReg.default.tokenType");
        tokenType = (char *) RA::GetConfigStore()->GetConfigAsString(configname, "userKey");

        rc = ldapAuth->Authenticate(login, a_session);
        /*ToDo: compare token cuid from reg user record with a_cuid
          if reg user record has it. If not, assume it's ok*/

        regAttrs = a_session->getExternalRegAttrs();

        if (regAttrs == NULL) {
             RA::Debug(LL_PER_PDU,FN, "Misconfigured External Registration!");
             RA::Error(FN, "Misconfigured External Registration!");
             r = false;
             return r;
        }


        if (rc == 0 ) {
            regAttrs->setTokenCUID(a_cuid);
            regAttrs->setUserId(login->GetUID());
        }
        const char *tt = a_session->getExternalRegAttrs()->getTokenType();
        if (tt != NULL)
            RA::Debug(LL_PER_PDU, FN, "isExternalReg: got tokenType:%s", tt);
        else {
            RA::Debug(LL_PER_PDU, FN, "isExternalReg: tokenType NULL, set to default");
            a_session->getExternalRegAttrs()->setTokenType(tokenType);
            RA::Debug(LL_PER_PDU, FN, "isExternalReg: tokenType NULL, done setting to default %s", tokenType);
        }

        /*
         * If cuid is provided on the user registration record, then
         * we have to compare that with the current token cuid;
         *
         * If, the cuid is not provided on the user registration record,
         * then any token can be used.
         */
        const char *userreg_cuid = a_session->getExternalRegAttrs()->getTokenCUID();
        if (userreg_cuid != NULL) {
            if (PL_strcasecmp((const char*)a_cuid, userreg_cuid) != 0) {
                RA::Debug(LL_PER_PDU, FN, "isExternalReg: ERROR: token cuid not matched");
                RA::Debug(LL_PER_PDU, FN, "current cuid=%s, userreg_cuid=%s",
                    a_cuid, userreg_cuid);
                o_status = STATUS_ERROR_NOT_TOKEN_OWNER;
                r = false;
                return r;
            } else {
                RA::Debug(LL_PER_PDU, FN, "isExternalReg: token cuid matched");
            }
        } else {
            RA::Debug(LL_PER_PDU, FN, "isExternalReg: cuid not provided on user registration record... cuid not checked");
        }
    } else
        rc = ldapAuth->Authenticate(login);

    RA::Debug(FN, "Authenticate returned: %d", rc);

    // rc: (0:login correct) (-1:LDAP error)  (-2:User not found) (-3:Password error)

    // XXX replace with proper enums
    // XXX evaluate rc==0 as specific case - this is success, it shouldn't be the default

    while ((rc == TPS_AUTH_ERROR_USERNOTFOUND || 
            rc == TPS_AUTH_ERROR_PASSWORDINCORRECT ) 
            && (retries < retry_limit)) {
        login = RequestLogin(a_session, 0 /* invalid_pw */, 0 /* blocked */);
        retries++;
        if (login != NULL) {
            if (isExternalReg && regAttrs) {
                rc = ldapAuth->Authenticate(login, a_session);
                a_session->getExternalRegAttrs()->setTokenCUID(a_cuid);
                a_session->getExternalRegAttrs()->setUserId(login->GetUID());
                const char *tt = a_session->getExternalRegAttrs()->getTokenType();
                if (tt != NULL)
                    RA::Debug(LL_PER_PDU, FN, "isExternalReg: got tokenType:%s", tt);
                else {
                    RA::Debug(LL_PER_PDU, FN, "isExternalReg: tokenType NULL, set to default");
                    a_session->getExternalRegAttrs()->setTokenType(tokenType);
                    RA::Debug(LL_PER_PDU, FN, "isExternalReg: tokenType NULL, done setting to default %s", tokenType);
                }
            } else
                rc = ldapAuth->Authenticate(login);
        }
    }

    switch (rc) {
    case TPS_AUTH_OK:
        RA::Debug(LL_PER_PDU, FN, "Authentication successful.");
        r=true;
        break;
    case TPS_AUTH_ERROR_LDAP:
        RA::Error(FN, "Authentication failed. LDAP Error");
        o_status = STATUS_ERROR_LDAP_CONN;
        RA::Debug(LL_PER_PDU, FN, "Authentication status=%d rc=%d", o_status,rc);
        RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, op, "failure", "authentication error", "", a_token_type);
        r = false;
        break;
    case TPS_AUTH_ERROR_USERNOTFOUND:
        RA::Error(FN, "Authentication failed. User not found");
        o_status = STATUS_ERROR_LOGIN;
        RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, op, "failure", "authentication error",  "", a_token_type);
        r = false;
        break;
    case TPS_AUTH_ERROR_PASSWORDINCORRECT:
        RA::Error(FN, "Authentication failed. Password Incorrect");
        o_status = STATUS_ERROR_LOGIN;
        RA::Debug(LL_PER_PDU, FN, "Authentication status=%d rc=%d", o_status,rc);
        RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, op, "failure", "authentication error", "", a_token_type);
        r = false;
        break;
    default:
        RA::Error(FN, "Undefined LDAP Auth Error.");
        r = false;
        break;
    }

    return r;
}


/**
 *  Authenticate the user with the configured authentication plugin
 * @return true if authentication successful
 */

bool RA_Processor::AuthenticateUser(
        const char * a_prefix,
        RA_Session * a_session,
        const char * a_configname, 
        char *a_cuid,
        NameValueSet *a_extensions,
        const char *a_tokenType,
        AuthParams *& a_login, const char *&o_userid, RA_Status &o_status
        )
{

    char *FN = ( char * ) "RA_Processor::AuthenticateUser";
    bool r=false;
    char *type = NULL;
    const char *authid = NULL;
    AuthenticationEntry *auth = NULL;
    //isExternalReg
    bool isExternalReg = false;

    const char *op = NULL;
    if (strcmp(a_prefix, "op.enroll") == 0) {
        op = "enrollment";
    } else if (strcmp(a_prefix, "op.format") == 0) {
        op = "format";
    } else if (strcmp(a_prefix, "op.pinReset") == 0) {
        op = "pinReset";
    } else {
        op = "unknown";
    }
    RA::Debug(FN, "started");

    if (a_configname != NULL) {
        RA::Debug(FN, "checking config: %s", a_configname);
        if (!RA::GetConfigStore()->GetConfigAsBool(a_configname, 1)){
            r = true;
            RA::Debug(FN, "Authentication has been disabled.");
            goto loser;
        }
        RA::Debug(FN, "isExternalReg false");
    } else {
        RA::Debug(FN, "isExternalReg true");
        isExternalReg = true;
    }
    if (a_login == NULL) {
        RA::Error(FN, "Login Request Disabled. Authentication failed.");
        o_status = STATUS_ERROR_LOGIN;
        goto loser;
    }

    RA::Debug(FN, "Authentication enabled");
    char configname[256];

    if (!isExternalReg) {
        PR_snprintf((char *)configname, 256, "%s.%s.auth.id", a_prefix, a_tokenType);
    } else {
    //isExternalReg
        PR_snprintf((char *)configname, 256, "externalReg.authId");
        a_tokenType = "externalRegNoTokenTypeYet";
    }
    authid = RA::GetConfigStore()->GetConfigAsString(configname);
    if (authid == NULL) {
        o_status = STATUS_ERROR_LOGIN;
        RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, op, "failure", "login not found", "", a_tokenType);
        goto loser;
    }
    auth = RA::GetAuth(authid);

    if (auth == NULL) {
        o_status = STATUS_ERROR_LOGIN;
        RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, op, "failure", "authentication error", "", a_tokenType);
        goto loser;
    }

    StatusUpdate(a_session, a_extensions, 2, "PROGRESS_START_AUTHENTICATION");

    type = auth->GetType();
    if (type == NULL) {
        o_status = STATUS_ERROR_LOGIN;
        RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, op, "failure", "authentication is missing param type", "", a_tokenType);
        r = false;
        goto loser;
    }

    if (strcmp(type, "LDAP_Authentication") == 0) {
        RA::Debug(FN, "LDAP started");
        r = AuthenticateUserLDAP(op, a_session, a_extensions, a_cuid, auth, a_login, o_status, a_tokenType);
        if ((isExternalReg) && (r == true)) {
            RA::Debug(FN, "AuthenticateUserLDAP() returned; session set with ExternalRegAttrs.");
        }

        if(r == false)
            o_status = STATUS_ERROR_LOGIN;

        goto loser;
    } else {
        RA::Error(FN, "No Authentication type was found.");
        o_status = STATUS_ERROR_LOGIN;
        RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, op, "failure", "authentication error", "", a_tokenType);
        r = false;
        goto loser;
    }

loser:
    return r;
}

RA_Status RA_Processor::Format(RA_Session *session, NameValueSet *extensions, bool skipAuth)
{
    const char *OP_PREFIX="op.format";
    char configname[256];
    char *cuid = NULL;
    char *msn = NULL;
    const char *tokenType = NULL;
    PRIntervalTime start, end;
    RA_Status status = STATUS_NO_ERROR;
    int rc = -1;
    Secure_Channel *channel = NULL;
    Buffer kdd;
    AuthParams *login = NULL;
    // char *new_pin = NULL;
    const char *applet_dir;
    bool upgrade_enc = false;
    SecurityLevel security_level = SECURE_MSG_MAC_ENC;

    Buffer *buildID = NULL;
    Buffer *token_status = NULL;
    const char* required_version = NULL;
    const char *appletVersion = NULL;
    const char *final_applet_version = NULL;
    const char *userid = PL_strdup( "" );
    // BYTE se_p1 = 0x00;
    // BYTE se_p2 = 0x00;
    const char *expected_version;
    int requiredV = 0;
    const char *tksid = NULL;
    const char *authid = NULL;
    AuthParams *authParams = NULL;
    Buffer host_challenge = Buffer(8, (BYTE)0);
    Buffer key_diversification_data;
    Buffer key_info_data;
    Buffer card_challenge;
    Buffer card_cryptogram;
    Buffer *cplc_data = NULL;
    char activity_msg[4096];
    LDAPMessage *ldapResult = NULL;
    LDAPMessage *e = NULL;
    LDAPMessage  *result = NULL;
    char serial[100];
    char *statusString = NULL;
    char filter[512];
    int statusNum;
    Buffer curKeyInfo;
    BYTE curVersion;
    char *curKeyInfoStr = NULL;
    char *newVersionStr = NULL;
    bool tokenFound = false;
    int finalKeyVersion = 0;
    char *keyVersion = NULL;
    char *xuserid = NULL;
    char audit_msg[512] = "";
    char *profile_state = NULL;
    ExternalRegAttrs *regAttrs = NULL;


    Buffer *CardManagerAID = RA::GetConfigStore()->GetConfigAsBuffer(
		   RA::CFG_APPLET_CARDMGR_INSTANCE_AID, 
		   RA::CFG_DEF_CARDMGR_INSTANCE_AID);
    Buffer *NetKeyAID = RA::GetConfigStore()->GetConfigAsBuffer(
		    RA::CFG_APPLET_NETKEY_INSTANCE_AID, 
		    RA::CFG_DEF_NETKEY_INSTANCE_AID);
    Buffer key_data_set;
    Buffer token_cuid;
    Buffer token_msn;
    RA::Debug(LL_PER_PDU, "RA_Processor::Format",
	      "Begin upgrade process");

    BYTE major_version = 0x0;
    BYTE minor_version = 0x0;
    BYTE app_major_version = 0x0;
    BYTE app_minor_version = 0x0;
        const char *connid = NULL;
        int upgrade_rc;

    start = PR_IntervalNow();

    RA::Debug("RA_Processor::Format", "Client %s",
                       session->GetRemoteIP());

    PR_snprintf((char *)configname, 256, "externalReg.enable");
    bool isExternalReg = RA::GetConfigStore()->GetConfigAsBool(configname, 0);

    SelectApplet(session, 0x04, 0x00, CardManagerAID);
    cplc_data = GetData(session);
    if (cplc_data == NULL) {
          RA::Error("RA_Format_Processor::Process",
                        "Get Data Failed");
          status = STATUS_ERROR_SECURE_CHANNEL;
          PR_snprintf(audit_msg, 512, "Get Data Failed, status = STATUS_ERROR_SECURE_CHANNEL");
          goto loser;
    }
    RA::DebugBuffer("RA_Processor::Format", "CPLC Data = ", 
                        cplc_data);
    if (cplc_data->size() < 47) {
          RA::Error("RA_Format_Processor::Process",
                        "Invalid CPLC Size");
          status = STATUS_ERROR_SECURE_CHANNEL;
          PR_snprintf(audit_msg, 512, "Invalid CPLC Size, status = STATUS_ERROR_SECURE_CHANNEL");
          goto loser;
    }
    token_cuid =  Buffer(cplc_data->substr(3,4)) +
             Buffer(cplc_data->substr(19,2)) +
             Buffer(cplc_data->substr(15,4));
    RA::DebugBuffer("RA_Processor::Format", "Token CUID= ",
                        &token_cuid);
    cuid = Util::Buffer2String(token_cuid);

    token_msn = Buffer(cplc_data->substr(41, 4));
    RA::DebugBuffer("RA_Processor::Format", "Token MSN= ",
                        &token_msn);
    msn = Util::Buffer2String(token_msn);


    /**
     * Checks if the netkey has the required applet version.
     */
    SelectApplet(session, 0x04, 0x00, NetKeyAID);
    token_status = GetStatus(session, 0x00, 0x00);
    if (token_status == NULL) {
        major_version = 0;
        minor_version = 0;
        app_major_version = 0x0;
        app_minor_version = 0x0;
    } else {
        major_version = ((BYTE*)*token_status)[0];
        minor_version = ((BYTE*)*token_status)[1];
        app_major_version = ((BYTE*)*token_status)[2];
        app_minor_version = ((BYTE*)*token_status)[3];
    }

    RA::Debug(LL_PER_PDU, "RA_Processor::Format",
	      "Major=%d Minor=%d", major_version, minor_version);
    RA::Debug(LL_PER_PDU, "RA_Processor::Format",
	      "Applet Major=%d Applet Minor=%d", app_major_version, app_minor_version);

    if (isExternalReg) {
        /*
          need to reach out to the Registration DB (authid)
          Entire user entry should be retrieved and parsed, if needed
          The following are retrieved:
              externalReg.tokenTypeAttributeName=tokenType
              externalReg.certs.recoverAttributeName=certsToRecover
              externalReg.certs.deleteAttributeName=certsToDelete 
         */
        /*
         * - tokenType id NULL at this point for isExternalReg 
         * - loginRequest cannot be per profile(tokenType) for isExternalReg
         *   because of the above; now it is per instance:
         *     "externalReg.format.loginRequest.enable"
         *     "externalReg.default.tokenType"
         *   it is not enabled by default.
         */
        PR_snprintf((char *)configname, 256, 
            "externalReg.format.loginRequest.enable");
//        PR_snprintf((char *)configname, 256, "%s.%s.loginRequest.enable", OP_PREFIX, tokenType);
        RA::Debug("RA_Processor::Format", "checking %s", configname);
        if (!RA::GetConfigStore()->GetConfigAsBool(configname, 0)) {
            RA::Debug("RA_Processor::Format", "no Login required");
            // get the default externalReg tokenType
            PR_snprintf((char *)configname, 256, 
                "externalReg.default.tokenType");
            tokenType = (char *) RA::GetConfigStore()->GetConfigAsString(configname, "userKey");
            RA::Debug("RA_Processor::Format", "setting tokenType to: %s", tokenType);
        } else {
            /* get user login and password - set in "login" */
            RA::Debug(LL_PER_PDU, "RA_Processor::Format", "isExternalReg: calling RequestUserId");
            if (!RequestUserId(OP_PREFIX, session, extensions, configname, NULL /*tokenType*/, cuid, login, userid, status)){
                PR_snprintf(audit_msg, 512, "RequestUserId error");
            goto loser;
            }
            if (!AuthenticateUser("op.format", session, NULL /*configname*/, cuid, extensions,
                NULL /*tokenType*/, login, userid, status)){
                PR_snprintf(audit_msg, 512, "AuthenticateUser error");
                goto loser;
            }

            regAttrs = session->getExternalRegAttrs();

            if (regAttrs == NULL) {
                PR_snprintf(audit_msg,512, "External Registration Misconfiguration!");
                goto loser;
            }

            RA::Debug(LL_PER_PDU, "RA_Processor::Format", "isExternalReg: get tokenType, etc.");
            tokenType = regAttrs->getTokenType();
        }

    } else {

        if (!GetTokenType(OP_PREFIX, major_version,
                    minor_version, cuid, msn,
                    extensions, status, tokenType)) {
            PR_snprintf(audit_msg, 512, "Failed to get token type");
            goto loser;
        }
    }

    // check if profile is enabled 
    PR_snprintf((char *)configname, 256, "config.Profiles.%s.state", tokenType);
    profile_state = (char *) RA::GetConfigStore()->GetConfigAsString(configname);
    if ((profile_state != NULL) && (PL_strcmp(profile_state, "Enabled") != 0)) {
        RA::Error("RA_Format_Processor::Process", "Profile %s Disabled for CUID %s", tokenType, cuid);
        status =  STATUS_ERROR_DEFAULT_TOKENTYPE_PARAMS_NOT_FOUND;
        PR_snprintf(audit_msg, 512, "profile %s disabled", tokenType);
        goto loser;
    }

    if (!isExternalReg) {

        if (RA::ra_is_token_present(cuid)) {

            int token_status = RA::ra_get_token_status(cuid);

            RA::Debug("RA_Processor::Format",
                "Found token %s status %d", cuid, token_status);

            // Check for transition to 0/UNINITIALIZED status.

            if (token_status == -1 || !RA::transition_allowed(token_status, 0)) {
                RA::Error("RA_Format_Processor::Process",
                        "Operation for CUID %s Disabled", cuid);
                status = STATUS_ERROR_DISABLED_TOKEN;
                PR_snprintf(audit_msg, 512, "Operation for CUID %s Disabled, illegal transition attempted %d:%d.", cuid, token_status, 0);
                goto loser;
            }
        } else {
            RA::Debug("RA_Processor::Format",
                "Not Found token %s", cuid);
            // This is a new token. We need to check our policy to see
            // if we should allow enrollment. raidzilla #57414
            PR_snprintf((char *)configname, 256, "%s.allowUnknownToken",
                OP_PREFIX);
            if (!RA::GetConfigStore()->GetConfigAsBool(configname, 1)) {
                RA::Error("Process", "CUID %s Format Unknown Token", cuid);
                status = STATUS_ERROR_DISABLED_TOKEN;
                PR_snprintf(audit_msg, 512, "Unknown token disallowed,  status=STATUS_ERROR_DISABLED_TOKEN");
                goto loser;
            }
        }
    }

    // we know cuid and msn here 
    RA::Audit(EV_FORMAT, AUDIT_MSG_PROC,
      userid != NULL ? userid : "",
      cuid != NULL ? cuid : "",
      msn != NULL ? msn : "",
      "success",
      "format",
      final_applet_version != NULL ? final_applet_version : "",
      keyVersion != NULL? keyVersion : "",
      "token enabled");

    PR_snprintf((char *)configname, 256, "%s.%s.tks.conn",
                    OP_PREFIX, tokenType);
    tksid = RA::GetConfigStore()->GetConfigAsString(configname);
    if (tksid == NULL) {
        RA::Error("RA_Format_Processor::Process",
                        "TKS Connection Parameter %s Not Found", configname);
        status = STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND;
        PR_snprintf(audit_msg, 512, "TKS Connection Parameter %s Not Found, status = STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND", configname);
        goto loser;
    }

    buildID = GetAppletVersion(session);
    if (buildID == NULL) {
        PR_snprintf((char *)configname, 256, "%s.%s.update.applet.emptyToken.enable", OP_PREFIX, tokenType);
        if (RA::GetConfigStore()->GetConfigAsBool(configname, 0)) {
            appletVersion = PL_strdup( "" );
        } else {
            RA::Error("RA_Format_Processor::Process", 
              "no applet found and applet upgrade not enabled");
            status = STATUS_ERROR_SECURE_CHANNEL;		 
            PR_snprintf(audit_msg, 512, "No applet found and applet upgrade not enabled, status = STATUS_ERROR_SECURE_CHANNEL");
            goto loser;
        }
    } else {
      char * buildid =  Util::Buffer2String(*buildID);
      RA::Debug("RA_Processor::Format", "buildid = %s", buildid);
      char version[13];
      PR_snprintf((char *) version, 13,
		  "%x.%x.%s", app_major_version, app_minor_version,
		  buildid);
      appletVersion = strdup(version);
      if (buildid != NULL) {
          PR_Free(buildid);
          buildid=NULL;
      }
    }

    final_applet_version = strdup(appletVersion);
    RA::Debug("RA_Processor::Format", "final_applet_version = %s", final_applet_version);

    /**
     * Checks if we need to upgrade applet. 
     */
    PR_snprintf((char *)configname, 256, "%s.%s.update.applet.requiredVersion", OP_PREFIX, tokenType);

    required_version = RA::GetConfigStore()->GetConfigAsString(
      configname);
    expected_version = PL_strdup(required_version);

    if (expected_version == NULL) {
        RA::Error("RA_Format_Processor::Process", 
          "upgrade.version not found");
        status = STATUS_ERROR_MISCONFIGURATION;		 
        PR_snprintf(audit_msg, 512, "Upgrade version not found, status = STATUS_ERROR_MISCONFIGURATION");
        goto loser;
    }
    /* upgrade applet */
    PR_snprintf((char *)configname, 256, "%s.%s.update.applet.directory", OP_PREFIX, tokenType);
    applet_dir = RA::GetConfigStore()->GetConfigAsString(configname);
    if (applet_dir == NULL || strlen(applet_dir) == 0) {
        RA::Error(LL_PER_PDU, "RA_Processor::UpdateApplet",
          "Failed to get %s", applet_dir);
        status = STATUS_ERROR_MISCONFIGURATION;		 
        PR_snprintf(audit_msg, 512, "Failed to get %s, status = STATUS_ERROR_MISCONFIGURATION", applet_dir);
        goto loser;
    }

// ToDo: isExternalReg : user already authenticated earlier... need to handle audit earlier
    if (!isExternalReg) {
        PR_snprintf((char *)configname, 256, "%s.%s.loginRequest.enable", OP_PREFIX, tokenType);
        if (!RequestUserId(OP_PREFIX, session, extensions, configname, tokenType, cuid, login, userid, status)){
                PR_snprintf(audit_msg, 512, "RequestUserId error");
            goto loser;
        }
    
        PR_snprintf((char *)configname, 256, "%s.%s.auth.enable", OP_PREFIX, tokenType);

        if (!AuthenticateUser("op.format", session, configname, cuid, extensions,
                tokenType, login, userid, status)){
                PR_snprintf(audit_msg, 512, "AuthenticateUser error");
            goto loser; 
        }

        RA::Audit(EV_FORMAT, AUDIT_MSG_PROC,
            userid != NULL ? userid : "",
            cuid != NULL ? cuid : "",
            msn != NULL ? msn : "",
            "success",
            "format",
            final_applet_version != NULL ? final_applet_version : "",
            keyVersion != NULL ? keyVersion : "",
            "token login successful");

            // get authid for audit log
            PR_snprintf((char *)configname, 256, "%s.%s.auth.id", OP_PREFIX, tokenType);
            authid = RA::GetConfigStore()->GetConfigAsString(configname);
    }

/*isExternalReg should check in a different way*/
    // check if it is the token owner
   if (!isExternalReg) {
       xuserid = RA::ra_get_token_userid(cuid);
       if (xuserid != NULL && strcmp(xuserid, "") != 0) {
         if (login != NULL) {
           if (strcmp(login->GetUID(), xuserid) != 0) {
              RA::Debug(LL_PER_PDU, "RA_Processor::Format",
                "Token owner mismatched");
              status = STATUS_ERROR_NOT_TOKEN_OWNER;
              PR_snprintf(audit_msg, 512, "Token owner mismatched, status = STATUS_ERROR_NOT_TOKEN_OWNER");
              goto loser;
           }
         }
       }
   }

    // we know cuid, msn and userid  here 
    RA::Audit(EV_FORMAT, AUDIT_MSG_PROC,
      userid != NULL ? userid : "",
      cuid != NULL ? cuid : "",
      msn != NULL ? msn : "",
      "success",
      "format",
      final_applet_version != NULL ? final_applet_version : "",
      keyVersion != NULL? keyVersion : "",
      "logged into token");

    if (extensions != NULL && 
	             extensions->GetValue("statusUpdate") != NULL) {
	               StatusUpdate(session, 10 /* progress */, 
	                          "PROGRESS_APPLET_UPGRADE");
    }

    PR_snprintf((char *)configname, 256, "%s.%s.update.applet.encryption", OP_PREFIX, tokenType);
    upgrade_enc = RA::GetConfigStore()->GetConfigAsBool(configname, true);
    if (!upgrade_enc)
        security_level = SECURE_MSG_MAC;
    PR_snprintf((char *)configname, 256, "%s.%s.tks.conn", OP_PREFIX, tokenType);
    connid = RA::GetConfigStore()->GetConfigAsString(configname);
    upgrade_rc = UpgradeApplet(session,(char *) OP_PREFIX, (char*)tokenType, major_version, 
      minor_version, expected_version, applet_dir, security_level, connid,
			       extensions, 10, 90, &keyVersion);
    if (upgrade_rc != 1) {
        RA::Debug("RA_Processor::Format", 
          "applet upgrade failed");
        status = STATUS_ERROR_UPGRADE_APPLET;		 
        /**
         * Bugscape #55709: Re-select Net Key Applet ONLY on failure.
         */
        SelectApplet(session, 0x04, 0x00, NetKeyAID);
        RA::tdb_activity(session->GetRemoteIP(), cuid, "format", "failure", "applet upgrade error", "", tokenType);
        // rc = -1 denotes Secure Channel Failure

        if (rc == -1) {
             RA::Audit(EV_APPLET_UPGRADE, AUDIT_MSG_APPLET_UPGRADE,
               userid, cuid, msn, "Failure", "format",
               keyVersion != NULL? keyVersion : "", appletVersion, expected_version, "failed to setup secure channel");
        } else {

            RA::Audit(EV_APPLET_UPGRADE, AUDIT_MSG_APPLET_UPGRADE,
               userid, cuid, msn, "Success", "format",
               keyVersion != NULL? keyVersion : "", appletVersion, expected_version, "setup secure channel");
        }

        RA::Audit(EV_APPLET_UPGRADE, AUDIT_MSG_APPLET_UPGRADE, 
          userid, cuid, msn, "Failure", "format", 
          keyVersion != NULL? keyVersion : "", appletVersion, expected_version, "applet upgrade");

        goto loser;
    } 

    RA::Audit(EV_APPLET_UPGRADE, AUDIT_MSG_APPLET_UPGRADE,
            userid, cuid, msn, "Success", "format",
            keyVersion != NULL? keyVersion : "", appletVersion, expected_version, "setup secure channel");


    RA::Audit(EV_APPLET_UPGRADE, AUDIT_MSG_APPLET_UPGRADE, 
      userid, cuid, msn, "Success", "format", 
      keyVersion != NULL? keyVersion : "", appletVersion, expected_version, "applet upgrade");

    if( final_applet_version != NULL ) {
        PR_Free( (char *) final_applet_version );
        final_applet_version = NULL;
    }

    final_applet_version = expected_version;

    if (extensions != NULL && 
	             extensions->GetValue("statusUpdate") != NULL) {
	               StatusUpdate(session, 90 /* progress */, 
	                          "PROGRESS_KEY_UPGRADE");
    }

    // add issuer info to the token
    PR_snprintf((char *)configname, 256, "%s.%s.issuerinfo.enable", 
          OP_PREFIX, tokenType);
    if (RA::GetConfigStore()->GetConfigAsBool(configname, 0)) {
        PR_snprintf((char *)configname, 256,"channel.defKeyIndex");
        int defKeyIndex = RA::GetConfigStore()->GetConfigAsInt(configname, 0x0);
        channel = SetupSecureChannel(session, 0x00,
                  defKeyIndex  /* default key index */, connid);

        if (channel != NULL) {
            char issuer[224];

            rc = channel->ExternalAuthenticate();

            for (int i = 0; i < 224; i++) {
              issuer[i] = 0;
            }
            PR_snprintf((char *)configname, 256, "%s.%s.issuerinfo.value", 
               OP_PREFIX, tokenType);
            char *issuer_val = (char*)RA::GetConfigStore()->GetConfigAsString(
                                   configname);
            sprintf(issuer, "%s", issuer_val);
            RA::Debug("RA_Processor::Format", "Set Issuer Info %s", issuer_val);
            Buffer *info = new Buffer((BYTE*)issuer, 224);
            rc = channel->SetIssuerInfo(info);
             
            if (info != NULL) {
                delete info;
                info = NULL;
            }
        }
    }

    /**
     * Checks if the netkey has the required key version.
     */
    PR_snprintf((char *)configname, 256, "%s.%s.update.symmetricKeys.enable", OP_PREFIX, tokenType);
    if (RA::GetConfigStore()->GetConfigAsBool(configname, 1)) {

        PR_snprintf((char *)configname, 256, "%s.%s.update.symmetricKeys.requiredVersion", OP_PREFIX, tokenType);
        requiredV = RA::GetConfigStore()->GetConfigAsInt(configname, 0x00);
        PR_snprintf((char *)configname, 256, "%s.%s.tks.conn", OP_PREFIX, tokenType);
        tksid = RA::GetConfigStore()->GetConfigAsString(configname);
        PR_snprintf((char *)configname, 256,"channel.defKeyIndex");
        int defKeyIndex = RA::GetConfigStore()->GetConfigAsInt(configname, 0x0);
        channel = SetupSecureChannel(session, requiredV,
                   defKeyIndex  /* default key index */, tksid);
        if (channel == NULL) {
            /**
             * Select Card Manager for Put Key operation.
             */
            SelectApplet(session, 0x04, 0x00, CardManagerAID);
	    // send status update to the client
	    if (extensions != NULL && 
	             extensions->GetValue("statusUpdate") != NULL) {
	               StatusUpdate(session, 92 /* progress */, 
	                          "PROGRESS_SETUP_SECURE_CHANNEL");
	    }
            /* if the key of the required version is
             * not found, create them.
             */ 
        PR_snprintf((char *)configname, 256,"channel.defKeyVersion");
        int defKeyVer = RA::GetConfigStore()->GetConfigAsInt(configname, 0x0);
        PR_snprintf((char *)configname, 256,"channel.defKeyIndex");
        int defKeyIndex = RA::GetConfigStore()->GetConfigAsInt(configname, 0x0);
            channel = SetupSecureChannel(session, 
                  defKeyVer,  /* default key version */
                  defKeyIndex  /* default key index */, tksid);
 
            if (channel == NULL) {
                RA::Error("RA_Upgrade_Processor::Process", 
                  "failed to establish secure channel");
                status = STATUS_ERROR_SECURE_CHANNEL;		 
                PR_snprintf(audit_msg, 512, "Failed to establish secure channel");
                goto loser;
            }

	    // send status update to the client
	    if (extensions != NULL && 
		extensions->GetValue("statusUpdate") != NULL) {
	               StatusUpdate(session, 94 /* progress */, 
	                          "PROGRESS_EXTERNAL_AUTHENTICATE");
	    }

            rc = channel->ExternalAuthenticate();

            PR_snprintf((char *)configname, 256, "%s.%s.update.symmetricKeys.requiredVersion", OP_PREFIX, tokenType);
            int v = RA::GetConfigStore()->GetConfigAsInt(configname, 0x00);
            curKeyInfo = channel->GetKeyInfoData();
            BYTE nv[2] = { v, 0x01 };
            Buffer newVersion(nv, 2);
            PR_snprintf((char *)configname,  256,"%s.%s.tks.conn", OP_PREFIX, tokenType);
            connid = RA::GetConfigStore()->GetConfigAsString(configname);
            rc = CreateKeySetData(
              channel->GetKeyDiversificationData(), 
              curKeyInfo,
              newVersion,
              key_data_set, connid);
            if (rc != 1) {
                RA::Error("RA_Format_Processor::Process", 
                  "failed to create new key set");
                status = STATUS_ERROR_CREATE_CARDMGR;
                PR_snprintf(audit_msg, 512, "create key set error, status = STATUS_ERROR_CREATE_CARDMGR");
                goto loser;
            }

            curVersion = ((BYTE*)curKeyInfo)[0];


	    // send status update to the client
	    if (extensions != NULL && 
	             extensions->GetValue("statusUpdate") != NULL) {
	               StatusUpdate(session, 96 /* progress */, 
	                          "PROGRESS_PUT_KEYS");
	    }

            BYTE curIndex = ((BYTE*)curKeyInfo)[1];
            rc = channel->PutKeys(session, 
                  curVersion,
                  curIndex,
                  &key_data_set);


            // need to check return value of rc
             // and create audit log for failure

            curKeyInfoStr = Util::Buffer2String(curKeyInfo);
            newVersionStr = Util::Buffer2String(newVersion);
    
            char curVer[10];
            char newVer[10];
            
            if(curKeyInfoStr != NULL && strlen(curKeyInfoStr) >= 2) {
                curVer[0] = curKeyInfoStr[0]; curVer[1] = curKeyInfoStr[1]; curVer[2] = 0;
            }
            else {
                curVer[0] = 0;
            }

            if(newVersionStr != NULL && strlen(newVersionStr) >= 2) {
                newVer[0] = newVersionStr[0] ; newVer[1] = newVersionStr[1] ; newVer[2] = 0;
            }
            else {
                newVer[0] = 0; 
            }

            if (rc != 0) {
                RA::Audit(EV_KEY_CHANGEOVER, AUDIT_MSG_KEY_CHANGEOVER,
                    userid != NULL ? userid : "", cuid != NULL ? cuid : "", msn != NULL ? msn : "", "Failure", "format", 
                    final_applet_version != NULL ? final_applet_version : "", curVer, newVer, 
                    "key changeover failed");
                // do we goto loser here?
            } 

             finalKeyVersion = ((int) ((BYTE *)newVersion)[0]);
            /**
	     * Re-select Net Key Applet.
	     */
            SelectApplet(session, 0x04, 0x00, NetKeyAID);
            PR_snprintf((char *)configname, 256, "%s.%s.update.symmetricKeys.requiredVersion", OP_PREFIX, tokenType);
            requiredV = RA::GetConfigStore()->GetConfigAsInt(configname, 0x00);
            PR_snprintf((char *)configname, 256, "%s.%s.tks.conn", OP_PREFIX, tokenType);
            tksid = RA::GetConfigStore()->GetConfigAsString(configname);
            if( channel != NULL ) {
                delete channel;
                channel = NULL;
            }
	    // send status update to the client
	    if (extensions != NULL && 
	             extensions->GetValue("statusUpdate") != NULL) {
	               StatusUpdate(session, 98 /* progress */, 
	                          "PROGRESS_SETUP_SECURE_CHANNEL");
	    }


            channel = SetupSecureChannel(session, requiredV,
              defKeyIndex  /* default key index */, tksid);
            if (channel == NULL) {
                RA::Error("RA_Format_Processor::Process", 
			      "failed to establish secure channel after reselect");
                status = STATUS_ERROR_CREATE_CARDMGR;
                PR_snprintf(audit_msg, 512,"failed to establish secure channel after reselect, status = STATUS_ERROR_CREATE_CARDMGR");
                goto loser;
            }

            RA::Audit(EV_KEY_CHANGEOVER, AUDIT_MSG_KEY_CHANGEOVER,
                    userid != NULL ? userid : "", cuid != NULL ? cuid : "", msn != NULL ? msn : "", "Success", "format",
                    final_applet_version != NULL ? final_applet_version : "", curVer, newVer,
                    "key changeover");

        }     
    }

    PR_snprintf((char *)filter, 256, "(cn=%s)", cuid);
    rc = RA::ra_find_tus_token_entries(filter, 100, &result, 0);
    if (rc == 0) {
        for (e = RA::ra_get_first_entry(result); e != NULL; e = RA::ra_get_next_entry(e)) {
            tokenFound = true;
            break;
        }
        if (result != NULL)
            ldap_msgfree(result);
    }

    // get keyVersion
    if (channel != NULL) {
        if (keyVersion != NULL) {
            PR_Free( (char *) keyVersion );
            keyVersion = NULL;
        }
        keyVersion = Util::Buffer2String(channel->GetKeyInfoData());
    }

    // need to revoke all the certificates on this token
    if (tokenFound) {

       //Now we call a separate function, the audit_msg will get filled in there if needed.

       bool success = RevokeCertificates(session, cuid,audit_msg,(char *)final_applet_version,
                                             keyVersion,(char *)tokenType,(char *)userid,status
        );

        if(!success)  {
            goto loser;
        }

    } else {        
        rc = RA::tdb_update("", cuid, (char *)final_applet_version, keyVersion, "uninitialized", "", tokenType);
        if (rc != 0) {
            RA::Debug(LL_PER_PDU, "RA_Processor::Format",
              "Failed to update the token database");
            status = STATUS_ERROR_UPDATE_TOKENDB_FAILED;
            PR_snprintf(audit_msg, 512, "Failed to update the token database, status = STATUS_ERROR_UPDATE_TOKENDB_FAILED");
            goto loser;
        }
    }

    // send status update to the client
    if (extensions != NULL &&
               extensions->GetValue("statusUpdate") != NULL) {
                      StatusUpdate(session, 100 /* progress */,
                                                 "PROGRESS_DONE");
    }

    status = STATUS_NO_ERROR;
    rc = 1;

    end = PR_IntervalNow();

    sprintf(activity_msg, "applet_version=%s tokenType=%s", 
           final_applet_version, tokenType);
    RA::tdb_activity(session->GetRemoteIP(), cuid, "format", "success", activity_msg, userid, tokenType);

    /* audit log for successful format */
    if (authid != NULL) {
        sprintf(activity_msg, "format processing complete, authid = %s", authid);
    } else {
        sprintf(activity_msg, "format processing complete");
    } 
    RA::Audit(EV_FORMAT, AUDIT_MSG_PROC, 
      userid, cuid, msn, "success", "format", final_applet_version, 
      keyVersion != NULL? keyVersion : "", activity_msg);

loser:
    if (strlen(audit_msg) > 0) { // a failure occurred
        RA::Audit(EV_FORMAT, AUDIT_MSG_PROC,
          userid != NULL ? userid : "",
          cuid != NULL ? cuid : "",
          msn != NULL ? msn : "",
          "failure",
          "format",
          final_applet_version != NULL ? final_applet_version : "",
          keyVersion != NULL? keyVersion : "",
          audit_msg);

        if ((cuid != NULL) && (tokenType != NULL)) {
            RA::tdb_activity(session->GetRemoteIP(),
                cuid, 
                "format", 
                "failure",
                audit_msg, 
                userid != NULL? userid : "", 
                tokenType);
        } 
    }

    if (curKeyInfoStr != NULL) {
        PR_Free( (char *) curKeyInfoStr);
        curKeyInfoStr = NULL;
    }

    if (newVersionStr != NULL) {
        PR_Free( (char *) newVersionStr);
        newVersionStr = NULL;
    }

    if (keyVersion != NULL) {
        PR_Free( (char *) keyVersion );
        keyVersion = NULL;
    }

    if (ldapResult != NULL) {
        ldap_msgfree(ldapResult);
    }

    if( cplc_data != NULL ) {
        delete cplc_data;
        cplc_data = NULL;
    }
    if( CardManagerAID != NULL ) {
        delete CardManagerAID;
        CardManagerAID = NULL;
    }
    if( NetKeyAID != NULL ) {
        delete NetKeyAID;
        NetKeyAID = NULL;
    }
    if( channel != NULL ) {
        delete channel;
        channel = NULL;
    }
    if( token_status != NULL ) {
        delete token_status;
        token_status = NULL;
    }
    if( buildID != NULL ) {
        delete buildID;
        buildID = NULL;
    }
    if( appletVersion != NULL ) {
        PR_Free( (char *) appletVersion );
        appletVersion = NULL;
    }
    if( final_applet_version != NULL ) {
        PR_Free( (char *) final_applet_version );
        final_applet_version = NULL;
    }
    if( userid != NULL ) {
        PR_Free( (char *) userid );
        userid = NULL;
    }
    if( cuid != NULL ) {
        PR_Free( cuid );
        cuid = NULL;
    }
    if( msn != NULL ) {
        PR_Free( msn );
        msn = NULL;
    }
    if( authParams != NULL ) {
        delete authParams;
        authParams = NULL;
    }
    if( login != NULL ) {
        delete login;
        login = NULL;
    }

#ifdef   MEM_PROFILING     
            MEM_dump_unfree();
#endif

    RA::Debug("RA_Processor::Format"," returning status %d", status);
    return status;
}

RA_Status RA_Processor::UpdateTokenRecoveredCerts( RA_Session *session, PKCS11Obj *pkcs11objx, Secure_Channel *channel, 
    char *applet_version, char *keyVersion)
{
    static const char *OP_PREFIX = "op.enroll";
    char audit_msg[512] = "";
    char activity_msg[512] = "";
    char keyTypePrefix[200] = "";
    char configname[200] = "";
    RA_Status status = STATUS_NO_ERROR;
    int count = 0;
    PRUint64 certSerial = 0;

    const char *userid = NULL;
    const char *cuid = NULL;
    const char *msn = NULL;

    SECItem si_mod;
    Buffer *modulus=NULL;
    CERTSubjectPublicKeyInfo*  spkix = NULL;
    SECItem *si_kid = NULL;
    Buffer *keyid=NULL;
    SECItem si_exp;
    Buffer *exponent=NULL;
    int keysize = 0;
    int keyUser = 0;
    int keyUsage = 0;
    const char *tokenType = NULL;

    BYTE objid[4];

    SECStatus rv;
    SECItem der;
    CERTSubjectPublicKeyInfo*  spki = NULL;
    SECKEYPublicKey *pk_p = NULL;
    CERTCertificate *cert = NULL;

    char * o_pub = NULL;
    char * o_priv = NULL;
    char *ivParam = NULL;
    char *label = NULL;
    char finalLabel[200] = "";

    const char *pattern = NULL;
    NameValueSet nv;

    objid[0] = 0xFF;
    objid[1] = 0x00;
    objid[2] = 0xFF;
    objid[3] = 0xF3;

    ExternalRegAttrs *erAttrs = NULL;
    ExternalRegCertToRecover **erCertsToRecover = NULL;
    ExternalRegCertToRecover *erCertToRecover = NULL;
    ExternalRegCertKeyInfo * erCertKeyInfo = NULL;

    erAttrs = session->getExternalRegAttrs();

    if (erAttrs == NULL) {
        status = STATUS_ERROR_RECOVERY_FAILED;
        goto loser;
    }

    erCertsToRecover = erAttrs->getCertsToRecover();

    if (erCertsToRecover == NULL) {
        status = STATUS_ERROR_RECOVERY_FAILED;
        goto loser;
    }

    count = erAttrs->getCertsToRecoverCount();

    if (count == 0) {
        goto loser;
    }

    tokenType = erAttrs->getTokenType();

    // Purge the object list of certs that have not been explicilty saved from deletion

    CleanObjectListBeforeExternalRecovery(pkcs11objx, erAttrs, applet_version, keyVersion);


    snprintf(keyTypePrefix, 200,"op.enroll.%s.keyGen.encryption",tokenType);
    userid = erAttrs->getUserId();
    cuid = erAttrs->getTokenCUID();
    msn = erAttrs->getTokenMSN();

    // set allowable $$ config patterns
    //pretty_cuid = GetPrettyPrintCUID(cuid);

    //nv.Add("pretty_cuid", pretty_cuid);

    if (cuid)
        nv.Add("cuid", cuid);

    if (msn)
        nv.Add("msn", msn);

    if(userid)
        nv.Add("userid", userid);

    PR_snprintf((char *)configname, 256, "%s.%s.keyGen.%s.label",
                            OP_PREFIX, tokenType, "encryption");
    pattern =  RA::GetConfigStore()->GetConfigAsString(configname, "encryption key for $userid$");

    if (pattern) {
        label = MapPattern(&nv, (char *) pattern);
    }

    if (!label) {
        status = STATUS_ERROR_RECOVERY_FAILED;
        goto loser;
    }

    RA::Debug(LL_PER_PDU, "RA_Processor::UpdateTokenRecoveredCert", "Actually write %d recovered certs to token object. \n", count);

    for (int i = 0; i< count; i++) {

        erCertToRecover = erCertsToRecover[i];

        certSerial = erCertToRecover->getSerial();

        if (!erCertToRecover)
            continue;
       
        erCertKeyInfo = erCertToRecover->getCertKeyInfo(); 

        if (!erCertKeyInfo)
            continue;

        o_pub =  erCertKeyInfo->getPublicKey();
        o_priv = erCertKeyInfo->getWrappedPrivKey();
        ivParam = erCertKeyInfo->getIVParam();
        cert = erCertKeyInfo->getCert();

        if (o_pub == NULL || o_priv == NULL || ivParam == NULL) {
            RA::Debug(LL_PER_PDU, "RA_Processor::UpdateTokenRecoveredCert", "Certifcate may be signing, retain only (not recover) cert, skipping... \n");
            continue;
        }

        int pubKeyNumber = 0;
        int priKeyNumber = 0;
        cert = erCertKeyInfo->getCert();

        int newCertId = 0;
        
        char certId[3];
        char certAttrId[3];
        char privateKeyAttrId[3];
        char publicKeyAttrId[3];

        bool isCertPresent = isCertInObjectList(pkcs11objx, cert);

        if (isCertPresent) { /* Just skip this one, it is here already */

            RA::Debug(LL_PER_PDU, "RA_Processor::UpdateTokenRecoveredCert", "Certifcate already on token, no need to recover further. \n", count);
            continue;

        }
   
        newCertId = GetNextFreeCertIdNumber(pkcs11objx);

        certId[0] = 'C';
        certId[1] = '0' + newCertId;
        certId[2] = 0;

        certAttrId[0] = 'c';
        certAttrId[1] = '0' + newCertId;
        certAttrId[2] = 0;

        pubKeyNumber = 2 * newCertId + 1;
        priKeyNumber = 2 * newCertId;

        privateKeyAttrId[0] = 'k';
        privateKeyAttrId[1] = '0' + priKeyNumber;
        privateKeyAttrId[2] = 0;

        publicKeyAttrId[0] = 'k';
        publicKeyAttrId[1] = '0' + pubKeyNumber;
        publicKeyAttrId[2] = 0;
 
        der.type = (SECItemType) 0; /* initialize it, since convertAsciiToItem does not set it */
        rv = ATOB_ConvertAsciiToItem (&der, o_pub);

        if (rv != SECSuccess){
            RA::Debug("RA_Processor::UpdateTokenRecoveredCert", "after converting public key, rv is failure");
            SECITEM_FreeItem(&der, PR_FALSE);
            status = STATUS_ERROR_RECOVERY_FAILED;
            PR_snprintf(audit_msg, 512, "Key Recovery failed. after converting public key, rv is failure");
            goto loser;
	}else {
            RA::Debug(LL_PER_PDU, "RA_Processor::UpdateTokenRecoveredCert", "item len=%d, item type=%d",der.len, der.type);

            spki = SECKEY_DecodeDERSubjectPublicKeyInfo(&der);
            SECITEM_FreeItem(&der, PR_FALSE);

            if (spki != NULL) {
                RA::Debug("RA__Processor::UpdateTokenRecoveredCert", "after converting public key spki is not NULL");
                pk_p = SECKEY_ExtractPublicKey(spki);
                if (pk_p != NULL)
                    RA::Debug("RA_Processor::UpdateTokenRecoveredCert", "after converting public key pk_p is not NULL");
                else
                    RA::Debug("RA_Processor::UpdateTokenRecoveredCert", "after converting public key, pk_p is NULL");
            } else
                          RA::Debug("RA_Processor::UpdateTokenRecoveredCert", "after converting public key, spki is NULL");
        }

        SECKEY_DestroySubjectPublicKeyInfo(spki);

        if( pk_p == NULL ) {
            RA::Debug("RA_Processor::UpdateTokenRecoveredCert",
                         "pk_p is NULL; unable to continue");
                          status = STATUS_ERROR_RECOVERY_FAILED;
                          PR_snprintf(audit_msg, 512, "Key Recovery failed. pk_p is NULL; unable to continue");
            goto loser;
        }

        si_mod = pk_p->u.rsa.modulus;
        modulus = new Buffer((BYTE*) si_mod.data, si_mod.len);

        keysize = si_mod.len * 8;
        spkix = SECKEY_CreateSubjectPublicKeyInfo(pk_p);

        /* 
	 * RFC 3279
	 * The keyIdentifier is composed of the 160-bit SHA-1 hash of the
         * value of the BIT STRING subjectPublicKey (excluding the tag,
         * length, and number of unused bits).
          */
        spkix->subjectPublicKey.len >>= 3;
        si_kid = PK11_MakeIDFromPubKey(&spkix->subjectPublicKey);
        spkix->subjectPublicKey.len <<= 3;
        SECKEY_DestroySubjectPublicKeyInfo(spkix);

        keyid = new Buffer((BYTE*) si_kid->data, si_kid->len);
        si_exp = pk_p->u.rsa.publicExponent;
        exponent =  new Buffer((BYTE*) si_exp.data, si_exp.len);

        RA::Debug(LL_PER_PDU, "RA_Processor::UpdateRecoveredTokenCerts",
				  " keyid, modulus and exponent are retrieved");

        // Create KeyBlob for private key, but first b64 decode it
        /* url decode o_priv */
        {
            Buffer priv_keyblob;
            Buffer *decodeKey = Util::URLDecode(o_priv);
	    //RA::DebugBuffer("cfu debug"," private key =",decodeKey);
            priv_keyblob =
            Buffer(1, 0x01) + // encryption
			    Buffer(1, 0x09)+ // keytype is RSAPKCS8Pair
			    Buffer(1,(BYTE)(keysize/256)) + // keysize is two bytes
			    Buffer(1,(BYTE)(keysize%256)) +
			    Buffer((BYTE*) *decodeKey, decodeKey->size());
            delete decodeKey;

            //inject PKCS#8 private key
            BYTE perms[6];
            perms[0] = 0x40;
            perms[1] = 0x00;
            perms[2] = 0x40;
            perms[3] = 0x00;
            perms[4] = 0x40;
            perms[5] = 0x00;

            if (channel->CreateObject(objid, perms, priv_keyblob.size()) != 1) {
                PR_snprintf(audit_msg, 512, "Failed to write key to token. CreateObject failed.");
                goto loser;
            }

            if (channel->WriteObject(objid, (BYTE*)priv_keyblob, priv_keyblob.size()) != 1) {
                 PR_snprintf(audit_msg, 512, "Failed to write key to token. WriteObject failed.");
                 goto loser;
            }
        }

        /* url decode the wrapped kek session key and keycheck*/
        {
            Buffer data;
            Buffer *decodeKey = Util::URLDecode(channel->getKekWrappedDESKey());

            char *keycheck = channel->getKeycheck();
            Buffer *decodeKeyCheck = Util::URLDecode(keycheck);
            if (keycheck)
                PL_strfree(keycheck);

            BYTE alg = 0x80;
            if(decodeKey && decodeKey->size()) {
                alg = 0x81;
            }

            //Get iv data returned by DRM

            Buffer *iv_decoded = Util::URLDecode(ivParam);

            if(iv_decoded == NULL) {
                 PR_snprintf(audit_msg, 512, "ProcessRecovery: store keys in token failed, iv data not found");
                 delete decodeKey;
                 delete decodeKeyCheck;
                 goto loser;
            }

            data =
                Buffer((BYTE*)objid, 4)+ // object id
                Buffer(1,alg) +
                //Buffer(1, 0x08) + // key type is DES3: 8
                Buffer(1, (BYTE) decodeKey->size()) + // 1 byte length
                Buffer((BYTE *) *decodeKey, decodeKey->size())+ // key -encrypted to 3des block
                // check size
                // key check
                Buffer(1, (BYTE) decodeKeyCheck->size()) + //keycheck size
                Buffer((BYTE *) *decodeKeyCheck , decodeKeyCheck->size())+ // keycheck
                Buffer(1, iv_decoded->size())+ // IV_Length
                Buffer((BYTE*)*iv_decoded, iv_decoded->size());

            //RA::DebugBuffer("cfu debug", "ImportKeyEnc data buffer =", &data);

            RA::Debug("RA_Processor::UpdateTokenRecoveredCert", " priKeyNumber %d pubKeyNumber %d \n", priKeyNumber, pubKeyNumber);

            delete decodeKey;
            delete decodeKeyCheck;
            delete iv_decoded;

            if (channel->ImportKeyEnc((keyUser << 4)+priKeyNumber,
                (keyUsage << 4)+pubKeyNumber, &data) != 1) {
                PR_snprintf(audit_msg, 512, "Failed to write key to token. ImportKeyEnc failed.");
                goto loser;
            }
        }

        {
            Buffer *certbuf = new Buffer(cert->derCert.data, cert->derCert.len);
            ObjectSpec *objSpec = 
                ObjectSpec::ParseFromTokenData(
                (certId[0] << 24) +
                (certId[1] << 16),
                certbuf);
            pkcs11objx->AddObjectSpec(objSpec);
        }

        snprintf(finalLabel,200,"%s %s",label, certAttrId);

        {
            Buffer b = channel->CreatePKCS11CertAttrsBuffer(
                KEY_TYPE_ENCRYPTION , certAttrId, finalLabel, keyid);
                ObjectSpec *objSpec = 
                    ObjectSpec::ParseFromTokenData(
                    (certAttrId[0] << 24) +
                    (certAttrId[1] << 16),
                    &b);
                pkcs11objx->AddObjectSpec(objSpec);
        }

        {
            Buffer b = channel->CreatePKCS11PriKeyAttrsBuffer(KEY_TYPE_ENCRYPTION, 
                privateKeyAttrId, finalLabel, keyid, modulus, OP_PREFIX, 
                tokenType, keyTypePrefix);
            ObjectSpec *objSpec = 
                ObjectSpec::ParseFromTokenData(
                (privateKeyAttrId[0] << 24) +
                (privateKeyAttrId[1] << 16),
                &b);
            pkcs11objx->AddObjectSpec(objSpec);
        }

        {
            Buffer b = channel->CreatePKCS11PubKeyAttrsBuffer(KEY_TYPE_ENCRYPTION, 
                publicKeyAttrId,finalLabel, keyid, 
                exponent, modulus, OP_PREFIX, tokenType, keyTypePrefix);
                ObjectSpec *objSpec = 
                ObjectSpec::ParseFromTokenData(
                    (publicKeyAttrId[0] << 24) +
                    (publicKeyAttrId[1] << 16),
                    &b);
            pkcs11objx->AddObjectSpec(objSpec);
        }

        PR_snprintf(activity_msg, 4096, "external registration recovery, certificate %lld stored on token", certSerial);
        RA::Audit(EV_ENROLLMENT, AUDIT_MSG_PROC,
        userid != NULL ? userid : "",
        cuid != NULL ? cuid : "",
        msn != NULL ? msn : "",
        "success",
        "external registration recovery",
         applet_version != NULL ? applet_version :"",
         keyVersion != NULL ? keyVersion : "",
        activity_msg);

        RA::tdb_activity(session->GetRemoteIP(),(char *) cuid, "external registration recovery", "success", activity_msg, userid, tokenType);
    }
loser:

    if (strlen(audit_msg) > 0) { 

        RA::Audit(EV_ENROLLMENT, AUDIT_MSG_PROC,
          userid != NULL ? userid : "",
          cuid != NULL ? cuid : "",
          msn != NULL ? msn : "",
          "failure",
          "external registration recovery",
          "",
          "",
          audit_msg);
    }

    
    
    if( modulus != NULL ) {
        delete modulus;
        modulus = NULL;
    }

    if( keyid != NULL ) {
        delete keyid;
        keyid = NULL;
    }
    if( exponent != NULL ) {
        delete exponent;
        exponent = NULL;
    }

    if( label != NULL ) {
        free(label);
        label = NULL;
    }

    return status;
}

/*
 * RA_Processor::CertCmp
 *   - given two certs, compare and return ture if same, false if not
 */
bool RA_Processor::CertCmp(CERTCertificate *cert1, CERTCertificate *cert2) {
    char *FN = "RA_Processor::CertCmp";
    bool matchAuthKeyID = false;
    bool matchSubjKeyID = false;
    bool matchSerial = false;

    if ((cert1 == NULL) || (cert2 == NULL))
        return false;

    // check separately so we know exactly which attribute fails to match
    matchAuthKeyID = SECITEM_ItemsAreEqual(
        &(cert1->authKeyID->keyID), &(cert2->authKeyID->keyID));
    if (matchAuthKeyID != true)
        RA::Debug(FN, "authority key identifiers do not match");

    matchSubjKeyID = SECITEM_ItemsAreEqual(
        &(cert1->subjectKeyID), &(cert2->subjectKeyID));
    if (matchSubjKeyID != true)
        RA::Debug(FN, "subject key identifiers do not match");

    matchSerial = SECITEM_ItemsAreEqual(
        &(cert1->serialNumber), &(cert2->serialNumber));
    if (matchSerial != true)
        RA::Debug(FN, "serial numbersdo not match");

    return ((matchAuthKeyID == true) &&
        (matchSubjKeyID == true) &&
        (matchSerial == true));
}

/**
 * Process the current session. It does nothing in the base
 * class.
 */
RA_Status RA_Processor::Process(RA_Session *session, NameValueSet *extensions)
{
    return STATUS_NO_ERROR;
} /* Process */

int RA_Processor::GetNextFreeCertIdNumber(PKCS11Obj *pkcs11objx)
{
    if(!pkcs11objx)
        return 0;

    //Look through the objects actually currently on the token
    //to determine an appropriate free certificate id

     int num_objs = pkcs11objx->PKCS11Obj::GetObjectSpecCount();
    char objid[2];

    int highest_cert_id = 0;
    for (int i = 0; i< num_objs; i++) {
        ObjectSpec* os = pkcs11objx->GetObjectSpec(i);
        unsigned long oid = os->GetObjectID();
        objid[0] = (char)((oid >> 24) & 0xff);
        objid[1] = (char)((oid >> 16) & 0xff);

        if(objid[0] == 'C') { //found a certificate

            int id_int = objid[1] - '0';

            if(id_int > highest_cert_id) {
                highest_cert_id = id_int;
            }
          }
    }

    RA::Debug(LL_PER_CONNECTION,
                                  "RA_Enroll_Processor::GetNextFreeCertIdNumber",
                                   "returning id number: %d", highest_cert_id + 1);
    return highest_cert_id + 1;
}

bool RA_Processor::isCertInObjectList(PKCS11Obj *pkcs11objx, CERTCertificate *certToFind)
{
     if ( !pkcs11objx || !certToFind)
         return false;

     SECItem certItem; 
     int num_objs = pkcs11objx->PKCS11Obj::GetObjectSpecCount();
     char b[3];
     bool foundObj = false;

     for (int i = 0; i< num_objs; i++) {
         ObjectSpec* os = pkcs11objx->GetObjectSpec(i);
         unsigned long oid = os->GetObjectID();
         b[0] = (char)((oid >> 24) & 0xff);
         b[1] = (char)((oid >> 16) & 0xff);
         b[2] = '\0';

        if ( b[0] == 'C' )   {
            for (int j = 0 ; j <  os->GetAttributeSpecCount() ; j++ ) {
                AttributeSpec *as = os->GetAttributeSpec(j);
                if (as->GetAttributeID() == CKA_VALUE) {
                    if (as->GetType() == (BYTE) 0) {
                        Buffer cert = as->GetValue();
                        certItem.type = (SECItemType) 0; 
                        certItem.data =  (unsigned char *) cert;
                        certItem.len  = cert.size();

                        SECComparison equal =  SECITEM_CompareItem(&certItem, &certToFind->derCert);

                        if(equal == 0){
                            RA::Debug(LL_PER_PDU, "RA_Processor::isCertObjectList:"," Match found, cert already in object spec list!");
                            return true;
                        }
                    }
                    break;
                 }
            }
        }
     }

    return foundObj;
}

/* Clean the read in ObjectSpec Object List of Certificates that are not mentioned in the CertsToRecoverList
*/

void RA_Processor::CleanObjectListBeforeExternalRecovery(PKCS11Obj *pkcs11objx, ExternalRegAttrs *erAttrs, 
    char *applet_version, char *keyVersion ) {

    const int MAX_CERTS = 30;
    char configname[256] = "";
    char keyTypePrefix[256] = "";

    CERTCertificate *cert = NULL;
    int count = 0;
    const char *tokenType = NULL;
    char audit_msg[500];

    /* Arrays that hold simple indexes of certsToDelete and certsToSave
       certsToDelete is a list of certs NOT in the recovery list.
       certsToSave is a list of certs to spare from deletion because they were 
        enrolled by the regular token profile.
    */

    int certsToDelete[MAX_CERTS] = { 0 };
    int numCertsToDelete = 0;
    int numCertsToSave = 0;
    int certsToSave[MAX_CERTS] = { 0 };


    if (!pkcs11objx || ! erAttrs)
        return;

    ExternalRegCertToRecover **erCertsToRecover = NULL;
    ExternalRegCertToRecover *erCertToRecover = NULL;
    ExternalRegCertKeyInfo *erCertKeyInfo = NULL;

    erCertsToRecover = erAttrs->getCertsToRecover();

    if (erCertsToRecover == NULL) {
        return;
    }
 
    count = erAttrs->getCertsToRecoverCount();

    if(count == 0)
        return;

    tokenType =  erAttrs->getTokenType();

    if (!tokenType)
        return; 

    const char *userid = erAttrs->getUserId();
    const char *cuid = erAttrs->getTokenCUID();
    const char *msn   = erAttrs->getTokenMSN();

    //Now let's try to save the just freshly enrolled certificates based on regular profile from deletion.

    PR_snprintf((char *)configname, 256, "%s.%s.keyGen.keyType.num", "op.enroll", tokenType);

    int keyTypeNum = RA::GetConfigStore()->GetConfigAsInt(configname);

    if (keyTypeNum > 0) {
        int index = -1;
        for (int i=0; i<keyTypeNum; i++) {
            PR_snprintf((char *)configname, 256, "%s.%s.keyGen.keyType.value.%d", "op.enroll", tokenType, i);
            const char *keyTypeValue = RA::GetConfigStore()->GetConfigAsString(configname, "");

            RA::Debug("RA_Processor::CleanObjectListBeforeExternalRecovery","configname %s  keyTypeValue %s ",configname, keyTypeValue);

            PR_snprintf((char *)keyTypePrefix, 256, "%s.%s.keyGen.%s", "op.enroll", tokenType, keyTypeValue);
            RA::Debug(LL_PER_PDU, "RA_Processor::CleanObjectListBeforeExternalRecovery","keyTypePrefix is %s",keyTypePrefix);

            PR_snprintf((char *)configname, 256,"%s.certId", keyTypePrefix);
            const char *certId = RA::GetConfigStore()->GetConfigAsString(configname, "");

            RA::Debug(LL_PER_PDU, "RA_Processor::CleanObjectListBeforeExternalRecovery","certId is %s",certId);

            if(certId != NULL && strlen(certId) > 1) {
                index = certId[1] - '0';
            }

            if (index >= 0) {
                if(numCertsToSave < MAX_CERTS) {   /* Set an entry in the list in order to save from subsequent deletion. */
                    certsToSave[numCertsToSave++] = index;
                }
            } 
        }
    }

    int num_objs = pkcs11objx->PKCS11Obj::GetObjectSpecCount();
    char b[3];
    bool foundObj = false;

    //Go through the object spec list and remove stuff we have marked for deletion.
    // Remove Cert and all associated objects of that cert.

    for (int i = 0; i< num_objs; i++) {
        ObjectSpec* os = pkcs11objx->GetObjectSpec(i);
        unsigned long oid = os->GetObjectID();
        b[0] = (char)((oid >> 24) & 0xff);
        b[1] = (char)((oid >> 16) & 0xff);
        b[2] = '\0';

       if ( b[0] == 'C' )   {    /* Is this a cert object ? */
           for (int j = 0 ; j <  os->GetAttributeSpecCount() ; j++ ) {
               AttributeSpec *as = os->GetAttributeSpec(j);
               if (as->GetAttributeID() == CKA_VALUE) {
                   if (as->GetType() == (BYTE) 0) {
                       Buffer cert = as->GetValue();
                       SECItem certItem;
                       certItem.type = (SECItemType) 0;
                       certItem.data =  (unsigned char *) cert;
                       certItem.len  = cert.size();
                       bool present =  isInCertsToRecoverList(&certItem, erAttrs);

                       if( present == false) {
                           int certId = (int) b[1] - '0';
                           RA::Debug(LL_PER_PDU, "RA_Processor::CleanObjectListBeforeExternalRecovery"," cert not found in recovery list, possible deletion... id:  %d", certId);
                           /* Now check the certsToSave list to see if this cert is protected */

                           bool protect = false;
                           for(int p = 0 ; p < numCertsToSave; p++) {
                               if( certsToSave[p] == certId)  {
                                  protect = true;
                                  break;
                               }
                           }

                           RA::Debug(LL_PER_PDU, "RA_Processor::CleanObjectListBeforeExternalRecovery"," protect cert %d: %d", certId, protect);
                           /* Delete this cert if it is NOT protected by the certs generated by the profile enrollment. */
                           if((numCertsToDelete < MAX_CERTS) && (protect == false )) {

                                /* Save the info of this cert that is going away, so we can later remove it from the token's list of certs in the db. */
                               ExternalRegCertToDelete *erCertToDelete =
                                   new ExternalRegCertToDelete();

                               PRUint64 serial = 0;
                               if (erCertToDelete) {
                                   char sNum[50];
                                   CERTCertificate  *c = CERT_DecodeCertFromPackage((char *)certItem.data, certItem.len);

                                   RA::Debug(LL_PER_PDU, "RA_Processor::CleanObjectListBeforeExternalRecovery"," cert to delete serial %s:", (char *) sNum);
                                   if ( c != NULL) {
                                      RA::ra_tus_print_integer(sNum, &c->serialNumber);
                                      serial =  strtoll(sNum,NULL,16);
                                      erCertToDelete->setSerial(serial);
                                      erAttrs->addCertToDelete(erCertToDelete); 
                                      CERT_DestroyCertificate(c); 

                                      PR_snprintf(audit_msg, 512, "External Registration Recovery: certificate %s slated for deletion form the token", sNum);
                                      RA::Audit(EV_ENROLLMENT, AUDIT_MSG_PROC,
                                          userid != NULL ? userid : "",
                                          cuid != NULL ? cuid : "",
                                          msn != NULL ? msn : "",
                                          "success",
                                          "external registration recovery",
                                          applet_version != NULL ? applet_version : "",
                                          keyVersion != NULL ? keyVersion : "",
                                          audit_msg);

                                   }
                               }
                               certsToDelete[numCertsToDelete++] = certId;
                           }
                       }
                   }
                   break;
                }
           }
       }
    }

    // Now rifle through the certsToDeleteList and remove those that need to be deleted

    for(int k = 0 ; k <  numCertsToDelete ; k ++ ) {
        RA::Debug("RA_Processor::CleanObjectListBeforeExternalRecovery", "cert to delete %d", certsToDelete[k]);
        RemoveCertFromObjectList(certsToDelete[k], pkcs11objx);
    }
}

/* Remove a certificate from the Object Spec List based on Cert index , C(1), C(2), etc */

void RA_Processor::RemoveCertFromObjectList(int cIndex, PKCS11Obj *pkcs11objx) {

    char b[3];

    if ( !pkcs11objx)
        return;

    RA::Debug("RA_Processor::RemoveCertFromObjectList", "index of cert to delete is: %d", cIndex);

    int objectCount = pkcs11objx->PKCS11Obj::GetObjectSpecCount();

    if ( cIndex < 0 || cIndex >= objectCount)
        return;

    int C = cIndex;
    int c = cIndex;
    int k1 = 2 *cIndex;
    int k2 = 2 * cIndex + 1;

    int index = 0;
    for (int i = 0; i< pkcs11objx->PKCS11Obj::GetObjectSpecCount() ;  i++) {
        ObjectSpec* os = pkcs11objx->GetObjectSpec(i);
        unsigned long oid = os->GetObjectID();
        b[0] = (char)((oid >> 24) & 0xff);
        b[1] = (char)((oid >> 16) & 0xff);
        b[2] = '\0';

       index = b[1] - '0';

       if ( b[0] == 'C' || b[0] == 'c' )   {
           if (  index == C || index == c ) {
               RA::Debug(LL_PER_PDU, "RA_Processor::RemoveCertFromObjectList",
                   "Removing Object %s", b);

               pkcs11objx->RemoveObjectSpec(i);
               i--;
           }
       }

       if ( b[0] == 'k' ) {

           if (index == k1 || index == k2) {
               RA::Debug(LL_PER_PDU, "RA_Processor::RemoveCertFromObjectList",
                   "Removing Object %s", b);

               pkcs11objx->RemoveObjectSpec(i);
               i--;
           }
       }
    } 
}

/* Does given cert exist in the ExternalRegAttrs CertsToRecoverList 
   We need to know if this cert is to be retained for an ExternalReg Recovery operation.
   If cert is in the list, it will be retained and not erased, otherwise it will go away.
*/

bool RA_Processor::isInCertsToRecoverList(SECItem *secCert, ExternalRegAttrs *erAttrs) {

    bool foundObj = false;
    if (!secCert || !erAttrs)
        return foundObj;

    CERTCertificate *cert = NULL;
    ExternalRegCertToRecover **erCertsToRecover = NULL;
    ExternalRegCertToRecover *erCertToRecover = NULL;
    ExternalRegCertKeyInfo *erCertKeyInfo = NULL;

    erCertsToRecover = erAttrs->getCertsToRecover();

    if (erCertsToRecover == NULL) {
        return foundObj;
    }

    int count = erAttrs->getCertsToRecoverCount();

    if(count == 0)
        return foundObj;

    for (int i = 0; i< count; i++) {
        erCertToRecover = erCertsToRecover[i];
        if (!erCertToRecover)
            continue;
        erCertKeyInfo = erCertToRecover->getCertKeyInfo();
        if (!erCertKeyInfo)
            continue;
        cert = erCertKeyInfo->getCert();
        if (cert) {
            SECComparison equal =  SECITEM_CompareItem(secCert, &cert->derCert);
            if (equal == 0) {
                foundObj = true;
                break;
            }
        }
    }
    return foundObj;
}
