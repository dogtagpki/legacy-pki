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

#include "engine/RA.h"
#include "main/Util.h"
#include "main/RA_Msg.h"
#include "main/RA_Session.h"
#include "channel/Secure_Channel.h"
#include "processor/RA_Processor.h"
#include "processor/RA_Pin_Reset_Processor.h"
#include "main/Memory.h"
#include "tus/tus_db.h"
#define OP_PREFIX "op.pinReset"
static const char *expected_version = NULL;

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs a processor for hanlding pin reset operation.
 */
TPS_PUBLIC RA_Pin_Reset_Processor::RA_Pin_Reset_Processor()
{
}

/**
 * Destructs pin reset processor.
 */
TPS_PUBLIC RA_Pin_Reset_Processor::~RA_Pin_Reset_Processor()
{
}

/**
 * Process the current session.
 */
TPS_PUBLIC RA_Status RA_Pin_Reset_Processor::Process(RA_Session *session, NameValueSet *extensions)
{
    char **tokenOwner=NULL;
    char configname[256];
    const char *tokenType = NULL;
    char *cuid = NULL;
    const char *msn = NULL;
    PRIntervalTime start, end;
    RA_Status status = STATUS_NO_ERROR;
    int rc = -1;
    AuthParams *login = NULL;
    Secure_Channel *channel = NULL;
    char *new_pin = NULL;
    unsigned int minlen = 0, maxlen = 0;
    const char *applet_dir;
    bool upgrade_enc = false;
    char curVer[10];
    char newVer[10];

    char *curKeyInfoStr = NULL;
    char *newVersionStr = NULL;

    SecurityLevel security_level = SECURE_MSG_MAC_ENC;
    Buffer *CardManagerAID = RA::GetConfigStore()->GetConfigAsBuffer(
		    RA::CFG_APPLET_CARDMGR_INSTANCE_AID,
		    RA::CFG_DEF_CARDMGR_INSTANCE_AID);
    Buffer *NetKeyAID = RA::GetConfigStore()->GetConfigAsBuffer(
		    RA::CFG_APPLET_NETKEY_INSTANCE_AID,
		    RA::CFG_DEF_NETKEY_INSTANCE_AID);

    int i;
    Buffer key_data_set;
    Buffer *token_status = NULL;
    Buffer *buildID = NULL;
    char *policy = NULL; 
    char *tmp_policy = NULL; 
    const char* required_version = NULL;
    const char *appletVersion = NULL;
    const char *final_applet_version = NULL;
    char *keyVersion = PL_strdup( "" );
    const char *userid = PL_strdup( "" );
    BYTE major_version = 0x0;
    BYTE minor_version = 0x0;
    BYTE app_major_version = 0x0;
    BYTE app_minor_version = 0x0;
    char *token_userid = NULL;

    Buffer host_challenge = Buffer(8, (BYTE)0);
    Buffer key_diversification_data;
    Buffer key_info_data;
    Buffer card_challenge;
    Buffer card_cryptogram;
    Buffer token_cuid;
    Buffer token_msn;
    const char *connId = NULL;
    const char *connid = NULL;
    const char *tksid = NULL;
    const char *authid = NULL;
    AuthParams *authParams = NULL;
    start = PR_IntervalNow();
    Buffer *cplc_data = NULL;
    char activity_msg[4096];
    LDAPMessage *e = NULL;
    LDAPMessage *ldapResult = NULL;
    int maxReturns = 10;
    char audit_msg[512] = "";
    char *profile_state = NULL;
    int key_change_over_success = 0;
    AppletInfo *appInfo = NULL;

    char *FN = ( char * ) "RA_Pin_Reset_Processor::Process";

    RA::Debug("RA_Pin_Reset_Processor::Process", "Client %s",                       session->GetRemoteIP());

    RA::Debug(LL_PER_PDU, "RA_Pin_Reset_Processor::Process",
        "RA_Pin_Reset_Processor::Process");

    PR_snprintf((char *)configname, 256, "externalReg.enable");
    bool isExternalReg = RA::GetConfigStore()->GetConfigAsBool(configname, 0);

    SelectApplet(session, 0x04, 0x00, CardManagerAID);
    cplc_data = GetData(session);
    if (cplc_data == NULL) {
          RA::Error("RA_Pin_Reset_Processor::Process",
                        "Get Data Failed");
          status = STATUS_ERROR_SECURE_CHANNEL;
          PR_snprintf(audit_msg, 512, "Get Data Failed, status = STATUS_ERROR_SECURE_CHANNEL");
          goto loser;
    }
    RA::DebugBuffer("RA_Pin_Reset_Processor::process", "CPLC Data = ", 
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
    RA::DebugBuffer("RA_Pin_Reset_Processor::process", "Token CUID= ",
                        &token_cuid);
    cuid = Util::Buffer2String(token_cuid);

    token_msn = Buffer(cplc_data->substr(41, 4));
    RA::DebugBuffer("RA_Pin_Reset_Processor::process", "Token MSN= ",
                        &token_msn);
    msn = Util::Buffer2String(token_msn);

    /**
     * Checks if the netkey has the required applet version.
     */
    SelectApplet(session, 0x04, 0x00, NetKeyAID);
    token_status = GetStatus(session, 0x00, 0x00);
    if (token_status == NULL) {
      major_version = 0x0;
      minor_version = 0x0;
      app_major_version = 0x0;
      app_minor_version = 0x0;
    } else {
      major_version = ((BYTE*)*token_status)[0];
      minor_version = ((BYTE*)*token_status)[1];
      app_major_version = ((BYTE*)*token_status)[2];
      app_minor_version = ((BYTE*)*token_status)[3];
    }

    RA::Debug(LL_PER_PDU, "RA_Pin_Reset_Processor::Process",
              "Major=%d Minor=%d", major_version, minor_version);
    RA::Debug(LL_PER_PDU, "RA_Pin_Reset_Processor::Process",
	      "Applet Major=%d Applet Minor=%d", app_major_version, app_minor_version);

    if (!RA::ra_is_token_present(cuid)) {
        RA::Error("RA_Pin_Reset_Processor::Process",
                        "CUID %s Not Present", cuid);
        status = STATUS_ERROR_DB;
        PR_snprintf(audit_msg, 512, "CUID Not Present, status = STATUS_ERROR_DB");
        goto loser;
    }

    appInfo = RA::CreateAppletInfo(major_version, minor_version, msn, extensions);

    if (isExternalReg) {
        /*
          need to reach out to the Registration DB (authid)
          Entire user entry should be retrieved and parsed, if needed
          The following are retrieved:
              externalReg.tokenTypeAttributeName=tokenType
              externalReg.certs.recoverAttributeName=certsToRecover
              externalReg.certs.deleteAttributeName=certsToDelete 
         */
        /* get user login and password - set in "login" */
        RA::Debug(LL_PER_PDU, FN,
            "isExternalReg: calling RequestUserId");
        /*
          configname and tokenType are NULL for isExternalReg 
         */
        if (!RequestUserId(OP_PREFIX, session, extensions, NULL /*configname*/, NULL /*tokenType*/, cuid, login, userid, status)){
            PR_snprintf(audit_msg, 512, "RequestUserId error");
            goto loser;
        }
        if (!AuthenticateUser(OP_PREFIX, session, NULL /*configname*/, cuid, extensions,
                NULL /*tokenType*/, login, userid, status)){
            PR_snprintf(audit_msg, 512, "AuthenticateUser error");
            goto loser;
        }

        RA::Debug(LL_PER_PDU, FN, "isExternalReg: get tokenType, etc."); 
        tokenType = "userKey"; //hardcode for now until ldap part code written
    } else {
        // retrieve CUID

        if (!GetTokenType(OP_PREFIX, appInfo, cuid, status, tokenType)) {
            PR_snprintf(audit_msg, 512, "Failed to get token type");
            goto loser;
        }
    }

    // check if profile is enabled 
    PR_snprintf((char *)configname, 256, "config.Profiles.%s.state", tokenType);
    profile_state = (char *) RA::GetConfigStore()->GetConfigAsString(configname);
    if ((profile_state != NULL) && (PL_strcmp(profile_state, "Enabled") != 0)) {
        RA::Error("RA_Pin_Reset_Processor::Process", "Profile %s Disabled for CUID %s", tokenType, cuid);
        status =  STATUS_ERROR_DEFAULT_TOKENTYPE_PARAMS_NOT_FOUND;
        PR_snprintf(audit_msg, 512, "profile %s disabled", tokenType);
        goto loser;
    }

    /*isExternalReg: still allow token disabled?*/
    if (RA::ra_is_tus_db_entry_disabled(cuid)) {
        RA::Error("RA_Pin_Reset_Processor::Process",
                        "CUID %s Disabled", cuid);
        status = STATUS_ERROR_DISABLED_TOKEN;
        PR_snprintf(audit_msg, 512, "Token disabled, status = STATUS_ERROR_DISABLED_TOKEN");
        goto loser;
     }

    // we know cuid and msn here 
    RA::Audit(EV_PIN_RESET, AUDIT_MSG_PROC,
      userid != NULL ? userid : "",
      cuid != NULL ? cuid : "",
      msn != NULL ? msn : "",
      "success",
      "pin_reset",
      final_applet_version != NULL ? final_applet_version : "",
      keyVersion != NULL? keyVersion : "",
      "token enabled");

    if (!RA::ra_is_token_pin_resetable(cuid)) {
        RA::Error("RA_Pin_Reset_Processor::Process",
                        "CUID %s Cannot Pin Reset", cuid);
        status = STATUS_ERROR_NOT_PIN_RESETABLE;
        PR_snprintf(audit_msg, 512, "token cannot pin reset, status = STATUS_ERROR_PIN_RESETABLE");
        goto loser;
      }

    // we know cuid and msn here 
    RA::Audit(EV_PIN_RESET, AUDIT_MSG_PROC,
      userid != NULL ? userid : "",
      cuid != NULL ? cuid : "",
      msn != NULL ? msn : "",
      "success",
      "pin_reset",
      final_applet_version != NULL ? final_applet_version : "",
      keyVersion != NULL? keyVersion : "",
      "pin reset allowed");

    PR_snprintf((char *)configname, 256, "%s.%s.tks.conn",
                    OP_PREFIX, tokenType);
    tksid = RA::GetConfigStore()->GetConfigAsString(configname);
    if (tksid == NULL) {
        RA::Error("RA_Pin_Reset_Processor::Process",
                        "TKS Connection Parameter %s Not Found", configname);
        status = STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND;
        PR_snprintf(audit_msg, 512, "TKS Connection Parameter %s Not Found, status = STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND", configname);
        goto loser;
    }

    buildID = GetAppletVersion(session);
    if (buildID == NULL) {
        PR_snprintf((char *)configname, 256, "%s.%s.update.applet.emptyToken.enable", OP_PREFIX,
          tokenType); 
         if (RA::GetConfigStore()->GetConfigAsBool(configname, 0)) {
                 appletVersion = PL_strdup( "unknown" );
         } else {
          	RA::Error("RA_Pin_Reset_Processor::Process", 
			"no applet found and applet upgrade not enabled");
                 status = STATUS_ERROR_SECURE_CHANNEL;
                PR_snprintf(audit_msg, 512, "no applet found and applet upgrade not enabled, status = STATUS_ERROR_SECURE_CHANNEL");
		 goto loser;
	 }
    } else {
      char * buildid =  Util::Buffer2String(*buildID);
      RA::Debug("RA_Pin_Reset_Processor", "buildid = %s", buildid);
      char version[13];
      PR_snprintf((char *) version, 13,
		  "%x.%x.%s", app_major_version, app_minor_version,
		  buildid);
      appletVersion = strdup(version);
      if (buildid != NULL) {
          PR_Free(buildid);
          buildid = NULL;
      }
    }

    final_applet_version = strdup(appletVersion);
    RA::Debug("RA_Pin_Reset_Processor", "final_applet_version = %s", final_applet_version);

    /**
     * Checks if we need to upgrade applet. 
     */
    PR_snprintf((char *)configname, 256, "%s.%s.update.applet.enable", OP_PREFIX, tokenType);
    if (RA::GetConfigStore()->GetConfigAsBool(configname, 0)) {
        PR_snprintf((char *)configname, 256, "%s.%s.update.applet.requiredVersion", OP_PREFIX, tokenType);
        required_version = RA::GetConfigStore()->GetConfigAsString(configname);
	expected_version = PL_strdup(required_version);

	if (expected_version == NULL) {
             RA::Error("RA_Pin_Reset_Processor::Process", 
			"misconfiguration for upgrade");
              status = STATUS_ERROR_MISCONFIGURATION;
              PR_snprintf(audit_msg, 512, "misconfiguration for upgrade, status = STATUS_ERROR_MISCONFIGURATION");
              goto loser;
	}
	/* Bugscape #55826: used case-insensitive check below */
        if (PL_strcasecmp(expected_version, appletVersion) != 0) {
                /* upgrade applet */
            PR_snprintf((char *)configname, 256, "%s.%s.update.applet.directory", OP_PREFIX, tokenType);
            applet_dir = RA::GetConfigStore()->GetConfigAsString(configname);
            if (applet_dir == NULL || strlen(applet_dir) == 0) {
                RA::Error(LL_PER_PDU, "RA_Processor::UpgradeApplet",
                                "Failed to get %s", applet_dir);
                PR_snprintf(audit_msg, 512, "Failed to get %s", applet_dir);
                goto loser;
            }
            PR_snprintf((char *)configname, 256, "%s.%s.update.applet.encryption", OP_PREFIX, tokenType);
            upgrade_enc = RA::GetConfigStore()->GetConfigAsBool(configname, true);
            if (!upgrade_enc)
              security_level = SECURE_MSG_MAC;
            PR_snprintf((char *)configname, 256, "%s.%s.tks.conn", OP_PREFIX, tokenType);
            connid = RA::GetConfigStore()->GetConfigAsString(configname);
            int upgrade_rc = UpgradeApplet(session, OP_PREFIX, (char*)tokenType, major_version, minor_version, 
                expected_version, applet_dir, security_level, connid, extensions, 30, 70, &keyVersion, token_cuid, msn);
	    if (upgrade_rc != 1) {
               RA::Error("RA_Pin_Reset_Processor::Process", 
			"upgrade failure");
              status = STATUS_ERROR_UPGRADE_APPLET;
              /**
               * Bugscape #55709: Re-select Net Key Applet ONLY on failure.
               */
              SelectApplet(session, 0x04, 0x00, NetKeyAID);

              if (upgrade_rc == -1) {
                 RA::Audit(EV_APPLET_UPGRADE, AUDIT_MSG_APPLET_UPGRADE,
                 userid, cuid, msn, "Failure", "pin_reset",
                 keyVersion != NULL? keyVersion : "", appletVersion, expected_version, "failed to setup secure channel");
              } else {

                  RA::Audit(EV_APPLET_UPGRADE, AUDIT_MSG_APPLET_UPGRADE,
                  userid, cuid, msn, "Success", "pin_reset",
                  keyVersion != NULL? keyVersion : "", appletVersion, expected_version, "setup secure channel");
             }


              RA::Audit(EV_APPLET_UPGRADE, AUDIT_MSG_APPLET_UPGRADE,
                userid, cuid, msn, "Failure", "pin_reset", 
                keyVersion != NULL? keyVersion : "", 
                appletVersion, expected_version, "applet upgrade");
              goto loser;
	    }

            RA::Audit(EV_APPLET_UPGRADE, AUDIT_MSG_APPLET_UPGRADE,
                  userid, cuid, msn, "Success", "pin_reset",
                  keyVersion != NULL? keyVersion : "", appletVersion, expected_version, "setup secure channel");

            RA::Audit(EV_APPLET_UPGRADE, AUDIT_MSG_APPLET_UPGRADE,
              userid, cuid, msn, "Success", "pin_reset", 
              keyVersion != NULL? keyVersion : "", 
              appletVersion, expected_version, "applet upgrade");

	    final_applet_version = expected_version;
        }
    }

    /**
     * Checks if the netkey has the required key version.
     */
    PR_snprintf((char *)configname, 256, "%s.%s.update.symmetricKeys.enable", OP_PREFIX, tokenType);

    if (RA::GetConfigStore()->GetConfigAsBool(configname, 0)) {
      PR_snprintf((char *)configname, 256, "%s.%s.update.symmetricKeys.requiredVersion", OP_PREFIX, tokenType);
      int requiredVersion = RA::GetConfigStore()->GetConfigAsInt(configname, 0x00);
      PR_snprintf((char *)configname, 256, "%s.%s.tks.conn", OP_PREFIX, tokenType);
      connId = RA::GetConfigStore()->GetConfigAsString(configname);
      if( channel != NULL ) {
          delete channel;
          channel = NULL;
      }

      channel = SetupSecureChannel(
                   session, requiredVersion, 
                   0x00  /* default key index */,
                   connId, token_cuid, OP_PREFIX, tokenType, appInfo);
      if (channel == NULL) {

        /* if version 0x02 key not found, create them */
        SelectApplet(session, 0x04, 0x00, CardManagerAID);
        channel = SetupSecureChannel(
                      session,
                      0x00,  /* default key version */
                      0x00  /* default key index */,
                      connId, token_cuid, OP_PREFIX, tokenType, appInfo);

        if (channel == NULL) {
            RA::Error("RA_Pin_Reset_Processor::Process", 
			"setup secure channel failure");
            status = STATUS_ERROR_SECURE_CHANNEL;
            PR_snprintf(audit_msg, 512, "setup secure channel failure, status = STATUS_ERROR_SECURE_CHANNEL");
            goto loser;
	}

        rc = channel->ExternalAuthenticate();
        if (rc != 1) {
            RA::Error("RA_Pin_Reset_Processor::Process", 
			"External authentication in secure channel failed");
            status = STATUS_ERROR_EXTERNAL_AUTH;
            PR_snprintf(audit_msg, 512, "External authentication in secure channel failed, status = STATUS_ERROR_EXTERNAL_AUTH");
            goto loser;
        } 

        PR_snprintf((char *)configname, 256, "%s.%s.update.symmetricKeys.requiredVersion", OP_PREFIX, tokenType);
        int v = RA::GetConfigStore()->GetConfigAsInt(configname, 0x00);
        Buffer curKeyInfo = channel->GetKeyInfoData();
        BYTE nv[2] = { v, 0x01 };
        Buffer newVersion(nv, 2);
        PR_snprintf((char *)configname,  256,"%s.%s.tks.conn", OP_PREFIX, tokenType);
        connid = RA::GetConfigStore()->GetConfigAsString(configname);
        rc = CreateKeySetData(
             token_cuid,
             channel->GetKeyDiversificationData(),
             curKeyInfo,
             newVersion,
             key_data_set, connid, OP_PREFIX, tokenType, appInfo);
        if (rc != 1) {
            RA::Error("RA_Pin_Reset_Processor::Process",
                        "failed to create new key set");
            status = STATUS_ERROR_CREATE_CARDMGR;
            PR_snprintf(audit_msg, 512, "failed to create new key set, status = STATUS_ERROR_CREATE_CARDMGR");
            goto loser;
        }

	 BYTE curVersion = ((BYTE*)curKeyInfo)[0];
         BYTE curIndex = ((BYTE*)curKeyInfo)[1];
         rc = channel->PutKeys(session,
                  curVersion,
                  curIndex,
                  &key_data_set);

        curKeyInfoStr = Util::Buffer2String(curKeyInfo);
        newVersionStr = Util::Buffer2String(newVersion);

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

        /**
         * PAS Modification
         * Removed only audit log entry for put key failure and replaced with additional logging and token activity database update.  ABOVE ^^^
         */

        /**
        if (rc!=0) {
            RA::Audit(EV_KEY_CHANGEOVER, AUDIT_MSG_KEY_CHANGEOVER,
                userid != NULL ? userid : "", cuid != NULL ? cuid : "", msn != NULL ? msn : "", "Failure", "pin_reset",
                final_applet_version != NULL ? final_applet_version : "", curVer, newVer,
                "key changeover failed");
        }
         */

        /**
         * PAS Modification
         * Previously the return code from put keys was not evaluated or recorded on failure
         * Prior comment block identified the necessity of evaluation and audit logging on failure
         */

        if(rc < 0){
            RA::Debug("RA_Processor::Format", "Failed to Put Keys for token %s", cuid);
            status = STATUS_ERROR_KEY_CHANGE_OVER;

            RA::Audit(EV_KEY_CHANGEOVER, AUDIT_MSG_KEY_CHANGEOVER,
                                userid != NULL ? userid : "", cuid != NULL ? cuid : "", msn != NULL ? msn : "", "failure", "format",
                                        final_applet_version != NULL ? final_applet_version : "", curKeyInfoStr, newVersionStr,
                                                "failed to put new GP key set to token");

            // update activity database with entry about put key event
            RA::tdb_activity(session->GetRemoteIP(), cuid, OP_PREFIX, "failure", "Failed to send new GP Key Set to token", (userid == NULL) ? "" : userid, tokenType);

            /**
             * PAS Modification
             * New configuration value to permit rollback of KeyInfo in Token DB, default disabled
             *
             */
            snprintf((char *)configname, 256, "%s.%s.rollbackKeyVersionOnPutKeyFailure", OP_PREFIX, tokenType);
            if(RA::GetConfigStore()->GetConfigAsBool(configname, 0)){
                rc = RA::tdb_update(NULL, cuid, NULL, curKeyInfoStr, NULL, NULL, NULL);
                if (rc < 0) {
                    RA::Debug(LL_PER_PDU, "RA_Processor::Format","Failed to update the token database with current key version");
                    status = STATUS_ERROR_UPDATE_TOKENDB_FAILED;  //clobbers the previous failure message :-(

                    RA::Audit(EV_TOKENDB_UPDATE, AUDIT_MSG_TOKENDB_UPDATE, "", cuid, "", curKeyInfoStr, "", "", "", "failed to update tokenDB to current key version");

                    goto loser;
                }else{

                    RA::Debug(LL_PER_PDU, "RA_Processor::Format","Successfully updated the token database with current key version");
                    RA::Audit(EV_TOKENDB_UPDATE, AUDIT_MSG_TOKENDB_UPDATE, "", cuid, "", curKeyInfoStr, "", "", "", "successfully updated tokenDB to current key version");

                }
            }
            goto loser;
        }else {


            RA::Audit(EV_KEY_CHANGEOVER, AUDIT_MSG_KEY_CHANGEOVER,
                                userid != NULL ? userid : "", cuid != NULL ? cuid : "", msn != NULL ? msn : "", "success", "format",
                                        final_applet_version != NULL ? final_applet_version : "", curKeyInfoStr, newVersionStr,
                                                "put new GP key set to token");

            RA::tdb_activity(session->GetRemoteIP(), cuid, OP_PREFIX, "success", "Sent new GP Key Set to token", (userid == NULL) ? "" : userid, tokenType);

        }
         SelectApplet(session, 0x04, 0x00, NetKeyAID);
        PR_snprintf((char *)configname, 256, "%s.%s.update.symmetricKeys.requiredVersion", OP_PREFIX, tokenType);
        if( channel != NULL ) {
            delete channel;
            channel = NULL;
        }

        PR_snprintf((char *)configname, 256, "%s.%s.tks.conn", OP_PREFIX, tokenType);
        connId = RA::GetConfigStore()->GetConfigAsString(configname);
         channel = SetupSecureChannel(
                      session, 
                      RA::GetConfigStore()->GetConfigAsInt(configname, 0x00),
                      0x00  /* default key index */,
                      connId, token_cuid, OP_PREFIX, tokenType, appInfo);
         if (channel == NULL) {
            RA::Error("RA_Pin_Reset_Processor::Process", 
			"setup secure channel failure");
            status = STATUS_ERROR_CREATE_CARDMGR;
            PR_snprintf(audit_msg, 512, "setup secure channel failure, status = STATUS_ERROR_CREATE_CARDMGR");
            goto loser;
         }

        RA::Audit(EV_KEY_CHANGEOVER, AUDIT_MSG_KEY_CHANGEOVER,
                userid != NULL ? userid : "", cuid != NULL ? cuid : "", msn != NULL ? msn : "", "Success", "pin_reset",
                final_applet_version != NULL ? final_applet_version : "", curVer, newVer,
                "key changeover");
        key_change_over_success = 1;
      }  else { key_change_over_success = 1; }
    } else {
      PR_snprintf((char *)configname, 256, "%s.%s.tks.conn", OP_PREFIX, tokenType);
      connId = RA::GetConfigStore()->GetConfigAsString(configname);
      if( channel != NULL ) {
          delete channel;
          channel = NULL;
      }
      channel = SetupSecureChannel(
                  session,
                  0x00,
                  0x00  /* default key index */,
                  connId, token_cuid, OP_PREFIX, tokenType, appInfo);
    }

    /* we should have a good channel here */
    if (channel == NULL) {
            RA::Error("RA_Pin_Reset_Processor::Process", 
			"no channel creation failure");
            status = STATUS_ERROR_CREATE_CARDMGR;
            PR_snprintf(audit_msg, 512, "no channel creation failure, status = STATUS_ERROR_CREATE_CARDMGR");
            goto loser;
    }

    if (channel != NULL) {
	if( keyVersion != NULL ) {
		PR_Free( (char *) keyVersion );
		keyVersion = NULL;
	}
        keyVersion = Util::Buffer2String(channel->GetKeyInfoData());
    }

    PR_snprintf((char *)configname, 256, "%s.%s.loginRequest.enable", OP_PREFIX, tokenType);

// !isExternalReg : user already authenticated earlier... need to handle audit earlier
if (!isExternalReg) {
    if (!RequestUserId(OP_PREFIX, session, extensions, configname, tokenType, cuid, login, userid, status)){
                PR_snprintf(audit_msg, 512, "RequestUserId error");
        goto loser;
    }

    PR_snprintf((char *)configname, 256, "%s.%s.auth.enable", OP_PREFIX, tokenType);

    if (!AuthenticateUser(OP_PREFIX, session, configname, cuid, extensions,
                tokenType, login, userid, status)){
                PR_snprintf(audit_msg, 512, "AuthenticateUser error");
        goto loser;
    }

    RA::Audit(EV_PIN_RESET, AUDIT_MSG_PROC, 
        userid != NULL ? userid : "",
        cuid != NULL ? cuid : "",
        msn != NULL ? msn : "",
        "success",
        "pinReset",
        final_applet_version != NULL ? final_applet_version : "",
        keyVersion != NULL ? keyVersion : "",
        "token login successful");

        // get authid for audit log
        PR_snprintf((char *)configname, 256, "%s.%s.auth.id", OP_PREFIX, tokenType);
        authid = RA::GetConfigStore()->GetConfigAsString(configname);
}


    if (extensions != NULL &&
           extensions->GetValue("statusUpdate") != NULL) {
           StatusUpdate(session, 30 /* progress */,
                        "PROGRESS_START_AUTHENTICATION");
    }

    RA::Audit(EV_PIN_RESET, AUDIT_MSG_PROC,
      userid != NULL ? userid : "",
      cuid != NULL ? cuid : "",
      msn != NULL ? msn : "",
      "success",
      "pin_reset",
      final_applet_version != NULL ? final_applet_version : "",
      keyVersion != NULL? keyVersion : "",
      "userid obtained");

/*isExternalReg still needs to check token owner, but do it differently - later */
    if (!isExternalReg) {
        PR_snprintf(configname, 256, "cn=%s", cuid);
        rc = RA::ra_find_tus_token_entries(configname, maxReturns, &ldapResult, 0);

        if (rc == 0) {
            for (e = RA::ra_get_first_entry(ldapResult); e != NULL;
              e = RA::ra_get_next_entry(e)) {
                tokenOwner = RA::ra_get_attribute_values(e, "tokenUserID");
                if (tokenOwner[0] != NULL && strlen(tokenOwner[0]) > 0 &&
                    strcmp(userid, tokenOwner[0]) != 0) {
                    status = STATUS_ERROR_NOT_TOKEN_OWNER;
                    PR_snprintf(audit_msg, 512, "token owner mismatch, status = STATUS_ERROR_NOT_TOKEN_OWNER");
                    goto loser;
                }
            }
        } else {
            RA::Error("RA_Pin_Reset_Processor::Process", "Error in ldap connection with token database.");
            status = STATUS_ERROR_LDAP_CONN;
            PR_snprintf(audit_msg, 512, "Error in ldap connection with token database, status = STATUS_ERROR_LDAP_CONN");
            goto loser;
        }
    }

    RA::Audit(EV_PIN_RESET, AUDIT_MSG_PROC,
      userid != NULL ? userid : "",
      cuid != NULL ? cuid : "",
      msn != NULL ? msn : "",
      "success",
      "pin_reset",
      final_applet_version != NULL ? final_applet_version : "",
      keyVersion != NULL? keyVersion : "",
      "authentication successful");


    RA::Debug(LL_PER_PDU, "RA_Pin_Reset_Processor::Process", 
          "SetupSecureChannel");

#if 0
    if (RA::GetConfigStore()->GetConfigAsBool("tus.enable", 0)) {
        if (IsTokenDisabledByTus(channel)) {
           status = STATUS_ERROR_TOKEN_DISABLED;
           goto loser;
        }
    }
#endif

/*isExternalReg should check in a different way*/
    /* check if the user owns the token */
if (!isExternalReg) {
    token_userid = RA::ra_get_token_userid(cuid);
    if (token_userid == NULL) {
        RA::Error(LL_PER_PDU, "RA_Pin_Reset_Processor::Process", 
          "No user owns the token '%s'", cuid);
        status = STATUS_ERROR_TOKEN_DISABLED;
        PR_snprintf(audit_msg, 512, "No user owns the token, status = STATUS_ERROR_TOKEN_DISABLED");
        goto loser;
    } else {
      if (strcmp(token_userid, userid) != 0) {
        RA::Error(LL_PER_PDU, "RA_Pin_Reset_Processor::Process", 
          "User does not own the token '%s'", cuid);
        status = STATUS_ERROR_TOKEN_DISABLED;
        PR_snprintf(audit_msg, 512, "User does not own the token. status = STATUS_ERROR_TOKEN_DISABLED");
        goto loser;
      }
    }
}

    RA::Audit(EV_PIN_RESET, AUDIT_MSG_PROC,
      userid != NULL ? userid : "",
      cuid != NULL ? cuid : "",
      msn != NULL ? msn : "",
      "success",
      "pin_reset",
      final_applet_version != NULL ? final_applet_version : "",
      keyVersion != NULL? keyVersion : "",
      "login successful");

    RA::Debug(LL_PER_PDU, "RA_Pin_Reset_Processor::Process", 
          "ExternalAuthenticate");
    rc = channel->ExternalAuthenticate();
    if (rc == -1) {
        RA::Error("RA_Pin_Reset_Processor::Process", 
			"External Authenticate failed.");
        status = STATUS_ERROR_CREATE_CARDMGR;
        RA::tdb_activity(session->GetRemoteIP(), cuid, "pin reset", "failure", "external authentication error", "", tokenType);
        PR_snprintf(audit_msg, 512, "External Authenticate failed, status = STATUS_ERROR_CREATE_CARDMGR");
        goto loser;
    }
    RA::Debug(LL_PER_PDU, "RA_Pin_Reset_Processor::Process", 
          "RequestNewPin");
    PR_snprintf((char *)configname, 256, "%s.%s.pinReset.pin.minLen", OP_PREFIX, tokenType);
    minlen = RA::GetConfigStore()->GetConfigAsUnsignedInt(configname, 4);
    PR_snprintf((char *)configname, 256, "%s.%s.pinReset.pin.maxLen", OP_PREFIX, tokenType);
    maxlen = RA::GetConfigStore()->GetConfigAsUnsignedInt(configname, 10);
    new_pin = RequestNewPin(session, minlen, maxlen);
    if (new_pin == NULL) {
        RA::Error("RA_Pin_Reset_Processor::Process", 
			"Set Pin failed.");
        status = STATUS_ERROR_MAC_RESET_PIN_PDU;
        RA::tdb_activity(session->GetRemoteIP(), cuid, "pin reset", "failure", "request new pin error", "", tokenType);
        PR_snprintf(audit_msg, 512, "RequestNewPin failed, status = STATUS_ERROR_MAC_RESET_PIN_PDU");
        goto loser;
    }

    if (extensions != NULL &&
           extensions->GetValue("statusUpdate") != NULL) {
           StatusUpdate(session, 70 /* progress */,
                        "PROGRESS_PIN_RESET");
    }

    rc = channel->ResetPin(0x0, new_pin);
    if (rc == -1) {
        status = STATUS_ERROR_MAC_RESET_PIN_PDU;
        RA::tdb_activity(session->GetRemoteIP(), cuid, "pin reset", "failure", "ereset pin error", "", tokenType);
        PR_snprintf(audit_msg, 512, "ResetPin failed, status = STATUS_ERROR_MAC_RESET_PIN_PDU");
        goto loser;
    }

    rc = channel->Close();
    if (rc == -1) {
        RA::Error("RA_Pin_Reset_Processor::Process", 
			"Failed to close channel");
        status = STATUS_ERROR_CONNECTION;
        RA::tdb_activity(session->GetRemoteIP(), cuid, "pin reset", "failure", "secure channel close error", "", tokenType);
        PR_snprintf(audit_msg, 512, "Failed to close channel, status = STATUS_ERROR_CONNECTION");
        goto loser;
    }

    
    //Update the KeyInfo in case of successful key changeover
    if (key_change_over_success != 0) {
        RA::tdb_update( userid  != NULL ? userid : (char *) "",
                         cuid != NULL ? cuid : (char *) "" ,
                         final_applet_version != NULL ? (char *) final_applet_version : (char *) "" ,
                          keyVersion != NULL ? keyVersion : (char *) "","active", "",
                          tokenType != NULL ? tokenType : (char *) "");
    }
    RA::Audit(EV_PIN_RESET, AUDIT_MSG_PROC,
      userid != NULL ? userid : "",
      cuid != NULL ? cuid : "",
      msn != NULL ? msn : "",
      "success",
      "pin_reset",
      final_applet_version != NULL ? final_applet_version : "",
      keyVersion != NULL? keyVersion : "",
      "ResetPin successful");

    if (extensions != NULL &&
           extensions->GetValue("statusUpdate") != NULL) {
           StatusUpdate(session, 100 /* progress */,
                        "PROGRESS_DONE");
    }

    end = PR_IntervalNow();

    rc = 1;
/*isExternalReg, preserve such policy?*/
    if (RA::ra_is_token_present(cuid)) {
	    /* 
	     * we want to have a tus policy to change PIN_RESET=YES 
	     * parameter to PIN_RESET=NO
	     */
      if (RA::ra_is_token_pin_resetable(cuid)) {
	policy = RA::ra_get_token_policy(cuid);
        RA::Error("RA_Pin_Reset_Processor::Process",
                        "Policy %s is %s", cuid, policy);
	tmp_policy = PL_strstr(policy, "PIN_RESET=YES");
	if (tmp_policy != NULL) {
	  tmp_policy[10] = 'N';
	  tmp_policy[11] = 'O';
	  for (i = 12; tmp_policy[i] != '\0'; i++)
	    tmp_policy[i] = tmp_policy[i+1];
	  rc = RA::ra_update_token_policy(cuid, policy);
          if (rc != 0) { 
              RA::Audit(EV_PIN_RESET, AUDIT_MSG_PROC,
                  userid != NULL ? userid : "",
                  cuid != NULL ? cuid : "",
                  msn != NULL ? msn : "",
                 "failure",
                 "pin_reset",
                 final_applet_version != NULL ? final_applet_version : "",
                 keyVersion != NULL? keyVersion : "",
                 "failed to reset token policy");
          }
	}
      }
    }

    sprintf(activity_msg, "applet_version=%s tokenType=%s",
           (char *)final_applet_version, tokenType);
    RA::tdb_activity(session->GetRemoteIP(), (char *)cuid, "pin reset", "success", activity_msg, userid, tokenType);

    /* audit log for successful pin reset */
    if (authid != NULL) {
        sprintf(activity_msg, "pin_reset processing completed, authid = %s", authid);
    } else {
        sprintf(activity_msg, "pin_reset processing completed");
    }
    RA::Audit(EV_PIN_RESET, AUDIT_MSG_PROC,
          userid, cuid, msn, "success", "pin_reset", final_applet_version, keyVersion!=NULL? keyVersion: "", activity_msg);

loser:
    if (strlen(audit_msg) > 0) {
            RA::Audit(EV_PIN_RESET, AUDIT_MSG_PROC,
               userid != NULL ? userid : "",
               cuid != NULL ? cuid : "",
               msn != NULL ? msn : "",
              "failure",
              "pin_reset",
              final_applet_version != NULL ? final_applet_version : "",
              keyVersion != NULL? keyVersion : "",
              audit_msg);
            
           if ((cuid != NULL) && (tokenType != NULL)) {
                RA::tdb_activity(session->GetRemoteIP(),
                    cuid,
                    "pin_reset",
                    "failure",
                    audit_msg,
                    userid != NULL ? userid : "",
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

    if( token_status != NULL ) {
        delete token_status;
        token_status = NULL;
    }
    if( CardManagerAID != NULL ) {
        delete CardManagerAID;
        CardManagerAID = NULL;
    }
    if( NetKeyAID != NULL ) { 
        delete NetKeyAID;
        NetKeyAID = NULL;
    }
    if( login != NULL ) {
        delete login;
        login = NULL;
    }
    if( new_pin != NULL ) {
        PL_strfree( new_pin );
        new_pin = NULL;
    }
    if( channel != NULL ) {
        delete channel;
        channel = NULL;
    }
    if( cuid != NULL ) {
        PR_Free( (char *) cuid );
        cuid = NULL;
    }
    if( msn != NULL ) {
        PR_Free( (char *) msn );
        msn = NULL;
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
    if( keyVersion != NULL ) {
        PR_Free( (char *) keyVersion );
        keyVersion = NULL;
    }
    if( userid != NULL ) {
        PR_Free( (char *) userid );
        userid = NULL;
    }
    if( authParams != NULL ) {
        delete authParams;
        authParams = NULL;
    }
    if( cplc_data != NULL ) {
        delete cplc_data;
        cplc_data = NULL;
    }

    if (tokenOwner != NULL) {
        ldap_value_free(tokenOwner);
        tokenOwner = NULL;
    }

    if (ldapResult != NULL) {
        ldap_msgfree(ldapResult);
        ldapResult = NULL;
    }

    if (appInfo != NULL) {
        free((AppletInfo *) appInfo);
        appInfo = NULL;
    }

#ifdef   MEM_PROFILING     
         MEM_dump_unfree();
#endif

    return status;
} /* Process */
