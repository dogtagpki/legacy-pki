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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "engine/RA.h"
#include "ldap.h"
#include "ldap_ssl.h"
#include "ldappr.h"
#include "authentication/LDAP_Authentication.h"
#include "authentication/Authentication.h"
#include "authentication/ExternalRegAttrs.h"
#include "main/Memory.h"
#include "main/Util.h"
#include "nuxwdog/WatchdogClient.h"

/* should be undefined before delivery */
#define ExternalRegPrototype

/**
 * Constructs a base processor.
 */
LDAP_Authentication::LDAP_Authentication ()
{
    m_hostport = NULL;
    m_baseDN = NULL;
    m_connInfo = NULL;
    m_attributes = NULL;
    m_ssl = NULL;
    m_bindDN = NULL;
    m_bindPwd = NULL;
    m_isPrototype = false;
    m_isExternalReg = false;
    m_isDelegate = false;
    m_attrName_tokenType = NULL;
    m_attrName_tokenCUID = NULL;
    m_attrName_certsToRecover = NULL;
    m_attrName_certsToDelete = NULL;
}

/**
 * Destructs processor.
 */
LDAP_Authentication::~LDAP_Authentication ()
{
    if( m_hostport != NULL ) {
        PL_strfree( m_hostport );
        m_hostport = NULL;
    }

    if( m_baseDN != NULL ) {
        PL_strfree( m_baseDN );
        m_baseDN = NULL;
    }

    if( m_connInfo != NULL ) {
        delete m_connInfo;
        m_connInfo = NULL;
    }

    if (m_attrName_tokenType != NULL) {
        PL_strfree(m_attrName_tokenType);
        m_attrName_tokenType = NULL;
    }

    if (m_attrName_tokenCUID != NULL) {
        PL_strfree(m_attrName_tokenCUID);
        m_attrName_tokenCUID = NULL;
    }

    if (m_attrName_certsToRecover != NULL) {
        PL_strfree(m_attrName_certsToRecover);
        m_attrName_certsToRecover = NULL;
    }

    if (m_attrName_certsToDelete != NULL) {
        PL_strfree(m_attrName_certsToDelete);
        m_attrName_certsToDelete = NULL;
    }
}

/*
 * Search for password name "name" in the password file "filepath"
 */
static char *get_pwd_from_conf(char *filepath, char *name)
{
    PRFileDesc *fd;
    char line[1024];
    int removed_return;
    char *val= NULL;
    char prompt[128];
    PRStatus status;
    char *wd_pipe = NULL;

    if (strlen(filepath) == 0) {
        return NULL;
    }
    fd= PR_Open(filepath, PR_RDONLY, 400);
    if (fd == NULL) {
        // password file is not readable.
        // if started by the watchdog, ask the watchdog instead.
        wd_pipe = PR_GetEnv("WD_PIPE_NAME");
        if ((wd_pipe != NULL) && (strlen(wd_pipe) > 0)) {
            status = call_WatchdogClient_init(); 
            if (status != PR_SUCCESS) {
                /* PR_fprintf(debug_fd, "get_pwd_from_conf unable to initialize connection to Watchdog"); */
                return NULL;
            }
            sprintf(line, "Please enter the password for %s:", name);
            val = call_WatchdogClient_getPassword(line, 0); 
            if (val == NULL) {
                /*PR_fprintf(debug_fd, "get_pwd_from_conf failed to get password from watchdog");*/
                return NULL;
            }
            return val;
        } else {
            // not started by watchdog. Even if this is pre-fork, getting the password 
            // directly from stdin is problematic here. 
            return NULL;
        }
    }

    while (1) {
        int n = Util::ReadLine(fd, line, 1024, &removed_return);
        if (n > 0) {
            /* handle comment line */
            if (line[0] == '#')
                continue;
            int c = 0;
            while ((c < n) && (line[c] != ':')) {
                c++;
            }
            if (c < n) {
                line[c] = '\0';
            } else {
                continue; /* no ':', skip this line */
            }
            if (!PL_strcmp (line, name)) {
                val =  PL_strdup(&line[c+1]);
                break;
            }
        } else if (n == 0 && removed_return == 1) {
            continue; /* skip empty line */
        } else {
            break;
        }
    }
    if( fd != NULL ) {
        PR_Close( fd );
        fd = NULL;
    }
    return val;

}

void LDAP_Authentication::Initialize(int instanceIndex) {
    char configname[256];
    const char *prefix="auth.instance";
    const char *FN = "LDAP_Authentication::Initialize";
    
    RA::Debug(FN, " begins");
    m_index = instanceIndex;
    PR_snprintf((char *)configname, 256, "%s.%d.hostport", prefix, instanceIndex);
    m_hostport = PL_strdup(RA::GetConfigStore()->GetConfigAsString(configname));
    PR_snprintf((char *)configname, 256, "%s.%d.SSLOn", prefix, instanceIndex);
    m_isSSL = RA::GetConfigStore()->GetConfigAsBool(configname, true);
    PR_snprintf((char *)configname, 256, "%s.%d.retries", prefix, instanceIndex);
    m_retries = RA::GetConfigStore()->GetConfigAsInt(configname, 1);
    PR_snprintf((char *)configname, 256, "%s.%d.retryConnect", prefix, instanceIndex);
    m_connectRetries = RA::GetConfigStore()->GetConfigAsInt(configname, 3);
    m_connInfo = new ConnectionInfo();
    m_connInfo->BuildFailoverList(m_hostport);
    PR_snprintf((char *)configname, 256, "%s.%d.baseDN", prefix, instanceIndex);
    m_baseDN = PL_strdup(RA::GetConfigStore()->GetConfigAsString(configname));
    PR_snprintf((char *)configname, 256, "%s.%d.attributes", prefix, instanceIndex);
    m_attributes = PL_strdup(RA::GetConfigStore()->GetConfigAsString(configname));

    /* support of SSL */
    PR_snprintf((char *)configname, 256, "%s.%d.ssl", prefix, instanceIndex);
    m_ssl = PL_strdup(RA::GetConfigStore()->GetConfigAsString(configname));
    PR_snprintf((char *)configname, 256, "%s.%d.bindDN", prefix, instanceIndex);
    m_bindDN = PL_strdup(RA::GetConfigStore()->GetConfigAsString(configname));
    PR_snprintf((char *)configname, 256, "%s.%d.bindPWD", prefix, instanceIndex);
    char *m_bindPwdPath = PL_strdup(RA::GetConfigStore()->GetConfigAsString(configname));
    m_bindPwd = get_pwd_from_conf(m_bindPwdPath, "tokendbBindPass");

    // support External Registration DB (externalReg)
    PR_snprintf((char *)configname, 256, "externalReg.prototype.enable");
    m_isPrototype = RA::GetConfigStore()->GetConfigAsBool(configname, false);

    PR_snprintf((char *)configname, 256, "externalReg.enable");
    m_isExternalReg = RA::GetConfigStore()->GetConfigAsBool(configname, 0);

    PR_snprintf((char *)configname, 256, "externalReg.delegation.enable");
    m_isDelegate = RA::GetConfigStore()->GetConfigAsBool(configname, 0);

    /*
     * e.g.
     *    auth.instance.2.externalReg.tokenTypeAttributeName=tokenType
     *    auth.instance.2.externalReg.cuidAttributeName=tokenCUID
     *    auth.instance.2.externalReg.certs.recoverAttributeName=certsToRecover
     *    auth.instance.2.externalReg.certs.deleteAttributeName=certsToDelete
     */
    if (!m_isPrototype && m_isExternalReg) {
        RA::Debug(FN, " isExternalReg init begins");
        // init the LDAP attribute names for externalReg
        PR_snprintf((char *)configname, 256, "%s.%d.externalReg.tokenTypeAttributeName", prefix, instanceIndex);
        m_attrName_tokenType = PL_strdup(RA::GetConfigStore()->GetConfigAsString(configname, "tokenType"));
        RA::Debug(FN, "m_attrName_tokenType =%s", m_attrName_tokenType);

        PR_snprintf((char *)configname, 256, "%s.%d.externalReg.cuidAttributeName", prefix, instanceIndex);
        m_attrName_tokenCUID = PL_strdup(RA::GetConfigStore()->GetConfigAsString(configname, "tokenCUID"));
        RA::Debug(FN, "m_attrName_tokenCUID =%s", m_attrName_tokenCUID);

        PR_snprintf((char *)configname, 256, "%s.%d.externalReg.certs.recoverAttributeName", prefix, instanceIndex);
        m_attrName_certsToRecover = PL_strdup(RA::GetConfigStore()->GetConfigAsString(configname, "certsToRecover"));
        RA::Debug(FN, "m_attrName_certsToRecover =%s", m_attrName_certsToRecover);

        PR_snprintf((char *)configname, 256, "%s.%d.externalReg.certs.deleteAttributeName", prefix, instanceIndex);
        m_attrName_certsToDelete = PL_strdup(RA::GetConfigStore()->GetConfigAsString(configname, "certsToDelete"));
        RA::Debug(FN, "m_attrName_certsToDelete =%s", m_attrName_certsToDelete);

        RA::Debug(FN, " isExternalReg init ends");
    }
    RA::Debug(FN, " ends");
}

/**
 * @return (0:login correct) (-1:LDAP error)  (-2:User not found) (-3:Password error)
 */

#define TPS_AUTH_OK                       0
#define TPS_AUTH_ERROR_LDAP              -1
#define TPS_AUTH_ERROR_USERNOTFOUND      -2
#define TPS_AUTH_ERROR_PASSWORDINCORRECT -3

int LDAP_Authentication::Authenticate(AuthParams *params)
{
    return Authenticate(params, NULL);
}

/*
 * ProcessExternalRegAttrs : 
 *   - retrieve relevant attributes for externalReg
 *   - parse the multi-valued attributes
 * @param name name of the attribute to be processed
 * @param value value of the attribute to be processed
 * @param params ldap attributes retrieved from ldap authenticate
 * @param session session container that will carry needed vals through session
 */
void LDAP_Authentication::ProcessExternalRegAttrs(char *name, char **value,
    AuthParams *params,
    RA_Session *session)
{
    const char *FN = "LDAP_Authentication::ProcessExternalRegAttrs";
    ExternalRegAttrs *erAttrs = NULL;

    RA::Debug(FN, "processing attr name %s", name);
    if (session != NULL) {
        erAttrs = session->getExternalRegAttrs();
    }

    if ((m_attrName_tokenType != NULL) &&
          (PL_strcmp(m_attrName_tokenType, name) == 0)) {
        char *tokenType = value[0];
        if (tokenType != NULL) {
            RA::Debug(FN,
                "got externalReg attr: %s=%s", m_attrName_tokenType, tokenType);
            if (erAttrs != NULL)
                erAttrs->setTokenType(tokenType);
        } else {
            RA::Debug(FN,
                "did not get externalReg attr: %s", m_attrName_tokenType);
        }
    } else if ((m_attrName_tokenCUID != NULL) &&
          (PL_strcmp(m_attrName_tokenCUID, name)== 0)) {
        char *tokenCUID = value[0];
        if (tokenCUID != NULL) {
            RA::Debug(FN,
                "got externalReg attr: %s=%s", m_attrName_tokenCUID, tokenCUID);
            if (erAttrs != NULL)
                erAttrs->setTokenCUID(tokenCUID);
        }
    } else if ((m_attrName_certsToRecover != NULL)  &&
          (PL_strcmp(m_attrName_certsToRecover, name)==0)) {
        /*
         * certs to be recovered for this user
         *     - multi-valued
         */
        int i = 0;
        while (value[i] != NULL) {
            /*
             * Each cert is represented as 
             *    (serial#, caID, keyID, drmID)
             * e.g.
             *    (1234, ca1, 81, drm1)
             *    note: numbers above are in decimal
             */
            RA::Debug(FN,
                "Exposed externalReg: %s=%s", m_attrName_certsToRecover, value[i]);
            ExternalRegCertToRecover *erCertToRecover =
                new ExternalRegCertToRecover();
            char *tok = NULL; 
            char *dup_v = strdup(value[i]);
            tok = strtok(dup_v, ","); 
            if (tok != NULL)
                erCertToRecover->setSerial((PRUint64)strtoull(tok,
                    NULL, 10));
            else
                goto next;
            tok = strtok( NULL, "," ); 
            if (tok != NULL)
                erCertToRecover->setCaConn(PL_strdup(tok));
            else
                goto next;
            tok = strtok( NULL, "," ); 
            if (tok != NULL)
                erCertToRecover->setKeyid((PRUint64)strtoull(tok,
                    NULL, 10));
            else
                goto next;
            tok = strtok( NULL, "," ); 
            if (tok != NULL)
                erCertToRecover->setDrmConn(PL_strdup(tok));

          next:
            if (erAttrs != NULL) {
                erAttrs->addCertToRecover(erCertToRecover); 
            }

            if (dup_v != NULL) {
                PR_Free(dup_v);
                dup_v = NULL;
            }
            i++;
        }
        RA::Debug(FN,
            "certsToRecover end count =%d", erAttrs->getCertsToRecoverCount());
    } else if ((m_attrName_certsToDelete != NULL)  &&
          (PL_strcmp(m_attrName_certsToDelete, name)==0)) {
        /*
         * certs to be deleted for this user
         *     - multi-valued
         */
        int i = 0;
        while (value[i] != NULL) {
            /*
             * Each cert is represented as 
             *    (serial#, caID, revokeOnDelete)
             * e.g.
             *    (234, ca1, true)
             *    note: number above is in decimal
             */
            RA::Debug(FN,
                "Exposed externalReg: %s=%s", m_attrName_certsToDelete, value[i]);
            ExternalRegCertToDelete *erCertToDelete =
                new ExternalRegCertToDelete();
            char *tok = NULL; 
            char *dup_v = strdup(value[i]);
            tok = strtok(dup_v, ","); 
            erCertToDelete->setSerial((PRUint64)strtoull(tok,
                    NULL, 10));
            tok = strtok( NULL, "," ); 
            erCertToDelete->setCaConn(PL_strdup(tok));
            tok = strtok( NULL, "," ); 
            erCertToDelete->setRevoke((PL_strcmp(tok, "true")==0)? true:false);
            if (erAttrs != NULL) {
                erAttrs->addCertToDelete(erCertToDelete); 
            }

            if (dup_v != NULL) {
                PR_Free(dup_v);
                dup_v = NULL;
            }
            i++;
        }
        RA::Debug(FN,
            "certsToDelete end count =%d", erAttrs->getCertsToDeleteCount());
    } else {
        RA::Debug(FN, "Exposed %s=%s", name, value[0]);
        params->Add(name, PL_strdup(value[0]));
        RA::Debug(FN, "Size %d", params->Size());
    }
    RA::Debug(FN, "processing for attr %s done", name);
}

/*
 * LDAP_Authentication::Authenticate
 *  params - ldap attributes retrieved from ldap authenticate
 *   session - NULL if !isExternalReg
 *           - otherwise isExternalReg, and it's ldap attributes retrieved
 *             and filled in session->extRegAttrs
 */
int LDAP_Authentication::Authenticate(AuthParams *params, RA_Session *session)
{
    char buffer[500];
    char *host = NULL;
    char *portStr = NULL;
    int port = 0;
    LDAP *ld = NULL;
    int status = TPS_AUTH_ERROR_LDAP;
    int version = LDAP_VERSION3;
    LDAPMessage *result = NULL, *e = NULL;
    char *dn = NULL;
    char *uid = NULL;
    char *password = NULL;
    int retries = 0;
    char configname[256];

    if (params == NULL) {
        status = TPS_AUTH_ERROR_USERNOTFOUND;
        goto loser;
    }

    uid = params->GetUID();
    password = params->GetPassword();

    GetHostPort(&host, &portStr);
    port = atoi(portStr); 

    if (m_ssl != NULL & strcmp(m_ssl, "true")==0) {
      /* handling of SSL */
      ld = ldapssl_init(host, port, 1); 
    } else {
      /* NOTE:  ldapssl_init() already utilizes */
      /*        prldap (IPv6) functionality.    */
      ld = prldap_init(host, port, 1); 
    }
    while (ld == NULL && retries < m_connectRetries) {
        RA::IncrementAuthCurrentIndex(m_connInfo->GetHostPortListLen());
        GetHostPort(&host, &portStr);
        port = atoi(portStr);
        if (m_ssl != NULL & strcmp(m_ssl, "true")==0) {
          /* handling of SSL */
          ld = ldapssl_init(host, port, 1); 
        } else {
          /* NOTE:  ldapssl_init() already utilizes */
          /*        prldap (IPv6) functionality.    */
          ld = prldap_init(host, port, 1); 
        }
            retries++;    
    }

    if (ld == NULL) {
        status = TPS_AUTH_ERROR_LDAP;
        goto loser;
    }

    PR_snprintf((char *)buffer, 500, "(uid=%s)", uid);

    if (m_isExternalReg && (session!= NULL) && (session->getExternalRegAttrs() == NULL)) {
        ExternalRegAttrs *erAttrs = new ExternalRegAttrs();
        session->setExternalRegAttrs(erAttrs);
    }

    while (retries < m_connectRetries) {
        RA::IncrementAuthCurrentIndex(m_connInfo->GetHostPortListLen());
        GetHostPort(&host, &portStr);
        port = atoi(portStr);
        RA::Debug("ldap auth:"," host=%s, portstr=%s, port=%d", host, portStr, port);
        if (m_ssl != NULL & strcmp(m_ssl, "true")==0) {
          /* handling of SSL */
          ld = ldapssl_init(host, port, 1); 
        } else {
          /* NOTE:  ldapssl_init() already utilizes */
          /*        prldap (IPv6) functionality.    */
          ld = prldap_init(host, port, 1); 
        }

        if (ld == NULL) {
            RA::Debug("LDAP_Authentication::Authenticate:", "ld null.  Trying failover...");
            retries++;
            continue;
        }

        if (ldap_set_option (ld, LDAP_OPT_PROTOCOL_VERSION, &version) != LDAP_SUCCESS) {
            status = TPS_AUTH_ERROR_LDAP;
            goto loser;
        }

        if (m_bindDN != NULL && strlen(m_bindDN) > 0) {
            RA::Debug("LDAP_Authentication::Authenticate", "Simple bind required '%s'", m_bindDN);
            ldap_simple_bind_s(ld, m_bindDN, m_bindPwd);
        }

        int ldap_status = LDAP_OTHER;
        if ((ldap_status = ldap_search_s(ld, m_baseDN, LDAP_SCOPE_SUBTREE, buffer, NULL, 0, &result)) != LDAP_SUCCESS) {
            if (ldap_status != LDAP_NO_SUCH_OBJECT) {
              RA::Debug("LDAP_Authentication::Authenticate:", "LDAP_UNAVAILABLE.  Trying failover...");
              retries++;
              continue; // do failover
            }
            status = TPS_AUTH_ERROR_USERNOTFOUND;
        } else {
            for (e = ldap_first_entry(ld, result); e != NULL; e = ldap_next_entry(ld, e)) {
                if ((dn = ldap_get_dn(ld, e)) != NULL) {
                    RA::Debug("LDAP_Authentication::Authenticate", "User bind required '%s' '(sensitive)'", dn );
                    if (ldap_simple_bind_s(ld, dn, password) == LDAP_SUCCESS) {
                        /* retrieve attributes and, */
                        /* put them into the auth parameters */
                        if (m_attributes != NULL) { 
                             RA::Debug("LDAP_Authentication::Authenticate", "Attributes %s", m_attributes);
                             char *m_dup_attributes = strdup(m_attributes);
                             char *token = NULL; 
                             char *lasts = NULL;
                             token = PL_strtok_r(m_dup_attributes, ",", &lasts); 
                             while( token != NULL ) {
                                 char **v = NULL;
                                 RA::Debug("LDAP_Authentication::Authenticate",
                                     "about to search for attr %s", token);
                                 v = ldap_get_values(ld, e, token);
                                 if (v != NULL) {
                                     RA::Debug("LDAP_Authentication::Authenticate", "found value for attr=%s",token);
                                     if (!m_isPrototype && m_isExternalReg) {
                                         ProcessExternalRegAttrs(token, v, params, session);
                                     } else {
                                         RA::Debug("LDAP_Authentication::Authenticate", "Exposed %s=%s", token, v[0]);
                                         params->Add(token, PL_strdup(v[0]));
                                         RA::Debug("LDAP_Authentication::Authenticate", "Size %d", params->Size());
                                     }
                                 } else {
                                     RA::Debug("LDAP_Authentication::Authenticate", "not found value for attr=%s",token);
                                 }
                                 token = PL_strtok_r( NULL, ",", &lasts ); 
                                 if (token == NULL)
                                     RA::Debug("LDAP_Authentication::Authenticate", "no more token");
                                 if( v != NULL ) {
                                     ldap_value_free( v );
                                     v = NULL;
                                 }

                             }
						     free(m_dup_attributes);
                        }

                        status = TPS_AUTH_OK;   // SUCCESS - PASSWORD VERIFIED
			    	} else {
                        status = TPS_AUTH_ERROR_PASSWORDINCORRECT;
                        goto loser;
                    } 
                } else {
                    status = TPS_AUTH_ERROR_USERNOTFOUND;
                    goto loser;
                } 
            }
#ifdef ExternalRegPrototype
            if ((m_isPrototype) && (m_isExternalReg) && (session != NULL)) {
                ExternalRegAttrs *erAttrs = NULL;
                if (session != NULL)
                    erAttrs = new ExternalRegAttrs();

                RA::Debug("LDAP_Authentication::Authenticate:", " ExternalRegPrototype begins");
                /*
                 * For Prototype/Demo only,
                 * in CS.cfg (instead of getting from ldap) e.g.
                 *
                 * externalReg.prototype.tokenType=delegateISEtoken
                 * externalReg.prototype.recoverNum=2
                 * externalReg.prototype.recover0.serial=6
                 * externalReg.prototype.recover0.keyid=3
                 * externalReg.prototype.recover0.caConn=ca1
                 * externalReg.prototype.recover0.drmConn=drm1
                 * externalReg.prototype.recover1.serial=8
                 * externalReg.prototype.recover1.keyid=4
                 * externalReg.prototype.recover1.caConn=ca1
                 * externalReg.prototype.recover1.drmConn=drm1
                 * externalReg.prototype.deleteNum=2
                 * externalReg.prototype.delete0.serial=10
                 * externalReg.prototype.delete0.caConn=ca1
                 * externalReg.prototype.delete0.revoke=false
                 * externalReg.prototype.delete1.serial=12
                 * externalReg.prototype.delete1.caConn=ca1
                 * externalReg.prototype.delete1.revoke=true
                 */
                char proto_recover_prefix[256] = "externalReg.prototype.recover";
                PR_snprintf((char *)configname, 256, "%sNum", proto_recover_prefix);
                int protoNum = RA::GetConfigStore()->GetConfigAsInt(configname);
                for (int i=0; i<protoNum; i++) {
                    ExternalRegCertToRecover *erCertToRecover = new ExternalRegCertToRecover();
                    PR_snprintf((char *)configname, 256, "%s%d.keyid", proto_recover_prefix,i);
                    PRUint64 keyid = RA::GetConfigStore()->GetConfigAsInt(configname);
                    erCertToRecover->setKeyid(keyid);
                    PR_snprintf((char *)configname, 256, "%s%d.serial", proto_recover_prefix,i);
                    PRUint64 serial = RA::GetConfigStore()->GetConfigAsInt(configname);
                    erCertToRecover->setSerial(serial);
                    PR_snprintf((char *)configname, 256, "%s%d.caConn", proto_recover_prefix,i);
                    erCertToRecover->setCaConn(RA::GetConfigStore()->GetConfigAsString(configname));
                    PR_snprintf((char *)configname, 256, "%s%d.drmConn", proto_recover_prefix,i);
                    erCertToRecover->setDrmConn(RA::GetConfigStore()->GetConfigAsString(configname));
                    erAttrs->addCertToRecover(erCertToRecover); 
                }

                char proto_delete_prefix[256] = "externalReg.prototype.delete";
                PR_snprintf((char *)configname, 256, "%sNum", proto_delete_prefix);
                protoNum = RA::GetConfigStore()->GetConfigAsInt(configname);
                for (int i=0; i<protoNum; i++) {
                    ExternalRegCertToDelete *erCertToDelete =
                        new ExternalRegCertToDelete();
                    PR_snprintf((char *)configname, 256, "%s%d.serial", proto_delete_prefix,i);
                    PRUint64 serial = RA::GetConfigStore()->GetConfigAsInt(configname);
                    erCertToDelete->setSerial(serial);
                    PR_snprintf((char *)configname, 256, "%s%d.caConn", proto_delete_prefix,i);
                    erCertToDelete->setCaConn(RA::GetConfigStore()->GetConfigAsString(configname));
                    PR_snprintf((char *)configname, 256, "%s%d.revoke", proto_delete_prefix,i);
                    erCertToDelete->setRevoke(RA::GetConfigStore()->GetConfigAsBool(configname, 0));
                    erAttrs->addCertToDelete(erCertToDelete);
                }
                PR_snprintf((char *)configname, 256, "externalReg.prototype.tokenType");
                erAttrs->setTokenType(RA::GetConfigStore()->GetConfigAsString(configname));
                session->setExternalRegAttrs(erAttrs);
                PR_snprintf((char *)configname, 256, "externalReg.prototype.cuid");
                erAttrs->setTokenCUID(RA::GetConfigStore()->GetConfigAsString(configname));
                RA::Debug("LDAP_Authentication::Authenticate:", " ExternalRegPrototype ends");
               /*
                * isDelegate
                */
                if (m_isDelegate) {
                    params->Add("lastname", "Doe");
                    params->Add("firstname", "Jane");
                    params->Add("edipi", "0123456789");
                    params->Add("pcc", "BB");
                    params->Add("mail", "jdoe@redhat.com");
                    params->Add("exec-edipi", "9123456789");
                    params->Add("exec-pcc", "AA");
                    params->Add("exec-mail", "exec@redhat.com");
                }
            }
#endif /*ExternalRegPrototype*/
            RA::Debug("LDAP_Authentication::Authenticate:", " authentication completed for %s",uid);
            break;
        }
    } //while
    
    if (dn == NULL) {
        status = TPS_AUTH_ERROR_USERNOTFOUND;
        goto loser;
    }

loser:
    RA::Debug("LDAP_Authentication::Authenticate:", "status =%d", status);

    if (result != NULL) {
      ldap_msgfree(result);
    }

    if (dn != NULL) {
      ldap_memfree(dn);
    }

    if (ld != NULL) {
        ldap_unbind(ld);
        ld = NULL;
    } 

    return status;
}

void LDAP_Authentication::GetHostPort(char **p, char **q) {
    int num=0;
    int auth_curr = RA::GetAuthCurrentIndex();
    char *hp = (m_connInfo->GetHostPortList())[auth_curr];
    char *host_port = PL_strdup(hp);

    char *lasts = NULL;
    char *tok = PL_strtok_r((char *)host_port, ":", &lasts);
    while (tok != NULL) {
        if (num == 0)
            *p = PL_strdup(tok);
        else
            *q = PL_strdup(tok);
        tok = PL_strtok_r(NULL, ":", &lasts);
        num++;
    } 

    PR_Free(host_port);
} 

bool LDAP_Authentication::IsSSL() {
    return m_isSSL;
}

char *LDAP_Authentication::GetHostPort() {
    return m_hostport;
}

Authentication *GetAuthentication() {
    LDAP_Authentication *auth = new LDAP_Authentication();    
    return (Authentication *)auth;
}

const char *LDAP_Authentication::GetTitle(char *locale)
{
    char configname[256];
    const char *prefix="auth.instance";
    PR_snprintf((char *)configname, 256, "%s.%d.ui.title.%s", 
        prefix, m_index, locale);
RA::Debug("LDAP_Authentication::GetTitle", "%s", configname);
    return RA::GetConfigStore()->GetConfigAsString(configname);
}

const char *LDAP_Authentication::GetDescription(char *locale)
{
    char configname[256];
    const char *prefix="auth.instance";
    PR_snprintf((char *)configname, 256, "%s.%d.ui.description.%s", 
        prefix, m_index, locale);
RA::Debug("LDAP_Authentication::GetDescription", "%s", configname);
RA::Debug("LDAP_Authentication::GetDescription", "%s", RA::GetConfigStore()->GetConfigAsString(configname));
    return RA::GetConfigStore()->GetConfigAsString(configname);
}

int LDAP_Authentication::GetNumOfParamNames()
{
    return 2;
}
                                                                                
char *LDAP_Authentication::GetParamID(int index)
{
    if (index == 0) 
        return ( char * ) "UID";
    else if (index == 1)
        return ( char * ) "PASSWORD";
    else
        return NULL;
}

const char *LDAP_Authentication::GetParamName(int index, char *locale)
{
    char configname[256];
    const char *prefix="auth.instance";
    PR_snprintf((char *)configname, 256, "%s.%d.ui.id.%s.name.%s", 
        prefix, m_index, GetParamID(index), locale);

RA::Debug("LDAP_Authentication::GetParamName", "%s", configname);

    return RA::GetConfigStore()->GetConfigAsString(configname);
}
                                                                                
char *LDAP_Authentication::GetParamType(int index)
{
    if (index == 0) 
        return ( char * ) "string";
    else if (index == 1)
        return ( char * ) "password";
    else
        return NULL;
}
                                                                                
const char *LDAP_Authentication::GetParamDescription(int index, char *locale)
{
    char configname[256];
    const char *prefix="auth.instance";
    PR_snprintf((char *)configname, 256, "%s.%d.ui.id.%s.description.%s", 
        prefix, m_index, GetParamID(index), locale);
    return RA::GetConfigStore()->GetConfigAsString(configname);
}
                                                                                
char *LDAP_Authentication::GetParamOption(int index)
{
    return ( char * ) "";
}

