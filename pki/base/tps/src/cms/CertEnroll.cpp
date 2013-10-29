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

#include <string.h>

#include "main/RA_Session.h"
#include "main/RA_Msg.h"
#include "main/Buffer.h"
#include "main/Util.h"
#include "engine/RA.h"
#include "cms/HttpConnection.h"
#include "cms/CertEnroll.h"

// for public key processing
#include "pk11func.h"
#include "cryptohi.h"
#include "keyhi.h"
#include "cert.h"
#include "base64.h"
#include "nssb64.h"
#include "prlock.h"

#include "main/Memory.h"

Buffer * parseResponse(char * /*response*/);
ReturnStatus verifyProof(SECKEYPublicKey* , SECItem* ,
             unsigned short , unsigned char* ,
             unsigned char* );

#ifdef XP_WIN32
#define TOKENDB_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TOKENDB_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs handle for Certificate Enrollment
 */
TOKENDB_PUBLIC CertEnroll::CertEnroll()
{
}

/**
 * Destructs handle for Certificate Enrollment
 */
TOKENDB_PUBLIC CertEnroll::~CertEnroll()
{
}

/**
 * Revokes a certificate in the CA
 * reason:
 *   0 = Unspecified
 *   1 = Key compromised
 *   2 = CA key compromised
 *   3 = Affiliation changed
 *   4 = Certificate superseded
 *   5 = Cessation of operation
 *   6 = Certificate is on hold
 * serialno: serial number in decimal
 */
TOKENDB_PUBLIC int CertEnroll::RevokeCertificate(const char *reason, const char *serialno, const char *connid, char *&o_status)
{
    char parameters[5000];
    char configname[5000];
    int num=0;

    PR_snprintf((char *)parameters, 5000, "op=revoke&revocationReason=%s&revokeAll=(certRecordId%%3D%s)&totalRecordCount=1", reason, serialno);

    PR_snprintf((char *)configname, 256, "conn.%s.servlet.revoke", connid);
    char *servletID = (char*)RA::GetConfigStore()->GetConfigAsString(configname);

    PSHttpResponse *resp =  sendReqToCA(servletID, parameters, connid);

    if (resp != NULL) {
        char *content = resp->getContent();
        char *p = strstr(content, "status=");
        num = *(p+7) - '0';
        RA::Debug("CertEnroll::RevokeCertificate", "serialno=%s reason=%s connid=%s status=%d", serialno, reason, connid, num);
        if (num != 0) {
            char *q = strstr(p, "error=");
            q = q+6;
            o_status = PL_strdup(q);
            RA::Debug("CertEnroll::RevokeCertificate", "status string=%s", q);
        }
        if (content != NULL) {
            resp->freeContent();
            content = NULL;
        }    
        delete resp;
        resp = NULL;
    } else {
        RA::Debug("CertEnroll::RevokeCertificate", "serialno=%s reason=%s connid=%s failed: resp is NULL");
        o_status = PL_strdup("resp from sendReqToCA is NULL");
        num = 1;  //non-zero
    }
    return num;
}


TOKENDB_PUBLIC int CertEnroll::UnrevokeCertificate(const char *serialno, const char *connid,
  char *&o_status)
{
    char parameters[5000];
    char configname[5000];
    int num=0;

    PR_snprintf((char *)parameters, 5000, "serialNumber=%s",serialno);

    PR_snprintf((char *)configname, 256, "conn.%s.servlet.unrevoke", connid);
    char *servletID = (char*)RA::GetConfigStore()->GetConfigAsString(configname);

    PSHttpResponse *resp =  sendReqToCA(servletID, parameters, connid);
    if (resp != NULL) {
        // XXX - need to parse response
        char *content = resp->getContent();
        char *p = strstr(content, "status=");
        num = *(p+7) - '0';
        RA::Debug("CertEnroll::UnrevokeCertificate", "status=%d", num);
        
        if (num != 0) {
            char *q = strstr(p, "error=");
            q = q+6;
            o_status = PL_strdup(q);
            RA::Debug("CertEnroll::UnrevokeCertificate", "status string=%s", q);
        }

        if (content != NULL) {
            resp->freeContent();
            content = NULL;
        }    
        delete resp;
        resp = NULL;
    }  else {
        RA::Debug("CertEnroll::UnrevokeCertificate", "serialno=%s reason=%s connid=%s failed: resp is NULL");
        o_status = PL_strdup("resp from sendReqToCA is NULL");
        num = 1;  //non-zero
    }

    return num;
}


/*
 * searches through all defined ca entries to find the cert's
 * signing ca for revocation
 *   revoke: true to revoke; false to unrevoke  
 *   cert: cert to (un)revoke
 *   serialno: parameter for the (Un)RevokeCertificate() functions
 *   o_status: parameter for the (Un)RevokeCertificate() functions
 *   reason: parameter for the RevocakeCertificate() function
 */
TPS_PUBLIC int CertEnroll::revokeFromOtherCA(
        bool revoke,
        CERTCertificate *cert,
        const char*serialno, char *&o_status,
        const char *reason) {

    int ret = 1;
    const char *caList = NULL;
    const char *nick = NULL;
    char configname[256] = {0};
    char configname_nick[256] = {0};
    char configname_caSKI[256] = {0};
    const char *caSKI_s = NULL;
    char *caSKI_x = NULL;
    char *caSKI_y = NULL;
    ConfigStore *store = RA::GetConfigStore();
    CERTCertDBHandle *certdb = CERT_GetDefaultCertDB();
    CERTCertificate *caCert = NULL;
    SECItem ca_ski;
    SECStatus rv = SECFailure;

    if (store == NULL)
        return 1;

    PR_ASSERT(certdb != NULL);
    RA::Debug(LL_PER_SERVER, "CertEnroll::revokeFromOtherCA: %s",
        revoke? "revoking":"unrevoking");
    PR_snprintf((char *)configname, 256, "conn.ca.list");
    caList = store->GetConfigAsString(configname, NULL);
    if (caList == NULL) {
        RA::Debug(LL_PER_SERVER, "CertEnroll::revokeFromOtherCA",
            "conn.ca.list not found");
        return 1;
    }

    char *caList_x = PL_strdup(caList);
    PR_ASSERT(caList_x != NULL);
    RA::Debug(LL_PER_SERVER, "CertEnroll::revokeFromOtherCA",
        "found ca list:%s", caList_x);
    char *sresult = NULL;
    char *lasts = NULL;

    sresult = PL_strtok_r(caList_x, ",", &lasts);

    while (sresult != NULL) {
        ret = 1;
        /* first, see if ca Subject Key Identifier (SKI) is in store */
        bool foundCaSKI = false;
        PRBool match = PR_FALSE;
        PR_snprintf((char *)configname_caSKI, 256, "conn.%s.caSKI",
            sresult);
        caSKI_s = store->GetConfigAsString(configname_caSKI, NULL);
        if ((caSKI_s == NULL) || *caSKI_s==0) {
            RA::Debug(LL_PER_SERVER, "CertEnroll::revokeFromOtherCA",
                "CA cert SKI not found in config for ca: %s", sresult);
        } else {
            caSKI_x = PL_strdup(caSKI_s);
            PR_ASSERT(caSKI_x != NULL);
            RA::Debug(LL_PER_SERVER, "CertEnroll::revokeFromOtherCA",
                "CA cert SKI found in config for: %s", sresult);
            foundCaSKI = true;
            /* convert from ASCII to SECItem */
            rv = ATOB_ConvertAsciiToItem(&ca_ski, caSKI_x);
            if (rv != SECSuccess) {
                RA::Debug(LL_PER_SERVER, "CertEnroll::revokeFromOtherCA",
                    "CA cert SKI failed ATOB_ConvertAsciiToItem() call");
                /* this will correct the ca SKI if caNickname is in store */
                foundCaSKI = false;
            }
        }

        if (!foundCaSKI) { /* get from cert db */
            PR_snprintf((char *)configname_nick, 256, "conn.%s.caNickname",
                sresult);
            nick = store->GetConfigAsString(configname_nick, NULL);
            if ((nick == NULL) || *nick==0) {
                RA::Debug(LL_PER_SERVER, "CertEnroll::revokeFromOtherCA",
                    "CA cert nickname not found for ca: %s", sresult);
                goto cleanup;
            }

            RA::Debug(LL_PER_SERVER, "CertEnroll::revokeFromOtherCA",
                "CA cert check for nickname: %s", nick);
            caCert = CERT_FindCertByNickname(certdb, nick);
            if (caCert == NULL) {
                RA::Debug(LL_PER_SERVER, "CertEnroll::revokeFromOtherCA",
                    "CA cert for nickname %s not found in trust database", nick);
                /* out of luck with this ca... next */
                goto cleanup;
            }
            ca_ski = caCert->subjectKeyID;

            /* store it in config */
            caSKI_y = BTOA_ConvertItemToAscii(&ca_ski);
            if (caSKI_y == NULL) {
                goto cleanup;
            }
            store->Add(configname_caSKI, caSKI_y);
            RA::Debug(LL_PER_SERVER, "CertEnroll::revokeFromOtherCA",
                "Commiting ca AKI Add for %s", sresult);
            char error_msg[512] = {0};
            int status = 0;
            status = store->Commit(true, error_msg, 512);
            if (status != 0) {
                /* commit error.. log it and keep going */
                RA::Debug(LL_PER_SERVER, "CertEnroll::RevokeCertificate",
                "Commit error for ca AKI Add : %s", error_msg);
            }
        }

        match = SECITEM_ItemsAreEqual(
            &cert->authKeyID->keyID, &ca_ski);
        if (!match) {
            RA::Debug("CertEnroll::revokeFromOtherCA", "cert AKI and caCert SKI do not match");
            goto cleanup;
        } else {
            RA::Debug("CertEnroll::revokeFromOtherCA", "cert AKI and caCert SKI matched");
            if (revoke) {
                ret = RevokeCertificate(
                    reason, serialno, sresult /*connid*/, o_status);
            } else { /*unrevoke*/
                ret = UnrevokeCertificate(
                    serialno, sresult /*connid*/, o_status);
            }
        }

cleanup:
        if (caSKI_x != NULL) {
            PL_strfree(caSKI_x);
            caSKI_x = NULL;
        }
        if (caSKI_y != NULL) {
            PORT_Free(caSKI_y);
            caSKI_y = NULL;
        }
        if (caCert != NULL) {
            CERT_DestroyCertificate(caCert);
            caCert = NULL;
        }
        if (ret == 0) /* success, break out */
            break;

        sresult = PL_strtok_r(NULL, ",", &lasts);
    } /* while */

    if (caList_x != NULL) {
        PL_strfree(caList_x);
    }
    return ret;
}


/*
 * revoke/unrevoke a certificate
 *    revoke: true to revoke; false to unrevoke  
 *    cert: the certificate to revoke or unrevoke
 *    reason: only applies if revoke is true; reason for revocation
 *    serialno: the serial number of cert to revoke or unrevoke
 *    connid: the enrollment CA connection. In (un)revocation it is first tested
 *        to see if it matches the cert's issuing CA signing cert; if not
 *        other ca's are searched, if available
 *    o_status: the return status
 */
TOKENDB_PUBLIC int CertEnroll::RevokeCertificate(bool revoke, CERTCertificate *cert, const char *reason, const char *serialno, const char *connid, char *&o_status)
{
    int ret = 1;
    char configname[5000] = {0};
    CERTCertDBHandle *certdb = CERT_GetDefaultCertDB();
    CERTCertificate *caCert = NULL;
    const char *caNickname = NULL;
    char configname_caSKI[256] = {0};
    const char *caSKI_s = NULL;
    char *caSKI_x = NULL;
    char *caSKI_y = NULL;
    SECItem ca_ski;
    SECStatus rv;
    ConfigStore *store = RA::GetConfigStore();

    if (store == NULL)
        return 1;
    PR_ASSERT(certdb != NULL);
    if ((cert == NULL) || (reason == NULL) ||
        (serialno == NULL) || (connid == NULL)) {
        RA::Debug("CertEnroll::RevokeCertificate", "missing info in call");
        return 1;
    }
    if (revoke) {
        RA::Debug("CertEnroll::RevokeCertificate", "revoke begins");
        if (reason == NULL) {
            RA::Debug("CertEnroll::RevokeCertificate", "missing reason in call to revoke");
            return 1;
            
        }
    } else {
        RA::Debug("CertEnroll::RevokeCertificate", "unrevoke begins");
    }

    /* first, see if ca Subject Key Identifier (SKI) is in store*/
    bool foundCaSKI = false;
    PR_snprintf((char *)configname_caSKI, 256, "conn.%s.caSKI",
        connid);
    caSKI_s = store->GetConfigAsString(configname_caSKI, NULL);
    if ((caSKI_s == NULL) || *caSKI_s==0) {
        RA::Debug(LL_PER_SERVER, "CertEnroll::RevokeCertificate",
            "CA cert SKI not found in config for ca: %s", connid);
    } else {
        caSKI_x = PL_strdup(caSKI_s);
        PR_ASSERT(caSKI_x != NULL);
        RA::Debug(LL_PER_SERVER, "CertEnroll::RevokeCertificate",
            "CA cert SKI found in config for: %s", connid);
        /* convert from ASCII to SECItem */
        rv = ATOB_ConvertAsciiToItem(&ca_ski, caSKI_x);
        if (rv != SECSuccess) {
            RA::Debug(LL_PER_SERVER, "CertEnroll::RevokeCertificate",
                "CA cert SKI found in config faiiled ascii to SECItem conversion for ca:%s", connid);
            /* allows ca SKI to be retrieved again later if ca nickname is in store*/
            foundCaSKI = false;
        } else {
            foundCaSKI = true;
        }
    }

    PRBool match = PR_TRUE;
    PRBool skipMatch = PR_FALSE;
    if (!foundCaSKI) { /* get from cert db */
        PR_snprintf((char *)configname, 256, "conn.%s.caNickname", connid);
        caNickname = store->GetConfigAsString(configname);
        if ((caNickname != NULL) && *caNickname !=0) {
            caCert = CERT_FindCertByNickname(certdb, caNickname);
            if (caCert != NULL) {
                ca_ski = caCert->subjectKeyID;

                /* store it in config */
                caSKI_y = BTOA_ConvertItemToAscii(&ca_ski);
                store->Add(configname_caSKI, caSKI_y);
                RA::Debug(LL_PER_SERVER, "CertEnroll::RevokeCertificate",
                    "Commiting ca AKI Add for %s", connid);
                char error_msg[512] = {0};
                int status = 0;
                status = store->Commit(true, error_msg, 512);
                if (status != 0) {
                    /* commit error.. log it and keep going */
                    RA::Debug(LL_PER_SERVER, "CertEnroll::RevokeCertificate",
                    "Commit error for ca AKI Add : %s", error_msg);
                }
            } else {
                /* ca cert not found; no match needed */
                skipMatch = PR_TRUE;
            }
        } else {
            /*
             *  if it gets here, that means config is missing both:
             *  1. conn.ca<n>.caSKI
             *  2. conn.ca<n>.caNickname
             *  now assume default of just using the issuing ca and
             *  no search performed
             */
            skipMatch = PR_TRUE;
        }
    }

    if (!skipMatch) {
        /* now compare cert's AKI to the ca's SKI 
         *   if matched, continue,
         *   if not, search in the ca list
         */
        match = SECITEM_ItemsAreEqual(
            &cert->authKeyID->keyID, &ca_ski);
        if (!match) {
            RA::Debug("CertEnroll::RevokeCertificate", "cert AKI and caCert SKI of the designated issuing ca do not match... searching for another ca.");
            ret = CertEnroll::revokeFromOtherCA(
                revoke /*revoke or unrevoke*/, cert,
                serialno, o_status, reason);
            goto cleanup;
        } else {
            RA::Debug("CertEnroll::RevokeCertificate", "cert AKI and caCert SKI matched");
        } 
    }

    if (revoke)
        ret = RevokeCertificate(reason, serialno, connid, o_status);
    else
        ret = UnrevokeCertificate(serialno, connid, o_status);

cleanup:
    if (caSKI_x != NULL) {
        PORT_Free(caSKI_x);
    }
    if (caSKI_y != NULL) {
        PORT_Free(caSKI_y);
    }
    if (caCert != NULL) {
        CERT_DestroyCertificate(caCert);
    }
    return ret;
}

/*
 * RetrieveCertificate - retrieves certificate from CA by serial number
 * @param serialno serial number of the cert to retrieve
 * @param connid connection id of the ca
 * @param error_msg error message for return
 * @return
 *      The certificate in Buffer if success
 *      NULL if failure
 */
TOKENDB_PUBLIC Buffer *CertEnroll::RetrieveCertificate(PRUint64 serialno, const char *connid, char *error_msg)
{
    const char *FN = "CertEnroll::RetrieveCertificate";
    char parameters[5000];
    char configname[5000];

    RA::Debug(FN, "begins.");
    // on CA, GetBySerial expects parameter "serialNumber"
    PR_snprintf((char *)parameters, 5000, "serialNumber=%llu", serialno);

    RA::Debug(FN, "got parameters =%s", parameters);
    //e.g. conn.ca1.servlet.getBySerial=/ca/ee/ca/displayBySerial
    PR_snprintf((char *)configname, 256, "conn.%s.servlet.getBySerial", connid);
    const char *servlet = RA::GetConfigStore()->GetConfigAsString(configname);
/*
    const char *servlet = RA::GetConfigStore()->GetConfigAsString(configname,
        "/ca/ee/ca/displayBySerial");
*/
    if (servlet == NULL) {
        RA::Debug(FN,
            "Missing the configuration parameter for %s, set to default /ca/ee/ca/displayBySerial", configname);
        servlet = "/ca/ee/ca/displayBySerial";
    }

    PSHttpResponse *resp =  sendReqToCA(servlet, parameters, connid);
    // XXX - need to parse response
    Buffer * certificate = NULL;
    if (resp != NULL) {
      RA::Debug(LL_PER_PDU, FN,
          "sendReqToCA done");

      certificate = parseResponse(resp, "certChainBase64");
      RA::Debug(LL_PER_PDU, FN,
          "parseResponse done");

      if( resp != NULL ) { 
          delete resp;
          resp = NULL;
      }
    } else {
      RA::Error(FN,
        "sendReqToCA failure");
      PR_snprintf(error_msg, 512, "sendReqToCA failure");
      return NULL;
    }

    return certificate;
}

TOKENDB_PUBLIC Buffer *CertEnroll::RenewCertificate(PRUint64 serialno, const char *connid, const char *profileId, char *error_msg)
{
    char parameters[5000];
    char configname[5000];

    RA::Debug("CertEnroll::RenewCertificate", "begins. profileId=%s",profileId);
    // on CA, renewal expects parameter "serial_num" if renew by serial number
    // ahh.  need to allow larger serialno...later
    PR_snprintf((char *)parameters, 5000, "serial_num=%llu&profileId=%s&renewal=true",
               serialno, profileId);
    RA::Debug("CertEnroll::RenewCertificate", "got parameters =%s", parameters);
    //e.g. conn.ca1.servlet.renewal=/ca/ee/ca/profileSubmitSSLClient
    PR_snprintf((char *)configname, 256, "conn.%s.servlet.renewal", connid);
    const char *servlet = RA::GetConfigStore()->GetConfigAsString(configname);
        if (servlet == NULL) {
            RA::Debug("CertEnroll::RenewCertificate",
                "Missing the configuration parameter for %s", configname);
            PR_snprintf(error_msg, 512, "Missing the configuration parameter for %s", configname);
            return NULL;
        }

    // on CA, same profile servlet processes the renewal as well as enrollment
    PSHttpResponse *resp =  sendReqToCA(servlet, parameters, connid);
    // XXX - need to parse response
    Buffer * certificate = NULL;
    if (resp != NULL) {
      RA::Debug(LL_PER_PDU, "CertEnroll::RenewCertificate",
          "sendReqToCA done");

      certificate = parseResponse(resp);
      RA::Debug(LL_PER_PDU, "CertEnroll::RenewCertificate",
          "parseResponse done");

      if( resp != NULL ) { 
          delete resp;
          resp = NULL;
      }
    } else {
      RA::Error("CertEnroll::RenewCertificate",
        "sendReqToCA failure");
      PR_snprintf(error_msg, 512, "sendReqToCA failure");
      return NULL;
    }

    return certificate;
}


/**
 * Sends certificate request to CA for enrollment.
 */
Buffer * CertEnroll::EnrollCertificate( 
    SECKEYPublicKey *pk_parsed,
    const char *profileId,
    const char *uid,
    const char *cuid /*token id*/,
    const char *connid, 
    char *error_msg,
    SECItem** encodedPublicKeyInfo)
{
    return EnrollCertificate(pk_parsed, profileId, uid,
         NULL /*subjectdn*/, 0, NULL /*url_SAN_ext*/,
         cuid, connid, error_msg, encodedPublicKeyInfo);
}

Buffer * CertEnroll::EnrollCertificate( 
    SECKEYPublicKey *pk_parsed,
    const char *profileId,
    const char *uid,
    const char *subjectdn,
    int san_num,
    const char *url_SAN_ext,
    const char *cuid /*token id*/,
    const char *connid, 
    char *error_msg,
    SECItem** encodedPublicKeyInfo)
{
    char parameters[5000];
    Buffer * certificate = NULL;
 
    SECItem* si = SECKEY_EncodeDERSubjectPublicKeyInfo(pk_parsed);
    if (si == NULL) {

      RA::Error("CertEnroll::EnrollCertificate",
          "SECKEY_EncodeDERSubjectPublicKeyInfo  returns error");
      PR_snprintf(error_msg, 512, "SECKEY_EncodeDERSubjectPublicKeyInfo  returns error");
      return NULL;
    }

    // b64 encode it
    char* pk_b64 = BTOA_ConvertItemToAscii(si);

    if(encodedPublicKeyInfo == NULL)
    {
        if( si != NULL ) {
            SECITEM_FreeItem( si, PR_TRUE );
            si = NULL;
        }
    }
    else
    {

        *encodedPublicKeyInfo = si;

    }

    if (pk_b64 == NULL) {
    RA::Error(LL_PER_PDU, "CertEnroll::EnrollCertificate",
          "BTOA_ConvertItemToAscii returns error");

        PR_snprintf(error_msg, 512, "BTOA_ConvertItemToAscii returns error");
        return NULL;
    }
    RA::Debug(LL_PER_PDU, "CertEnroll::EnrollCertificate",
          "after BTOA_ConvertItemToAscii pk_b64=%s",pk_b64);

    char *url_pk = Util::URLEncode(pk_b64);
    char *url_uid = Util::URLEncode(uid);
    char *url_cuid = Util::URLEncode(cuid);
    char *url_subjectdn = NULL;
    const char *servlet;
    char configname[256];

    PR_snprintf((char *)configname, 256, "conn.%s.servlet.enrollment", connid);
    servlet = RA::GetConfigStore()->GetConfigAsString(configname);

    if ((subjectdn == NULL) && (san_num == 0)) {
        PR_snprintf((char *)parameters, 5000, "profileId=%s&tokencuid=%s&screenname=%s&publickey=%s", profileId, url_cuid, url_uid, url_pk);
    } else {
        RA::Debug(LL_PER_PDU, "CertEnroll::EnrollCertificate",
            "before sendReqToCA() with subjectdn and/or url_SAN_ext");
        if ((subjectdn != NULL) && (san_num == 0)) {
            url_subjectdn= Util::URLEncode(subjectdn);
            PR_snprintf((char *)parameters, 5000, "profileId=%s&tokencuid=%s&screenname=%s&publickey=%s&subject=%s", profileId, url_cuid, url_uid, url_pk, url_subjectdn);
        } else if ((subjectdn == NULL) && (san_num != 0)) {
            PR_snprintf((char *)parameters, 5000, "profileId=%s&tokencuid=%s&screenname=%s&publickey=%s&%s&req_san_entries=%d", profileId, url_cuid, url_uid, url_pk, url_SAN_ext, san_num);
        } else if ((subjectdn != NULL) && (san_num != 0)) {
            url_subjectdn= Util::URLEncode(subjectdn);
            PR_snprintf((char *)parameters, 5000, "profileId=%s&tokencuid=%s&screenname=%s&publickey=%s&subject=%s&%s&req_san_entries=%d", profileId, url_cuid, url_uid, url_pk, url_subjectdn, url_SAN_ext, san_num);
        }
    }

    RA::Debug(LL_PER_PDU, "CertEnroll::EnrollCertificate",
        "parameters = %s", parameters);
    PSHttpResponse *resp =  sendReqToCA(servlet, parameters, connid);
    if (resp != NULL) {
      RA::Debug(LL_PER_PDU, "CertEnroll::EnrollCertificate",
          "sendReqToCA done");

      certificate = parseResponse(resp);
      RA::Debug(LL_PER_PDU, "CertEnroll::EnrollCertificate",
          "parseResponse done");

      if( resp != NULL ) { 
          delete resp;
          resp = NULL;
      }
    } else {
      RA::Error("CertEnroll::EnrollCertificate",
        "sendReqToCA failure");
      PR_snprintf(error_msg, 512, "sendReqToCA failure");
      goto loser;
    }

loser:
    if( pk_b64 != NULL ) {
        PR_Free( pk_b64 );
        pk_b64 = NULL;
    }
    if( url_pk != NULL ) {
        PR_Free( url_pk );
        url_pk = NULL;
    }
    if( url_uid != NULL ) {
        PR_Free( url_uid );
        url_uid = NULL;
    }
    if( url_cuid != NULL ) {
        PR_Free( url_cuid );
        url_cuid = NULL;
    }
    if (url_subjectdn != NULL)
        PR_Free( url_subjectdn );

    return certificate;
}

/**
 * Extracts information from the public key blob and verify proof.
 *
 * Muscle Key Blob Format (RSA Public Key)
 * ---------------------------------------
 * 
 * The key generation operation places the newly generated key into
 * the output buffer encoding in the standard Muscle key blob format.
 *  For an RSA key the data is as follows:
 * 
 * Byte     Encoding (0 for plaintext)
 * 
 * Byte     Key Type (1 for RSA public)
 * 
 * Short     Key Length (1024 û high byte first)
 * 
 * Short     Modulus Length
 * 
 * Byte[]     Modulus
 * 
 * Short     Exponent Length
 * 
 * Byte[]     Exponent
 * 
 *  
 * Signature Format (Proof)
 * ---------------------------------------
 *  
 * The key generation operation creates a proof-of-location for the
 * newly generated key. This proof is a signature computed with the 
 * new private key using the RSA-with-MD5 signature algorithm.  The 
 * signature is computed over the Muscle Key Blob representation of 
 * the new public key and the challenge sent in the key generation 
 * request.  These two data fields are concatenated together to form
 * the input to the signature, without any other data or length fields.
 * 
 * Byte[]     Key Blob Data
 * 
 * Byte[]     Challenge
 * 
 * 
 * Key Generation Result
 * ---------------------------------------
 * 
 * The key generation command puts the key blob and the signature (proof)
 * into the output buffer using the following format:
 * 
 * Short     Length of the Key Blob
 * 
 * Byte[]     Key Blob Data
 * 
 * Short     Length of the Proof
 * 
 * Byte[]     Proof (Signature) Data
 *
 * @param blob the publickey blob to be parsed
 * @param challenge the challenge generated by RA
 * @return
 *      rc is 1 if success, -1 if failure
 *      pk is the public key resulted from parsing the blob.
 *
 ******/

SECKEYPublicKey *CertEnroll::ParsePublicKeyBlob(unsigned char *blob,
                             Buffer *challenge)
{
    char configname[5000];
    SECKEYPublicKey *pk = NULL;

    ReturnStatus rs;
    rs.status = PR_FAILURE;
    rs.statusNum = ::MSG_INVALID;

    if ((blob == NULL) || (challenge == NULL)) {
        RA::Error(LL_PER_PDU, "CertEnroll::ParsePublicKeyBlob", "invalid input");
	return NULL;
    }

    /*
     * decode blob into structures
     */

    // offset to the beginning of the public key length.  should be 0
    unsigned short pkeyb_len_offset = 0;

    unsigned short pkeyb_len = 0;
    unsigned char* pkeyb;
    unsigned short proofb_len = 0;
    unsigned char* proofb;

    /*
     * now, convert lengths
     */
    // 1st, keyblob length
    unsigned char len0 = blob[pkeyb_len_offset];
    unsigned char len1 = blob[pkeyb_len_offset +1];
    pkeyb_len = (unsigned short) ((len0 << 8) | (len1 & 0xFF));

    RA::Debug(LL_PER_PDU, "CertEnroll::ParsePublicKeyBlob",
          "pkeyb_len =%d",pkeyb_len);

    if (pkeyb_len <= 0) {
      RA::Error("CertEnroll::ParsePublicKeyBlob", "public key blob length = %d", pkeyb_len);
      return NULL;
    }
    // 2nd, proofblob length
    unsigned short proofb_len_offset = pkeyb_len_offset + 2 + pkeyb_len;
    len0 = blob[proofb_len_offset];
    len1 = blob[proofb_len_offset +1];
    proofb_len = (unsigned short) (len0 << 8 | len1 & 0xFF);
    RA::Debug(LL_PER_PDU, "CertEnroll::ParsePublicKeyBlob",
          "proofb_len =%d", proofb_len);

    // public key blob
    pkeyb = &blob[pkeyb_len_offset + 2];

    // proof blob
    proofb = &blob[proofb_len_offset + 2];

    SECItem siProof;
    siProof.type = (SECItemType) 0;
    siProof.data = (unsigned char *)proofb;
    siProof.len = proofb_len;

    // convert pkeyb to pkey
    // 1 byte encoding, 1 byte key type, 2 bytes key length, then the key
    unsigned short pkey_offset = 4;
    // now, convert lengths for modulus and exponent
    len0 = pkeyb[pkey_offset];
    len1 = pkeyb[pkey_offset + 1];
    unsigned short mod_len = (len0 << 8 | len1);

    len0 = pkeyb[pkey_offset + 2 + mod_len];
    len1 = pkeyb[pkey_offset + 2 + mod_len + 1];
    unsigned short exp_len = (len0 << 8 | len1);


    // public key mod blob
    unsigned char * modb = &pkeyb[pkey_offset + 2];

    // public key exp blob
    unsigned char * expb = &pkeyb[pkey_offset + 2 + mod_len + 2];

    // construct SECItem
    SECItem siMod;
    siMod.type = (SECItemType) 0;
    siMod.data = (unsigned char *) modb;
    siMod.len = mod_len;

    SECItem siExp;
    siExp.type = (SECItemType) 0;
    siExp.data = (unsigned char *)expb;
    siExp.len = exp_len;

    // construct SECKEYRSAPublicKeyStr
    SECKEYRSAPublicKeyStr rsa_pks;
    rsa_pks.modulus = siMod;
    rsa_pks.publicExponent = siExp;

    // construct SECKEYPublicKey
    // this is to be returned
    pk = (SECKEYPublicKey *) malloc(sizeof(SECKEYPublicKey));
    pk->keyType = rsaKey;
    pk->pkcs11Slot = NULL;
    pk->pkcs11ID = CK_INVALID_HANDLE;
    pk->u.rsa = rsa_pks;

    PR_snprintf((char *)configname, 256, "general.verifyProof");
    int verifyProofEnable = RA::GetConfigStore()->GetConfigAsInt(configname, 0x1);
    if (verifyProofEnable) {
      rs = verifyProof(pk, &siProof, pkeyb_len, pkeyb, challenge);
      if (rs.status == PR_FAILURE) {
        RA::Error("CertEnroll::ParsePublicKeyBlob",
          "verify proof failed");
        free(pk);
        pk = NULL;
      }
    }

    return pk;
}


/**
 * verify the proof.
 * @param pk the public key from the input blob
 * @param siProof the proof from the input blob
 * @param pkeyb_len the length of the publickey blob
 * @param pkeyb the public key blob
 * @param challenge the challenge generated by RA
 *
 * @return
 *      returns success indication in case of success
 *      returns error message number as defined in ReturnStatus in Base.h
 */
ReturnStatus CertEnroll::verifyProof(SECKEYPublicKey* pk, SECItem* siProof,
             unsigned short pkeyb_len, unsigned char* pkeyb,
             Buffer* challenge) {

    ReturnStatus rs;
    VFYContext * vc = NULL;
    rs.statusNum = ::VRFY_SUCCESS;
    rs.status = PR_SUCCESS;

    // verify proof (signature)
    RA::Debug(LL_PER_PDU, "CertEnroll::verifyProof",
          "verify proof begins");

    vc = VFY_CreateContext(pk, siProof, SEC_OID_ISO_SHA_WITH_RSA_SIGNATURE, NULL);

    if (vc == NULL) {
        RA::Error("CertEnroll::verifyProof",
        "VFY_CreateContext() failed");
        rs.status = PR_FAILURE;
        rs.statusNum = ::VFY_BEGIN_FAILURE;
        return rs;
    } else {
        RA::Debug(LL_PER_PDU, "CertEnroll::verifyProof",
        "VFY_CreateContext() succeeded");
    }

    unsigned char proof[1024];
    int i =0; 
    for (i = 0; i<pkeyb_len; i++) {
        proof[i] = pkeyb[i];
    }
    //    RA::DebugBuffer("CertEnroll::VerifyProof","VerifyProof:: challenge =", challenge);
    unsigned char* chal = (unsigned char *)(BYTE *) (*challenge);
    unsigned int j = 0;
    for (j=0; j < challenge->size(); i++, j++) {
        proof[i] = chal[j];
	//	RA::Debug(LL_PER_PDU, "CertEnroll::VerifyProof","proof[%d]= %x",
	//		  i, proof[i]);
    }

    SECStatus vs = VFY_Begin(vc);
    if (vs == SECSuccess) {
      vs = VFY_Update(vc, (unsigned char *)proof , pkeyb_len + challenge->size());
      if (vs == SECSuccess) {
          vs = VFY_End(vc);
          if (vs == SECFailure) {
            RA::Error("CertEnroll::verifyProof",
                "VFY_End() failed pkeyb_len=%d challenge_size=%d", pkeyb_len, challenge->size());
            rs.statusNum = ::VFY_UPDATE_FAILURE;
            rs.status = PR_FAILURE;
          }
      } else {
          RA::Error("CertEnroll::verifyProof",
              "VFY_Update() failed");
          rs.statusNum = ::VFY_UPDATE_FAILURE;
          rs.status = PR_FAILURE;
      }
    } else {
      RA::Error("CertEnroll::verifyProof",
          "VFY_Begin() failed");

      rs.statusNum = ::VFY_BEGIN_FAILURE;
      rs.status = PR_FAILURE;
    }

    if( vc != NULL ) {
        VFY_DestroyContext( vc, PR_TRUE );
        vc = NULL;
    }
    RA::Debug(LL_PER_PDU, "CertEnroll::verifyProof",
        " VFY_End() returned %d",vs);

    return rs;

}

/**
 * sendReqToCA sends cert enrollment request via HTTPS to the CA
 * @param pk normalized public key
 * @param uid uid/screenname
 * @param cuid cud number of the client token
 * @param timeout timeout value for connection
 * @return
 *     PSHttpResponse if success
 *     NULL if failure
 */
PSHttpResponse * CertEnroll::sendReqToCA(const char *servlet, const char *parameters, const char *connid)
{
    // compose http uri

    RA::Debug(LL_PER_PDU, "CertEnroll::sendReqToCA",
          "begins");

    HttpConnection *caConn = RA::GetCAConn(connid);
    if (caConn == NULL) {
        RA::Debug(LL_PER_PDU, "CertEnroll::sendReqToCA", "Failed to get CA Connection %s", connid);
        RA::Error(LL_PER_PDU, "CertEnroll::sendReqToCA", "Failed to get CA Connection %s", connid);
        return NULL;
    }
    // PRLock *ca_lock = RA::GetCALock();
    int ca_curr = RA::GetCurrentIndex(caConn);
    int maxRetries = caConn->GetNumOfRetries();
    ConnectionInfo *connInfo = caConn->GetFailoverList();
    char **hostport = connInfo->GetHostPortList();
    int currRetries = 0;

    RA::Debug(LL_PER_PDU, "Before calling getResponse, caHostPort is %s", hostport[ca_curr]);

    PSHttpResponse * response = caConn->getResponse(ca_curr, servlet, parameters);
    while (response == NULL) {
        RA::Failover(caConn, connInfo->GetHostPortListLen());
        ca_curr = RA::GetCurrentIndex(caConn);

        if (++currRetries >= maxRetries) {
            RA::Debug(LL_PER_PDU, "Used up all the retries. Response is NULL","");
            RA::Error("CertEnroll::sendReqToCA", "Failed connecting to CA after %d retries", currRetries);
	    if (caConn != NULL) {
		    RA::ReturnCAConn(caConn);
	    }
            return NULL;
        }
        response = caConn->getResponse(ca_curr, servlet, parameters);
    }

    if (caConn != NULL) {
	    RA::ReturnCAConn(caConn);
    }
    return response;
}

Buffer * CertEnroll::parseResponse(PSHttpResponse * resp)
{
    return parseResponse(resp, "outputVal");
}

/**
 * parse the http response and retrieve the certificate.
 * @param resp the response returned from http request
 * @param certB64Param the string pattern that represents the param name of the cert in response
 * @return
 *      The certificate in Buffer if success
 *      NULL if failure
 */
Buffer * CertEnroll::parseResponse(PSHttpResponse * resp, char *certB64Param)
{
    unsigned int i;
    const int PARAM_CERT_MAX_SIZE = 8192;
    char pattern [32] = {0};
    unsigned char blob[PARAM_CERT_MAX_SIZE]={0}; /* cert returned */
    int blob_len = 0; /* cert length */
    char *certB64 = NULL;
    char *certB64End = NULL;
    unsigned int certB64Len = 0;
    Buffer *cert = NULL;
    char * response = NULL;
    SECItem * outItemOpt = NULL;
    char *err = NULL;
    
    if (resp == NULL) {
        RA::Debug(LL_PER_PDU, "CertEnroll::parseResponse",
          "no response found");
	    return NULL;
    }
    response = resp->getContent();
    if (response == NULL) {
        RA::Debug(LL_PER_PDU, "CertEnroll::parseResponse",
          "no content found");
	    return NULL;
    } else {
        RA::Debug(LL_PER_PDU, "CertEnroll::parseResponse",
          "response not NULL");
    }

    if (certB64Param == NULL) {
        RA::Debug(LL_PER_PDU, "CertEnroll::parseResponse",
            "cert param name in response is needed to parse...now missing");
        goto endParseResp;
    } else {
        RA::Debug(LL_PER_PDU, "CertEnroll::parseResponse",
            "cert param name in response :%s", certB64Param);
    }

    // process result
    // first look for errorCode="" to look for success clue
    // and errorReason="..." to extract error reason
    PL_strcpy(pattern, "errorCode=\"0\"");
    err = strstr((char *)response, (char *)pattern);

    if (err == NULL) {
      RA::Debug("CertEnroll::parseResponse",
		"can't find errorCode.");
    } else {
        RA::Debug(LL_PER_PDU, "CertEnroll::parseResponse",
          "begin parsing but with err: %s", err);
    }

    // if success, look for "<certB64Param>=" to extract
    // the cert
    certB64 = strstr((char *)response, certB64Param);
    if (certB64 == NULL) {
        RA::Debug(LL_PER_PDU, "CertEnroll::parseResponse",
          "parameter %s not found in response", certB64Param);
        goto endParseResp;
    }

    if (strlen(certB64) < (strlen(certB64Param)+3)) { //safety check
        RA::Debug(LL_PER_PDU, "CertEnroll::parseResponse",
            "certB64 too short");
        goto endParseResp;
    }
    certB64 = &certB64[strlen(certB64Param)+2]; // point pass open "

    certB64End = strstr(certB64, "\";");
    if (certB64End == NULL) {
        RA::Debug(LL_PER_PDU, "CertEnroll::parseResponse",
          "certB64 can't find end of param in response");
        goto endParseResp;
    }
    *certB64End = '\0';

    certB64Len = strlen(certB64);
    RA::Debug(LL_PER_PDU, "CertEnroll::parseResponse",
          "certB64 len = %d", certB64Len);

    for (i=0; i<certB64Len-1 ; i++) {
        if (certB64[i] == '\\') { certB64[i] = ' '; certB64[i+1] = ' '; }
    }

    // b64 decode and put back in blob
    RA::Debug(LL_PER_PDU, "CertEnroll::parseResponse",
          "b64 decode received cert");

    outItemOpt = NSSBase64_DecodeBuffer(NULL, NULL, certB64, certB64Len);
    if (outItemOpt == NULL) {
        RA::Error("CertEnroll::parseResponse",
          "b64 decode failed, error code=%d", PR_GetError());

        goto endParseResp;
    }
    RA::Debug(LL_PER_PDU, "CertEnroll::parseResponse",
          "b64 decode len =%d",outItemOpt->len);

    if (outItemOpt->len > PARAM_CERT_MAX_SIZE) {
       RA::Debug(LL_PER_PDU, "CertEnroll::parseResponse",
           "cert too long");
       goto endParseResp;
    }
    memcpy((char*)blob, (const char*)(outItemOpt->data), outItemOpt->len);
    blob_len = outItemOpt->len;

    cert = new Buffer((BYTE *) blob, blob_len);

 endParseResp:
    if( outItemOpt != NULL ) {
        SECITEM_FreeItem( outItemOpt, PR_TRUE );
        outItemOpt = NULL;
    }

    RA::Debug(LL_PER_PDU, "CertEnroll::parseResponse",
          "finished");

    if (response != NULL) {
        resp->freeContent();
        response = NULL;
    }
    return cert;
}

