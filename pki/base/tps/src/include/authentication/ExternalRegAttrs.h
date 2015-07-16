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
 * Copyright (C) 2013 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 */

#ifndef EXTERNAL_REG_ATTRS_H
#define EXTERNAL_REG_ATTRS_H

#ifdef HAVE_CONFIG_H
#ifndef AUTOTOOLS_CONFIG_H
#define AUTOTOOLS_CONFIG_H

/* Eliminate warnings when using Autotools */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <config.h>
#endif /* AUTOTOOLS_CONFIG_H */
#endif /* HAVE_CONFIG_H */

#include "keythi.h"
#include "cert.h"
#include "main/Buffer.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

#define MAX_EXTERNAL_REG_CERTS 20
#define MaxExternalRegBuf 64
/*
 * cert status in tokendb:
 */
typedef enum {
    UNINITIALIZED = 0,
    ACTIVE = 1,
    REVOKED = 2,
    EXPIRED = 3
} CertStatus;

/*
 * ExternalRegCertKeyInfo - cert/key info for the token
 */
class ExternalRegCertKeyInfo
{
    friend class ExternalRegCertToRecover;
    friend class ExternalRegCertToDelete;
    public:
        ExternalRegCertKeyInfo();
        ~ExternalRegCertKeyInfo();
    public:

        TPS_PUBLIC void setCert(CERTCertificate *cert);
        TPS_PUBLIC CERTCertificate *getCert();
/*ToDo: other functions to handle private data
public data for now...
*/
    public:
        void setPublicKeyAttrId(char *attrId) { strncpy(publicKeyAttrId,attrId, MaxExternalRegBuf); }
        char *getPublicKeyAttrId() { return publicKeyAttrId;}

        void setPrivateKeyNumber(int keyNum) { privateKeyNumber = keyNum; }
        int getPrivateKeyNumber() { return privateKeyNumber;}

        void setPublicKeyNumber(int keyNum) { publicKeyNumber = keyNum; }
        int getPublicKeyNumber() { return publicKeyNumber;}

        void setCertStatus(CertStatus status) { certStatus = status; }
        CertStatus getCertStatus() { return certStatus; }

        void setPrivateKeyAttrId(char *attrId) { strncpy(privateKeyAttrId, attrId, MaxExternalRegBuf); }
        char *getPrivateKeyAttrId() { return privateKeyAttrId;}

        void setLabel(char *theLabel) { strncpy(label, theLabel, MaxExternalRegBuf); }
        char *getLabel() { return label; }

        void setCertAttrId(char *theCertAttrId) { strncpy(certAttrId, theCertAttrId, MaxExternalRegBuf); }
        char *getCertAtrId() { return certAttrId; }

        void setCertId(char *theCertId) { strncpy(certId, theCertId, MaxExternalRegBuf); }
        char *getCertId() { return certId; }

        void setCuidLabel(char *theLabel) { strncpy(cuid_label, theLabel, MaxExternalRegBuf); }
        char *getCuidLabel() { return cuid_label; }

        void setIVParam(char *theIVParam) { strncpy(ivParam, theIVParam, MaxExternalRegBuf); }
        char *getIVParam() { return ivParam; }


        char publicKeyAttrId[MaxExternalRegBuf];
        char privateKeyAttrId[MaxExternalRegBuf];
        int privateKeyNumber;
        int publicKeyNumber;
        char ivParam[MaxExternalRegBuf];
        char label[MaxExternalRegBuf];

        char certAttrId[MaxExternalRegBuf];
        char certId[MaxExternalRegBuf];
        char cuid_label[MaxExternalRegBuf];

        void setPublicKey(const char *pubKey) { if(!public_key && pubKey != NULL) { public_key =  strdup(pubKey); }}
        char *getPublicKey() { return public_key; } 

        void setWrappedPrivKey( const char *theWrappedPrivKey) { if(!wrappedPrivKey && theWrappedPrivKey != NULL) { wrappedPrivKey =  strdup(theWrappedPrivKey); }}
        char *getWrappedPrivKey() { return wrappedPrivKey; }

    private:
        CERTCertificate *certificate;
        char *public_key;
        char *wrappedPrivKey;
        CertStatus certStatus;
};

/*
 * ExternalRegCertToRecover - one entry of a cert to recover
 */
class ExternalRegCertToRecover
{
    friend class ExternalRegAttrs;
    public:
        ExternalRegCertToRecover();
        ~ExternalRegCertToRecover();

    public:
        TPS_PUBLIC void setSerial(PRUint64 serial);
        TPS_PUBLIC PRUint64 getSerial();
        TPS_PUBLIC void setKeyid(PRUint64 keyid);
        TPS_PUBLIC PRUint64 getKeyid();
        TPS_PUBLIC void setCaConn(const char *caConn);
        TPS_PUBLIC const char *getCaConn();
        TPS_PUBLIC void setDrmConn(const char *drmConn);
        TPS_PUBLIC const char *getDrmConn();
        TPS_PUBLIC void setCertKeyInfo(ExternalRegCertKeyInfo *ckInfo);
        TPS_PUBLIC ExternalRegCertKeyInfo *getCertKeyInfo();
        TPS_PUBLIC void setIgnoreForUpdateCerts(bool ignore) { ignoreForUpdateCerts = ignore; }
        TPS_PUBLIC bool getIgnoreForUpdateCerts() { return ignoreForUpdateCerts; }

    private:
        PRUint64 keyid;
        PRUint64 serial;
        const char *caConn;
        const char *drmConn;
        ExternalRegCertKeyInfo *certKeyInfo;
        bool ignoreForUpdateCerts;
};

/*
 * ExternalRegCertToDelete - one entry of a cert to delete (revoke optional)
 */
class ExternalRegCertToDelete
{
    friend class ExternalRegAttrs;
    public:
        ExternalRegCertToDelete();
        ~ExternalRegCertToDelete();

    public:
        TPS_PUBLIC void setSerial(PRUint64 serial);
        TPS_PUBLIC PRUint64 getSerial();
        TPS_PUBLIC void setCaConn(const char *caConn);
        TPS_PUBLIC const char *getCaConn();
        TPS_PUBLIC void setRevoke(bool revoke);
        TPS_PUBLIC bool getRevoke();

    private:
        PRUint64 serial;
        const char *caConn;
        bool revoke;

    private:
        ExternalRegCertKeyInfo *certKeyInfo;
};

class ExternalRegAttrs
{
    public:
        TPS_PUBLIC ExternalRegAttrs();
        TPS_PUBLIC virtual ~ExternalRegAttrs();

    public:
        TPS_PUBLIC void setTokenCUID(const char *cuid);
        TPS_PUBLIC const char *getTokenCUID();
        TPS_PUBLIC void setTokenType(const char *tokenType);
        TPS_PUBLIC const char *getTokenType();
        TPS_PUBLIC const char *getUserId();
        TPS_PUBLIC void setUserId(const char *theUserId);
        TPS_PUBLIC void setTokenMSN(const char *theMsn);
        TPS_PUBLIC const char *getTokenMSN();

        TPS_PUBLIC int getCertsToRecoverCount();
        TPS_PUBLIC void addCertToRecover(ExternalRegCertToRecover *ctr);
        TPS_PUBLIC ExternalRegCertToRecover** getCertsToRecover();
        TPS_PUBLIC int getCertsToDeleteCount();
        TPS_PUBLIC void addCertToDelete(ExternalRegCertToDelete *ctd);
        TPS_PUBLIC ExternalRegCertToDelete** getCertsToDelete();

    protected:
        char *tokenCUID;
        char *tokenType;
        char *userId;
        char *tokenMSN;
        ExternalRegCertToRecover *certsToRecover[MAX_EXTERNAL_REG_CERTS];
        ExternalRegCertToDelete *certsToDelete[MAX_EXTERNAL_REG_CERTS];
};

#endif /* EXTERNAL_REG_ATTRS_H */

