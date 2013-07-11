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
        char publicKeyAttrId[MaxExternalRegBuf];
        char publicKeyNumber[MaxExternalRegBuf];
        char privateKeyAttrId[MaxExternalRegBuf];
        char privateKeyNumber[MaxExternalRegBuf];
        char label[MaxExternalRegBuf];
        char certAttrId[MaxExternalRegBuf];
        char certId[MaxExternalRegBuf];
        char cuid_label[MaxExternalRegBuf];
        Buffer *public_key;
        Buffer *wrappedPrivKey;
        Buffer *wrappedDESkey; /*from TKS- session key wrapped with DRM transport*/
    private:
        CERTCertificate *certificate;
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

    private:
        PRUint64 keyid;
        PRUint64 serial;
        const char *caConn;
        const char *drmConn;
        ExternalRegCertKeyInfo *certKeyInfo;
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
        TPS_PUBLIC int getCertsToRecoverCount();
        TPS_PUBLIC void addCertToRecover(ExternalRegCertToRecover *ctr);
        TPS_PUBLIC ExternalRegCertToRecover** getCertsToRecover();
        TPS_PUBLIC int getCertsToDeleteCount();
        TPS_PUBLIC void addCertToDelete(ExternalRegCertToDelete *ctd);
        TPS_PUBLIC ExternalRegCertToDelete** getCertsToDelete();

    protected:
        const char *tokenCUID;
        const char *tokenType;
        ExternalRegCertToRecover *certsToRecover[MAX_EXTERNAL_REG_CERTS];
        ExternalRegCertToDelete *certsToDelete[MAX_EXTERNAL_REG_CERTS];
};

#endif /* EXTERNAL_REG_ATTRS_H */

