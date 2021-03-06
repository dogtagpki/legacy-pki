// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.kra;

import java.security.PublicKey;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.TokenException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.security.ITransportKeyUnit;
import com.netscape.cmsutil.util.Cert;


/**
 * A class represents the transport key pair. This key pair
 * is used to protected EE's private key in transit.
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class TransportKeyUnit extends EncryptionUnit implements 
        ISubsystem, ITransportKeyUnit {

    public static final String PROP_NICKNAME = "nickName";
    public static final String PROP_SIGNING_ALGORITHM = "signingAlgorithm";

    // private RSAPublicKey mPublicKey = null;
    // private RSAPrivateKey mPrivateKey = null;
    private IConfigStore mConfig = null;
    private org.mozilla.jss.crypto.X509Certificate mCert = null;
    private CryptoManager mManager = null;

    /**
     * Constructs this token.
     */
    public TransportKeyUnit() {
        super();
    }

    /**
     * Retrieves subsystem identifier.
     */
    public String getId() {
        return "transportKeyUnit";
    }

    /**
     * Sets subsystem identifier.
     */
    public void setId(String id) throws EBaseException {
        throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_OPERATION"));
    }

    /**
     * Initializes this subsystem.
     */
    public void init(ISubsystem owner, IConfigStore config) 
        throws EBaseException {
        mConfig = config;
        try {
            mManager = CryptoManager.getInstance();
            mCert = mManager.findCertByNickname(getNickName());
            String algo = config.getString("signingAlgorithm", "SHA256withRSA");

            // #613795 - initialize this; otherwise JSS is not happy
            CryptoToken token = getToken(); 
            SignatureAlgorithm sigalg = Cert.mapAlgorithmToJss(algo);
            Signature signer = token.getSignatureContext(sigalg); 
            signer.initSign(getPrivateKey());
           

        } catch (org.mozilla.jss.CryptoManager.NotInitializedException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()));

        } catch (TokenException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()));
        } catch (ObjectNotFoundException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()));
        } catch (Exception e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()));
        }
    }

    public CryptoToken getInternalToken() {
        try {
            return CryptoManager.getInstance().getInternalKeyStorageToken();
        } catch (Exception e) {
            return null;
        }
    }

    public CryptoToken getToken() {
        // 390148: returning the token that owns the private
        //         key. 
        return getPrivateKey().getOwningToken();
    }

    /**
     * Starts up this subsystem.
     */
    public void startup() throws EBaseException {
    }

    /**
     * Shutdowns this subsystem.
     */
    public void shutdown() {
    }
	
    /**
     * Returns the configuration store of this token.
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    public String getNickName() throws EBaseException {
        return mConfig.getString(PROP_NICKNAME);
    }

    public void setNickName(String str) throws EBaseException {
        mConfig.putString(PROP_NICKNAME, str);
    }

    public String getSigningAlgorithm() throws EBaseException {
        return mConfig.getString(PROP_SIGNING_ALGORITHM);
    }

    public void setSigningAlgorithm(String str) throws EBaseException {
        mConfig.putString(PROP_SIGNING_ALGORITHM, str);
    }

    /**
     * Logins to this token.
     */
    public void login(String pin) throws EBaseException {
    }

    /**
     * Logout from this token.
     */
    public void logout() {
    }

    /**
     * Retrieves public key.
     */
    public org.mozilla.jss.crypto.X509Certificate getCertificate() {
        return mCert;
    }

    public PublicKey getPublicKey() {
        return mCert.getPublicKey();
    }

    public PrivateKey getPrivateKey() {
        try {
            return mManager.findPrivKeyByCert(mCert);
        } catch (TokenException e) {
            return null;
        } catch (ObjectNotFoundException e) {
            return null;
        }
    }

    /**
     * Verifies the integrity of the given key pair.
     */
    public void verify(byte publicKey[], PrivateKey privateKey)
        throws EBaseException {
        // XXX
    }
}
