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
package com.netscape.cmsutil.crypto;


import java.net.*;
import java.io.*;
import java.util.*;
import java.text.*;
import java.math.*;

import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.DSAParams;
import java.security.cert.*;

//import sun.misc.BASE64Encoder;
//import sun.misc.BASE64Decoder;
import org.mozilla.jss.*;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.util.*;
import org.mozilla.jss.pkix.primitive.*;
import org.mozilla.jss.pkix.crmf.*;
import org.mozilla.jss.pkcs7.ContentInfo;
import org.mozilla.jss.pkcs7.*;
import org.mozilla.jss.pkcs11.*;
import org.mozilla.jss.pkcs11.PK11KeyPairGenerator;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.util.Base64OutputStream;

import netscape.security.util.*;
import netscape.security.pkcs.*;
import netscape.security.x509.*;
import com.netscape.cmsutil.util.Cert;


public class CryptoUtil {

    public static final String CERTREQ_BEGIN_HEADING = "-----BEGIN CERTIFICATE REQUEST-----";
    public static final String CERTREQ_END_HEADING = "-----END CERTIFICATE REQUEST-----";
    public static final int LINE_COUNT = 76;
    public static final String CERT_BEGIN_HEADING = "-----BEGIN CERTIFICATE-----";
    public static final String CERT_END_HEADING = "-----END CERTIFICATE-----";

    private static final String[] ecCurves = {"nistp256","nistp384","nistp521","sect163k1","nistk163","sect163r1","sect163r2",
       "nistb163","sect193r1","sect193r2","sect233k1","nistk233","sect233r1","nistb233","sect239k1","sect283k1","nistk283",
       "sect283r1","nistb283","sect409k1","nistk409","sect409r1","nistb409","sect571k1","nistk571","sect571r1","nistb571",
       "secp160k1","secp160r1","secp160r2","secp192k1","secp192r1","nistp192","secp224k1","secp224r1","nistp224","secp256k1",
       "secp256r1","secp384r1","secp521r1","prime192v1","prime192v2","prime192v3","prime239v1","prime239v2","prime239v3","c2pnb163v1",
       "c2pnb163v2","c2pnb163v3","c2pnb176v1","c2tnb191v1","c2tnb191v2","c2tnb191v3","c2pnb208w1","c2tnb239v1","c2tnb239v2","c2tnb239v3",
       "c2pnb272w1","c2pnb304w1","c2tnb359w1","c2pnb368w1","c2tnb431r1","secp112r1","secp112r2","secp128r1","secp128r2","sect113r1","sect113r2",
       "sect131r1","sect131r2"
    };

    private final static HashMap<String,Vector> ecOIDs = new HashMap<String,Vector>();
 	static
    {
       ecOIDs.put( "1.2.840.10045.3.1.7",  new Vector() {{add("nistp256");add("secp256r1");}});
       ecOIDs.put( "1.3.132.0.34",         new Vector() {{add("nistp384");add("secp384r1");}});
       ecOIDs.put( "1.3.132.0.35",         new Vector() {{add("nistp521");add("secp521r1");}});
       ecOIDs.put( "1.3.132.0.1",          new Vector() {{add("sect163k1");add("nistk163");}});
       ecOIDs.put( "1.3.132.0.2",          new Vector() {{add("sect163r1");}});
       ecOIDs.put( "1.3.132.0.15",         new Vector() {{add("sect163r2");add("nistb163");}});
       ecOIDs.put( "1.3.132.0.24",         new Vector() {{add("sect193r1");}});
       ecOIDs.put( "1.3.132.0.25",         new Vector() {{add("sect193r2");}});
       ecOIDs.put( "1.3.132.0.26",         new Vector() {{add("sect233k1");add("nistk233");}});
       ecOIDs.put( "1.3.132.0.27",         new Vector() {{add("sect233r1");add("nistb233");}});
       ecOIDs.put( "1.3.132.0.3",         new Vector() {{add("sect239k1");}});
       ecOIDs.put( "1.3.132.0.16",         new Vector() {{add("sect283k1");add("nistk283");}});
       ecOIDs.put( "1.3.132.0.17",         new Vector() {{add("sect283r1");add("nistb283");}});
       ecOIDs.put( "1.3.132.0.36",         new Vector() {{add("sect409k1");add("nistk409");}});
       ecOIDs.put( "1.3.132.0.37",         new Vector() {{add("sect409r1");add("nistb409");}});
       ecOIDs.put( "1.3.132.0.38",         new Vector() {{add("sect571k1"); add("nistk571");}});
       ecOIDs.put( "1.3.132.0.39",         new Vector() {{add("sect571r1");add("nistb571");}});
       ecOIDs.put( "1.3.132.0.9",          new Vector()  {{add("secp160k1");}});
       ecOIDs.put( "1.3.132.0.8",          new Vector()  {{add("secp160r1");}});
       ecOIDs.put( "1.3.132.0.30",         new Vector() {{add("secp160r2");}});
       ecOIDs.put( "1.3.132.0.31",         new Vector() {{add("secp192k1");}});
       ecOIDs.put( "1.2.840.10045.3.1.1",  new Vector() {{add("secp192r1");add("nistp192");add("prime192v1");}});
       ecOIDs.put( "1.3.132.0.32",         new Vector() {{add("secp224k1");}});
       ecOIDs.put( "1.3.132.0.33",         new Vector() {{add("secp224r1");add("nistp224");}});
       ecOIDs.put( "1.3.132.0.10",         new Vector() {{add("secp256k1");}});
       ecOIDs.put( "1.2.840.10045.3.1.2",new Vector() {{add("prime192v2");}});
       ecOIDs.put( "1.2.840.10045.3.1.3",new Vector() {{add("prime192v3");}});
       ecOIDs.put( "1.2.840.10045.3.1.4",new Vector() {{add("prime239v1");}});
       ecOIDs.put( "1.2.840.10045.3.1.5",new Vector() {{add("prime239v2");}});
       ecOIDs.put( "1.2.840.10045.3.1.6",new Vector() {{add("prime239v3");}});
       ecOIDs.put( "1.2.840.10045.3.0.1",  new Vector() {{add("c2pnb163v1");}});
       ecOIDs.put( "1.2.840.10045.3.0.2",  new Vector() {{add("c2pnb163v2");}});
       ecOIDs.put( "1.2.840.10045.3.0.3",  new Vector() {{add("c2pnb163v3");}});
       ecOIDs.put( "1.2.840.10045.3.0.4",  new Vector() {{add("c2pnb176v1");}});
       ecOIDs.put( "1.2.840.10045.3.0.5",  new Vector() {{add("c2tnb191v1");}});
       ecOIDs.put( "1.2.840.10045.3.0.6",  new Vector() {{add("c2tnb191v2");}});
       ecOIDs.put( "1.2.840.10045.3.0.7",  new Vector() {{add("c2tnb191v3");}});
       ecOIDs.put( "1.2.840.10045.3.0.10", new Vector() {{add("c2pnb208w1");}});
       ecOIDs.put( "1.2.840.10045.3.0.11", new Vector() {{add("c2tnb239v1");}});
       ecOIDs.put( "1.2.840.10045.3.0.12", new Vector() {{add("c2tnb239v2");}});
       ecOIDs.put( "1.2.840.10045.3.0.13", new Vector() {{add("c2tnb239v3");}});
       ecOIDs.put( "1.2.840.10045.3.0.16", new Vector() {{add("c2pnb272w1");}});
       ecOIDs.put( "1.2.840.10045.3.0.17", new Vector() {{add("c2pnb304w1");}});
       ecOIDs.put( "1.2.840.10045.3.0.19", new Vector() {{add("c2pnb368w1");}});
       ecOIDs.put( "1.2.840.10045.3.0.20", new Vector() {{add("c2tnb431r1");}});
       ecOIDs.put( "1.3.132.0.6",          new Vector() {{add("secp112r1");}});
       ecOIDs.put( "1.3.132.0.7",          new Vector() {{add("secp112r2");}});
       ecOIDs.put( "1.3.132.0.28",         new Vector() {{add("secp128r1");}});
       ecOIDs.put( "1.3.132.0.29",         new Vector() {{add("secp128r2");}});
       ecOIDs.put( "1.3.132.0.4",          new Vector() {{add("sect113r1");}});
       ecOIDs.put( "1.3.132.0.5",          new Vector() {{add("sect113r2");}});
       ecOIDs.put( "1.3.132.0.22",         new Vector() {{add("sect131r1");}});
       ecOIDs.put( "1.3.132.0.23",         new Vector() {{add("sect131r2");}});
    }

    /*
     * encodes cert
     */
 // private static BASE64Encoder mEncoder = new BASE64Encoder();
    public static String toMIME64(X509CertImpl cert) {
        try {
            return
                    "-----BEGIN CERTIFICATE-----\n"
                //  + mEncoder.encodeBuffer(cert.getEncoded())
                    + com.netscape.osutil.OSUtil.BtoA( cert.getEncoded() )
                    + "-----END CERTIFICATE-----\n";
        } catch (Exception e) {}
        return null;
    }
                                                                                
    public static boolean arraysEqual(byte[] bytes, byte[] ints) {
        if (bytes == null || ints == null) {
            return false;
        }
                                                                                
        if (bytes.length != ints.length) {
            return false;
        }
                                                                                
        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] != ints[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Retrieves handle to a JSS token.
     */
    public static CryptoToken getTokenByName(String token)
        throws CryptoManager.NotInitializedException,
                NoSuchTokenException {
        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken t = null;

        if (token.equals("internal")) {
            t = cm.getInternalKeyStorageToken();
        } else {
            t = cm.getTokenByName(token);
        }
        return t;
    }

    /**
     * Generates a RSA key pair.
     */
    public static KeyPair generateRSAKeyPair(String token, int keysize)
        throws CryptoManager.NotInitializedException,
                NoSuchTokenException,
                NoSuchAlgorithmException,
                TokenException {
        CryptoToken t = getTokenByName(token);
        KeyPairGenerator g = t.getKeyPairGenerator(KeyPairAlgorithm.RSA);

        g.initialize(keysize);
        KeyPair pair = g.genKeyPair();

        return pair;
    }

    public static boolean isECCKey(X509Key key) 
    {
        String keyAlgo = key.getAlgorithm();
         if (keyAlgo.equals("EC") ||
                keyAlgo.equals("OID.1.2.840.10045.44")) { // ECC
             return true;
         }
         return false;
    }

    /**
     * Generates an ecc key pair.
     */
    public static KeyPair generateECCKeyPair(String token, int keysize)
        throws CryptoManager.NotInitializedException,
                NoSuchTokenException,
                NoSuchAlgorithmException,
                TokenException {
        return generateECCKeyPair(token, keysize, null, null);
    }

    public static KeyPair generateECCKeyPair(String token, int keysize,
           org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usage_ops,
           org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usage_mask)
        throws CryptoManager.NotInitializedException,
                NoSuchTokenException,
                NoSuchAlgorithmException,
                TokenException {
        return generateECCKeyPair(token, keysize, usage_ops, usage_mask,
            false, -1, -1);
    }

    /*
     * temporary, sensitive, and extractable usages are per defined in
     * JSS pkcs11/PK11KeyPairGenerator.java
     */
    public static KeyPair generateECCKeyPair(String token, int keysize,
           org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usage_ops,
           org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usage_mask,
           boolean temporary, int sensitive, int extractable)
        throws CryptoManager.NotInitializedException,
                NoSuchTokenException,
                NoSuchAlgorithmException,
                TokenException {
        CryptoToken t = getTokenByName(token);

        KeyPairAlgorithm alg = KeyPairAlgorithm.EC;
        KeyPairGenerator keygen = t.getKeyPairGenerator(alg);

        keygen.setKeyPairUsages(usage_ops, usage_mask);
        keygen.temporaryPairs(temporary);

        if (sensitive == 1 )
            keygen.sensitivePairs(true);
        else if (sensitive == 0)
            keygen.sensitivePairs(false);

        if (extractable == 1 )
            keygen.extractablePairs(true);
        else if (extractable == 0)
            keygen.extractablePairs(false);

        keygen.initialize(keysize);

        KeyPair pair = keygen.genKeyPair();

        return pair;
    }

    /**
     * Generates an ecc key pair by curve name
     */
    public static KeyPair generateECCKeyPair(String token, String curveName)
        throws CryptoManager.NotInitializedException,
                NoSuchTokenException,
                NoSuchAlgorithmException,
                TokenException {
        return generateECCKeyPair(token, curveName, null, null);
    }

    public static KeyPair generateECCKeyPair(CryptoToken token, String curveName)
        throws CryptoManager.NotInitializedException,
                NoSuchTokenException,
                NoSuchAlgorithmException,
                TokenException {
        return generateECCKeyPair(token, curveName, null, null);
    }

    public static KeyPair generateECCKeyPair(String token, String curveName,
           org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usage_ops,
           org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usage_mask)
        throws CryptoManager.NotInitializedException,
                NoSuchTokenException,
                NoSuchAlgorithmException,
                TokenException {
        CryptoToken t = getTokenByName(token);
        return generateECCKeyPair(t, curveName, usage_ops, usage_mask);
    }

    public static KeyPair generateECCKeyPair(String token, String curveName,
           org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usage_ops,
           org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usage_mask,
           boolean temporary, int sensitive, int extractable)
        throws CryptoManager.NotInitializedException,
                NoSuchTokenException,
                NoSuchAlgorithmException,
                TokenException {
        CryptoToken t = getTokenByName(token);
        return generateECCKeyPair(t, curveName, usage_ops, usage_mask,
            temporary, sensitive, extractable);
    }

    public static KeyPair generateECCKeyPair(CryptoToken token, String curveName,
           org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usage_ops,
           org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usage_mask)
        throws CryptoManager.NotInitializedException,
                NoSuchTokenException,
                NoSuchAlgorithmException,
                TokenException {
        return generateECCKeyPair(token, curveName, usage_ops, usage_mask,
            false, -1, -1);
    }

    /*
     * temporary, sensitive, and extractable usages are per defined in
     * JSS pkcs11/PK11KeyPairGenerator.java
     */
    public static KeyPair generateECCKeyPair(CryptoToken token, String curveName,
           org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usage_ops,
           org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usage_mask,
           boolean temporary, int sensitive, int extractable)
        throws CryptoManager.NotInitializedException,
                NoSuchTokenException,
                NoSuchAlgorithmException,
                TokenException {
        KeyPairAlgorithm alg = KeyPairAlgorithm.EC;
        KeyPairGenerator keygen = token.getKeyPairGenerator(alg);

        keygen.setKeyPairUsages(usage_ops, usage_mask);
        keygen.temporaryPairs(temporary);

        if (sensitive == 1 )
            keygen.sensitivePairs(true);
        else if (sensitive == 0)
            keygen.sensitivePairs(false);

        if (extractable == 1 )
            keygen.extractablePairs(true);
        else if (extractable == 0)
            keygen.extractablePairs(false);


        //System.out.println("CryptoUtil: generateECCKeyPair: curve = "+ curveName);
        int curveCode = 0;
        try {
            curveCode = keygen.getCurveCodeByName(curveName);
        } catch (Exception e) {
            //System.out.println("CryptoUtil: generateECCKeyPair: "+ e.toString());
            throw new NoSuchAlgorithmException();
        }
        keygen.initialize(curveCode);

        //System.out.println("CryptoUtil: generateECCKeyPair: after KeyPairGenerator initialize with:"+ curveName);
        KeyPair pair = keygen.genKeyPair();

        return pair;
    }

    public static byte[] getModulus(PublicKey pubk) {
        RSAPublicKey rsaKey = (RSAPublicKey) pubk;

        return rsaKey.getModulus().toByteArray();
    }

    public static byte[] getPublicExponent(PublicKey pubk) {
        RSAPublicKey rsaKey = (RSAPublicKey) pubk;

        return rsaKey.getPublicExponent().toByteArray();
    }

    public static String base64Encode(byte[] bytes) throws IOException {
        // All this streaming is lame, but Base64OutputStream needs a
        // PrintStream
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Base64OutputStream b64 = new Base64OutputStream(new
                PrintStream(new
                FilterOutputStream(output)));
                                                                                
        b64.write(bytes);
        b64.flush();
                                                                                
        // This is internationally safe because Base64 chars are
        // contained within 8859_1
        return output.toString("8859_1");
    }
                                                                                
    public static byte[] base64Decode(String s) throws IOException {
     // BASE64Decoder base64 = new BASE64Decoder();
     // byte[] d = base64.decodeBuffer(s);
        byte[] d = com.netscape.osutil.OSUtil.AtoB( s );
                                                                                
        return d;
    }

    /*
     * formats a cert request
     */
    public static String reqFormat(String content) {
        int beginIndex = CERTREQ_BEGIN_HEADING.length();
        int endIndex = CERTREQ_END_HEADING.length();
                                                                                
        String result = CERTREQ_BEGIN_HEADING + "\n";
        int index = 0;
                                                                                
        while (content.length() >= LINE_COUNT) {
            result = result + content.substring(0, LINE_COUNT) + "\n";
            content = content.substring(LINE_COUNT);
        }
        if (content.length() > 0) {
            result = result + content + "\n" + CERTREQ_END_HEADING;
        } else {
            result = result + CERTREQ_END_HEADING;
        }
                                                                                
        return result;
    }
                                                                                
    public static String getPKCS10FromKey(String dn, 
                    byte modulus[], byte exponent[], byte prikdata[])
              throws IOException,
                     InvalidKeyException,
                     TokenException,
                     NoSuchProviderException,
                     CertificateException,
                     SignatureException,
                     CryptoManager.NotInitializedException,
                     NoSuchAlgorithmException
    {
        X509Key x509key = getPublicX509Key(modulus, exponent);
        PrivateKey prik = findPrivateKeyFromID(prikdata);
        PKCS10 pkcs10 = createCertificationRequest(dn, x509key, prik);
        ByteArrayOutputStream bs = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(bs);
        pkcs10.print(ps);
        return bs.toString();
    }

    public static String getPKCS10FromKey(String dn, 
                    byte modulus[], byte exponent[], byte prikdata[], String alg)
              throws IOException,
                     InvalidKeyException,
                     TokenException,
                     NoSuchProviderException,
                     CertificateException,
                     SignatureException,
                     CryptoManager.NotInitializedException,
                     NoSuchAlgorithmException
    {
        X509Key x509key = getPublicX509Key(modulus, exponent);
        PrivateKey prik = findPrivateKeyFromID(prikdata);
        PKCS10 pkcs10 = createCertificationRequest(dn, x509key, prik, alg);
        ByteArrayOutputStream bs = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(bs);
        pkcs10.print(ps);
        return bs.toString();
    }

    /*
     * formats a cert
     */
    public static String certFormat(String content) {
        if (content == null || content.length() == 0) {
            return "";
        }
        int beginIndex = CERT_BEGIN_HEADING.length();
        int endIndex = CERT_END_HEADING.length();
                                                                                
        String result = CERT_BEGIN_HEADING + "\n";
        int index = 0;
                                                                                
        while (content.length() >= LINE_COUNT) {
            result = result + content.substring(0, LINE_COUNT) + "\n";
            content = content.substring(LINE_COUNT);
        }
        if (content.length() > 0) {
            result = result + content + "\n" + CERT_END_HEADING;
        } else {
            result = result + CERT_END_HEADING;
        }
                                                                                
        return result;
    }

    /**
     * strips out the begin and end certificate brackets
     * @param s the string potentially bracketed with
     * "-----BEGIN CERTIFICATE-----" and "-----END CERTIFICATE-----"
     * @return string without the brackets
     */
    public static String stripCertBrackets(String s) {
        if (s == null) {
            return s;
        }
                                                                                
        if (s.startsWith(CERT_BEGIN_HEADING) && s.endsWith(CERT_END_HEADING)) {
            return (s.substring(27, (s.length() - 25)));
        }
                                                                                
        // To support Thawte's header and footer
        if ((s.startsWith("-----BEGIN PKCS #7 SIGNED DATA-----"))
                && (s.endsWith("-----END PKCS #7 SIGNED DATA-----"))) {
            return (s.substring(35, (s.length() - 33)));
        }
                                                                                
        return s;
    }

    public static String normalizeCertAndReq(String s) {
        if (s == null) {
            return s;
        }
        s = s.replaceAll("-----BEGIN CERTIFICATE REQUEST-----", "");
        s = s.replaceAll("-----BEGIN NEW CERTIFICATE REQUEST-----", "");
        s = s.replaceAll("-----END CERTIFICATE REQUEST-----", "");
        s = s.replaceAll("-----END NEW CERTIFICATE REQUEST-----", "");
        s = s.replaceAll("-----BEGIN CERTIFICATE-----", "");
        s = s.replaceAll("-----END CERTIFICATE-----", "");
                                                                                
        StringBuffer sb = new StringBuffer();
        StringTokenizer st = new StringTokenizer(s, "\r\n ");
                                                                                
        while (st.hasMoreTokens()) {
            String nextLine = st.nextToken();
                                                                                
            nextLine = nextLine.trim();
            if (nextLine.equals("-----BEGIN CERTIFICATE REQUEST-----")) {
                continue;
            }
            if (nextLine.equals("-----BEGIN NEW CERTIFICATE REQUEST-----")) {
                continue;
            }
            if (nextLine.equals("-----END CERTIFICATE REQUEST-----")) {
                continue;
            }
            if (nextLine.equals("-----END NEW CERTIFICATE REQUEST-----")) {
                continue;
            }
            if (nextLine.equals("-----BEGIN CERTIFICATE-----")) {
                continue;
            }
            if (nextLine.equals("-----END CERTIFICATE-----")) {
                continue;
            }
            sb.append(nextLine);
        }
        return sb.toString();
    }
                                                                                
    public static String normalizeCertStr(String s) {
        String val = "";
                                                                                
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '\n') {
                continue;
            } else if (s.charAt(i) == '\r') {
                continue;
            } else if (s.charAt(i) == '"') {
                continue;
            } else if (s.charAt(i) == ' ') {
                continue;
            }
            val += s.charAt(i);
        }
        return val;
    }

    public static void importCertificateChain(String certchain)
             throws IOException,
                    CryptoManager.NotInitializedException,
                    TokenException,
                    CertificateEncodingException,
                    CertificateException
    {
        byte[] blah = base64Decode(certchain);
        CryptoManager manager = CryptoManager.getInstance();
        PKCS7 pkcs7 = null;
        try {  
          // try PKCS7 first
          pkcs7 = new PKCS7(blah);
        } catch (Exception e) {
        }
        X509Certificate cert = null;
        if (pkcs7 == null) {
          cert = manager.importCACertPackage(blah);
        } else {
          java.security.cert.X509Certificate certsInP7[] = 
                pkcs7.getCertificates();
          if (certsInP7 == null) {
            cert = manager.importCACertPackage(blah);
          } else {
            for (int i = 0; i < certsInP7.length; i++) {
              // import P7 one by one
              cert = manager.importCACertPackage(certsInP7[i].getEncoded());
            }
          }
        }
        X509Certificate[] certchains = 
            CryptoManager.getInstance().buildCertificateChain(cert);
                                                                                
        if (certchains != null) {
          cert = certchains[certchains.length - 1];
        }
        InternalCertificate icert = (InternalCertificate) cert;
        icert.setSSLTrust( InternalCertificate.TRUSTED_CA
                                    | InternalCertificate.TRUSTED_CLIENT_CA
                                    | InternalCertificate.VALID_CA);
    }

    public static SEQUENCE parseCRMFMsgs(byte cert_request[])
               throws IOException, InvalidBERException
    {
        ByteArrayInputStream crmfBlobIn = 
              new ByteArrayInputStream(cert_request);
        SEQUENCE crmfMsgs = (SEQUENCE)
          new SEQUENCE.OF_Template(new CertReqMsg.Template()).decode(
                        crmfBlobIn);
        return crmfMsgs;
    }

    public static X509Key getX509KeyFromCRMFMsgs(SEQUENCE crmfMsgs) 
              throws IOException, NoSuchAlgorithmException, 
                  InvalidKeyException, InvalidKeyFormatException
    {
        int nummsgs = crmfMsgs.size();
        if (nummsgs <= 0) {
          throw new IOException("invalid certificate requests");
        }
        CertReqMsg msg = (CertReqMsg) crmfMsgs.elementAt(0);
        CertRequest certreq = msg.getCertReq();
        CertTemplate certTemplate = certreq.getCertTemplate();
        SubjectPublicKeyInfo spkinfo = certTemplate.getPublicKey();
        PublicKey pkey = spkinfo.toPublicKey();
        X509Key x509key = convertPublicKeyToX509Key(pkey);
        return x509key;
    }

    public static X509Key getPublicX509Key(byte modulus[], byte exponent[]) 
        throws InvalidKeyException {
        return new netscape.security.provider.RSAPublicKey(new BigInt(modulus),
                new BigInt(exponent));
    }

    public static X509Key getPublicX509ECCKey(byte encoded[])
        throws InvalidKeyException {
      try {
        return X509Key.parse(new DerValue(encoded));
      } catch (IOException e) {
        throw new InvalidKeyException();
      }
    }

    public static X509Key convertPublicKeyToX509Key(PublicKey pubk)
        throws InvalidKeyException {
        X509Key xKey;
                                                                                
        if (pubk instanceof RSAPublicKey) {
            RSAPublicKey rsaKey = (RSAPublicKey) pubk;
                                                                                
            xKey = new netscape.security.provider.RSAPublicKey(
                    new BigInt(rsaKey.getModulus()),
                    new BigInt(rsaKey.getPublicExponent()));
        } else if (pubk instanceof PK11ECPublicKey) {
            byte encoded[] = pubk.getEncoded();
            xKey = CryptoUtil.getPublicX509ECCKey(encoded);
        } else {
            // Assert.assert(pubk instanceof DSAPublicKey);
            DSAPublicKey dsaKey = (DSAPublicKey) pubk;
            DSAParams params = dsaKey.getParams();
                                                                                
            xKey = new netscape.security.provider.DSAPublicKey(dsaKey.getY(),
                    params.getP(), params.getQ(), params.getG());
        }
        return xKey;
    }

    public static String getSubjectName(SEQUENCE crmfMsgs) 
      throws IOException {
        int nummsgs = crmfMsgs.size();
        if (nummsgs <= 0) {
          throw new IOException("invalid certificate requests");
        }
        CertReqMsg msg = (CertReqMsg) crmfMsgs.elementAt(0);
        CertRequest certreq = msg.getCertReq();
        CertTemplate certTemplate = certreq.getCertTemplate();
        Name n = certTemplate.getSubject();
        ByteArrayOutputStream subjectEncStream = new ByteArrayOutputStream();
        n.encode(subjectEncStream);
        
        byte[] b = subjectEncStream.toByteArray();
        X500Name subject = new X500Name(b);
        return subject.toString();
    }

    /**
     * Creates a Certificate template.
     */
	public static X509CertInfo createX509CertInfo(KeyPair pair,
			BigInteger serialno, String issuername, String subjname,
			Date notBefore, Date notAfter) throws IOException,
			CertificateException, InvalidKeyException {
        return createX509CertInfo(convertPublicKeyToX509Key(pair.getPublic()), 
                serialno, issuername, subjname, notBefore, notAfter);
    }

	public static X509CertInfo createX509CertInfo(PublicKey publickey,
			BigInteger serialno, String issuername, String subjname,
			Date notBefore, Date notAfter) throws IOException,
			CertificateException, InvalidKeyException {
        return createX509CertInfo(convertPublicKeyToX509Key(publickey), serialno,
                issuername, subjname, notBefore, notAfter);
    }

	public static X509CertInfo createX509CertInfo(X509Key x509key,
			BigInteger serialno, String issuername, String subjname,
			Date notBefore, Date notAfter) throws IOException,
			CertificateException, InvalidKeyException {
        // set default; use the other call with "alg" to set algorithm
        String alg = "SHA256withRSA";
        try {
        return createX509CertInfo (x509key, serialno, issuername, subjname, notBefore, notAfter, alg);
        } catch (NoSuchAlgorithmException ex) {
          // for those that calls the old call without alg
          throw new CertificateException("createX509CertInfo old call should not be here");
        }
    }

	public static X509CertInfo createX509CertInfo(X509Key x509key,
			BigInteger serialno, String issuername, String subjname,
			Date notBefore, Date notAfter, String alg) throws IOException,
			CertificateException, InvalidKeyException, NoSuchAlgorithmException {
        X509CertInfo info = new X509CertInfo();

        info.set(X509CertInfo.VERSION, new
                CertificateVersion(CertificateVersion.V3));
        info.set(X509CertInfo.SERIAL_NUMBER, new
                CertificateSerialNumber(serialno));
        info.set(X509CertInfo.ISSUER, new
                CertificateIssuerName(new X500Name(issuername)));
        info.set(X509CertInfo.SUBJECT, new
                CertificateSubjectName(new X500Name(subjname)));
        info.set(X509CertInfo.VALIDITY, new
                CertificateValidity(notBefore, notAfter));
        AlgorithmId sigAlgId = new AlgorithmId();

        info.set(X509CertInfo.ALGORITHM_ID, new
                CertificateAlgorithmId(sigAlgId.get(alg)));
        info.set(X509CertInfo.KEY, new CertificateX509Key(x509key));
        info.set(X509CertInfo.EXTENSIONS, new CertificateExtensions());
        return info;
    }


    public static X509CertImpl signECCCert(PrivateKey privateKey, 
            X509CertInfo certInfo)
        throws NoSuchTokenException, 
                CryptoManager.NotInitializedException,
                NoSuchAlgorithmException,
                NoSuchTokenException,
                TokenException,
                InvalidKeyException,
                SignatureException,
                IOException,
                CertificateException
    {
        // set default; use the other call with "alg" to specify algorithm
        String alg = "SHA256withEC";
        return signECCCert(privateKey, certInfo, alg);
    }

    public static X509CertImpl signECCCert(PrivateKey privateKey, 
            X509CertInfo certInfo, String alg)
        throws NoSuchTokenException, 
                CryptoManager.NotInitializedException,
                NoSuchAlgorithmException,
                NoSuchTokenException,
                TokenException,
                InvalidKeyException,
                SignatureException,
                IOException,
                CertificateException
    {
       return signCert(privateKey, certInfo, 
                Cert.mapAlgorithmToJss(alg));
    }

    /**
     * Signs certificate.
     */
    public static X509CertImpl signCert(PrivateKey privateKey, 
            X509CertInfo certInfo, String alg)
        throws NoSuchTokenException, 
                CryptoManager.NotInitializedException,
                NoSuchAlgorithmException,
                NoSuchTokenException,
                TokenException,
                InvalidKeyException,
                SignatureException,
                IOException,
                CertificateException {
        return signCert (privateKey, certInfo,
                 Cert.mapAlgorithmToJss(alg));
    }

    public static X509CertImpl signCert(PrivateKey privateKey, 
            X509CertInfo certInfo, SignatureAlgorithm sigAlg)
        throws NoSuchTokenException, 
                CryptoManager.NotInitializedException,
                NoSuchAlgorithmException,
                NoSuchTokenException,
                TokenException,
                InvalidKeyException,
                SignatureException,
                IOException,
                CertificateException {

        DerInputStream ds = new DerInputStream(ASN1Util.encode(sigAlg.toOID()));
        ObjectIdentifier sigAlgOID = new ObjectIdentifier(ds);
        AlgorithmId aid = new AlgorithmId(sigAlgOID);
        certInfo.set(X509CertInfo.ALGORITHM_ID, 
               new CertificateAlgorithmId(aid));
                                                                                
        org.mozilla.jss.crypto.PrivateKey priKey = 
              (org.mozilla.jss.crypto.PrivateKey) privateKey;
        CryptoToken token = priKey.getOwningToken();
                                                                                
        DerOutputStream tmp = new DerOutputStream();
        DerOutputStream out = new DerOutputStream();
                                                                                
        certInfo.encode(tmp);
        Signature signer = token.getSignatureContext(sigAlg);
                                                                                
        signer.initSign(priKey);
        signer.update(tmp.toByteArray());
        byte signed[] = signer.sign();
                                                                                
        aid.encode(tmp);
        tmp.putBitString(signed);
        out.write(DerValue.tag_Sequence, tmp);
        X509CertImpl signedCert = new X509CertImpl(out.toByteArray());
                                                                                
        return signedCert;
    }

    /**
     * Creates a PKCS#10 request.
     */
    public static PKCS10 createCertificationRequest(String subjectName,
            X509Key pubk, PrivateKey prik)
        throws NoSuchAlgorithmException, NoSuchProviderException,
                InvalidKeyException, IOException, CertificateException,
                SignatureException {
        // give default
        String alg = "SHA256withRSA";
        if (isECCKey(pubk)) {
          alg = "SHA256withEC";
        }
        return createCertificationRequest(subjectName, pubk, prik, alg);
    }

    public static PKCS10 createCertificationRequest(String subjectName,
            X509Key pubk, PrivateKey prik, String alg)
        throws NoSuchAlgorithmException, NoSuchProviderException,
                InvalidKeyException, IOException, CertificateException,
                SignatureException {
        X509Key key = pubk;
        java.security.Signature sig = java.security.Signature.getInstance(alg,
                "Mozilla-JSS");

        sig.initSign(prik);
        PKCS10 pkcs10 = new PKCS10(key);
        X500Name name = new X500Name(subjectName);
        X500Signer signer = new X500Signer(sig, name);

        pkcs10.encodeAndSign(signer);
        return pkcs10;
    }

    /**
     * Creates a PKCS#10 request
     * (injecting the specified Certificate Extensions into the request)
     *
     *     NOTE:  This code was inspired by the
     *            'getCertRequest(String subjectName, KeyPair keyPair,
     *             Extensions exts)' method of 'KeyCertUtil.java'.
     *
     *  03/27/2013 - The following attempt to embed a certificate
     *               extension into a PKCS #10 certificate request
     *               was abandoned since we were unable to successfully
     *               convert the certificate extension into a PKCS #10
     *               attribute.  What was generated was an improper
     *               PKCS #10 certificate request. - mlh
     *
     */
//  public static PKCS10 createCertificationRequest(String subjectName,
//          X509Key pubk, PrivateKey prik, String alg,
//          CertificateExtensions exts)
//      throws NoSuchAlgorithmException, NoSuchProviderException,
//              InvalidKeyException, IOException, CertificateException,
//              SignatureException {
//      X509Key key = pubk;
//      java.security.Signature sig = java.security.Signature.getInstance(alg,
//              "Mozilla-JSS");
//
//      sig.initSign(prik);
//      PKCS10 pkcs10 = null;
//      if (exts != null) {
//          PKCS10Attribute attr = new
//              PKCS10Attribute(PKCS9Attribute.EXTENSION_REQUEST_OID,
//                  (CertAttrSet) exts);
//          PKCS10Attributes attrs = new PKCS10Attributes();
//          attrs.setAttribute(attr.getAttributeValue().getName(), attr);
//          pkcs10 = new PKCS10(key, attrs);
//      } else {
//          pkcs10 = new PKCS10(key);
//      }
//      X500Name name = new X500Name(subjectName);
//      X500Signer signer = new X500Signer(sig, name);
//
//      pkcs10.encodeAndSign(signer);
//      return pkcs10;
//  }

    /**
     * Creates a PKCS#10 request.
     */
    public static PKCS10 createCertificationRequest(String subjectName,
            KeyPair keyPair)
        throws NoSuchAlgorithmException, NoSuchProviderException,
                InvalidKeyException, IOException, CertificateException,
                SignatureException {
        String alg;
        PublicKey pubk = keyPair.getPublic();
        X509Key key = convertPublicKeyToX509Key(pubk);
        if (pubk instanceof RSAPublicKey) {
            alg = "SHA256withRSA";
        } else if (isECCKey(key)) {
            alg = "SHA256withEC";
        } else {
            // Assert.assert(pubk instanceof DSAPublicKey);
            alg = "DSA";
        }
        return createCertificationRequest(subjectName,keyPair, alg);
    }

    public static PKCS10 createCertificationRequest(String subjectName,
            KeyPair keyPair, String alg)
        throws NoSuchAlgorithmException, NoSuchProviderException,
                InvalidKeyException, IOException, CertificateException,
                SignatureException {
        PublicKey pubk = keyPair.getPublic();
        X509Key key = convertPublicKeyToX509Key(pubk);
                                                                                
        java.security.Signature sig = java.security.Signature.getInstance(alg,
                "Mozilla-JSS");
                                                                                
        sig.initSign(keyPair.getPrivate());
                                                                                
        PKCS10 pkcs10 = new PKCS10(key);
                                                                                
        X500Name name = new X500Name(subjectName);
        X500Signer signer = new X500Signer(sig, name);
                                                                                
        pkcs10.encodeAndSign(signer);
                                                                                
        return pkcs10;
    }

    /**
     * Creates a PKCS#10 request
     * (injecting the specified Certificate Extensions into the request)
     *
     *     NOTE:  This code was inspired by the
     *            'getCertRequest(String subjectName, KeyPair keyPair,
     *             Extensions exts)' method of 'KeyCertUtil.java'.
     *
     *  03/27/2013 - The following attempt to embed a certificate
     *               extension into a PKCS #10 certificate request
     *               was abandoned since we were unable to successfully
     *               convert the certificate extension into a PKCS #10
     *               attribute.  What was generated was an improper
     *               PKCS #10 certificate request. - mlh
     *
     */
//  public static PKCS10 createCertificationRequest(String subjectName,
//          KeyPair keyPair, String alg, CertificateExtensions exts)
//      throws NoSuchAlgorithmException, NoSuchProviderException,
//              InvalidKeyException, IOException, CertificateException,
//              SignatureException {
//      PublicKey pubk = keyPair.getPublic();
//      X509Key key = convertPublicKeyToX509Key(pubk);
//
//      java.security.Signature sig = java.security.Signature.getInstance(alg,
//              "Mozilla-JSS");
//
//      sig.initSign(keyPair.getPrivate());
//
//      PKCS10 pkcs10 = null;
//      if (exts != null) {
//          PKCS10Attribute attr = new
//              PKCS10Attribute(PKCS9Attribute.EXTENSION_REQUEST_OID,
//                  (CertAttrSet) exts);
//          PKCS10Attributes attrs = new PKCS10Attributes();
//          attrs.setAttribute(attr.getAttributeValue().getName(), attr);
//          pkcs10 = new PKCS10(key, attrs);
//      } else {
//          pkcs10 = new PKCS10(key);
//      }
//
//      X500Name name = new X500Name(subjectName);
//      X500Signer signer = new X500Signer(sig, name);
//
//      pkcs10.encodeAndSign(signer);
//
//      return pkcs10;
//  }

    public static void unTrustCert(InternalCertificate cert) {
        // remove TRUSTED_CA
        int flag = cert.getSSLTrust();
                                                                                
        flag ^= InternalCertificate.VALID_CA;
        cert.setSSLTrust(flag);
    }
                                                                                
    /**
     * Trusts a certificate by nickname.
     */
    public static void trustCertByNickname(String nickname) 
        throws CryptoManager.NotInitializedException,
                TokenException {
        CryptoManager cm = CryptoManager.getInstance();
        X509Certificate certs[] = cm.findCertsByNickname(nickname);

        if (certs == null) {
            return;
        }
        for (int i = 0; i < certs.length; i++) {
            trustCert((InternalCertificate) certs[i]);
        }
    }

    /**
     * Trusts a certificate.
     */
    public static void trustCert(InternalCertificate cert) {
        int flag = InternalCertificate.VALID_CA | InternalCertificate.TRUSTED_CA
                | InternalCertificate.USER
                | InternalCertificate.TRUSTED_CLIENT_CA;
                                                                                
        cert.setSSLTrust(flag);
        cert.setObjectSigningTrust(flag);
        cert.setEmailTrust(flag);
    }
                                                                                
    /**
     * To certificate server point of view, SSL trust is
     * what we referring.
     */
    public static boolean isCertTrusted(InternalCertificate cert) {
        if (isTrust(cert.getSSLTrust()) && isTrust(cert.getObjectSigningTrust())
                && isTrust(cert.getEmailTrust())) {
            return true;
        } else {
            return false;
        }
    }
                                                                                
    public static boolean isTrust(int flag) {
        if (((flag & InternalCertificate.VALID_CA) > 0)
                && ((flag & InternalCertificate.TRUSTED_CA) > 0)
                && ((flag & InternalCertificate.USER) > 0)
                && ((flag & InternalCertificate.TRUSTED_CLIENT_CA) > 0)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Generates a symmetric key.
     */
    public static SymmetricKey generateKey(CryptoToken token,
            KeyGenAlgorithm alg)
        throws TokenException, NoSuchAlgorithmException,
                IllegalStateException {
        try {
            KeyGenerator kg = token.getKeyGenerator(alg);
                                                                                
            return kg.generate();
        } catch (CharConversionException e) {
            throw new RuntimeException(
                    "CharConversionException while generating symmetric key");
        }
    }

    /**
     * Compares 2 byte arrays to see if they are the same.
     */
    public static boolean compare(byte src[], byte dest[]) {
        if (src != null && dest != null) {
            if (src.length == dest.length) {
                boolean matched = true;

                for (int i = 0; i < src.length; i++) {
                    if (src[i] != dest[i]) {
                        matched = false;
                    }
                }
                if (matched) {
                    return true;
                }
            }
        }
        return false;
    }

    public static String byte2string(byte id[]) {
        return new BigInteger(id).toString(16);
    }

    public static byte[] string2byte(String id) {
        return (new BigInteger(id, 16)).toByteArray();
    }

    /**
     * Retrieves a private key from a unique key ID.
     */
    public static PrivateKey findPrivateKeyFromID(byte id[]) 
        throws CryptoManager.NotInitializedException,
                TokenException {
        CryptoManager cm = CryptoManager.getInstance();
        Enumeration enums = cm.getAllTokens();

        while (enums.hasMoreElements()) {
            CryptoToken token = (CryptoToken) enums.nextElement();
            String tokenName = token.getName();
            CryptoStore store = token.getCryptoStore();
            PrivateKey keys[] = store.getPrivateKeys(); 

            if (keys != null) {
                for (int i = 0; i < keys.length; i++) {
                    if (compare(keys[i].getUniqueID(), id)) {
                        return keys[i];
                    }
                }
            }
        }
        return null;
    }

    /**
     * Retrieves all user certificates from all tokens.
     */
    public static X509CertImpl[] getAllUserCerts()
        throws CryptoManager.NotInitializedException,
                TokenException {
        Vector certs = new Vector();
        CryptoManager cm = CryptoManager.getInstance();
        Enumeration enums = cm.getAllTokens();

        while (enums.hasMoreElements()) {
            CryptoToken token = (CryptoToken) enums.nextElement();
            String tokenName = token.getName();
                                                                                
            CryptoStore store = token.getCryptoStore();
            org.mozilla.jss.crypto.X509Certificate list[] = store.getCertificates();
                                                                               
            for (int i = 0; i < list.length; i++) {
                try {
                    PrivateKey key = cm.findPrivKeyByCert(list[i]);
                    X509CertImpl impl = null;

                    try {
                        impl = new X509CertImpl(list[i].getEncoded());
                    } catch (CertificateException e) {
                        continue;
                    }
                    certs.addElement(impl);
                } catch (TokenException e) {
                    continue;
                } catch (ObjectNotFoundException e) {
                    continue;
                }
            }
        }
        if (certs.size() == 0) {
            return null;
        } else {
            X509CertImpl c[] = new X509CertImpl[certs.size()];

            certs.copyInto(c);
            return c;
        }
    }

    /**
     * Deletes a private key.
     */
    public static void deletePrivateKey(PrivateKey prikey)
        throws CryptoManager.NotInitializedException, TokenException {
        CryptoManager cm = CryptoManager.getInstance();

        try {
            CryptoToken token = prikey.getOwningToken();
            CryptoStore store = token.getCryptoStore();

            store.deletePrivateKey(prikey);
        } catch (NoSuchItemOnTokenException e) {}
    }

    /**
     * Retrieves a private key by nickname.
     */
    public static PrivateKey getPrivateKey(String nickname)
        throws CryptoManager.NotInitializedException, TokenException {
        try {
            CryptoManager cm = CryptoManager.getInstance();
            X509Certificate cert = cm.findCertByNickname(nickname);
            org.mozilla.jss.crypto.PrivateKey prikey = cm.findPrivKeyByCert(cert);

            return prikey;
        } catch (ObjectNotFoundException e) {}
        return null;
    }

    /**
     * Deletes all certificates by a nickname.
     */
    public static void deleteAllCertificates(String nickname)
        throws CryptoManager.NotInitializedException, TokenException {
        CryptoManager cm = CryptoManager.getInstance();
        X509Certificate certs[] = cm.findCertsByNickname(nickname);

        if (certs == null) {
            return;
        }
        for (int i = 0; i < certs.length; i++) {
            try {
                X509Certificate cert = certs[i];
                org.mozilla.jss.crypto.PrivateKey prikey = cm.findPrivKeyByCert(
                        cert);
                CryptoToken token = prikey.getOwningToken();
                CryptoStore store = token.getCryptoStore();

                store.deleteCert(cert);
            } catch (NoSuchItemOnTokenException e) {} catch (ObjectNotFoundException e) {}
        }
    }

    /**
     * Imports a PKCS#7 certificate chain that includes the user 
     * certificate, and trusts the certificate.
     */
    public static X509Certificate importUserCertificateChain(String c, 
            String nickname)
        throws CryptoManager.NotInitializedException, 
                CryptoManager.NicknameConflictException, 
                CryptoManager.UserCertConflictException,
                NoSuchItemOnTokenException,
                TokenException,
                CertificateEncodingException {
        CryptoManager cm = CryptoManager.getInstance();
        X509Certificate cert = cm.importCertPackage(c.getBytes(), nickname);

        trustCertByNickname(nickname);
        return cert;
    }

    /**
     * Imports a user certificate, and trusts the certificate.
     */
    public static void importUserCertificate(X509CertImpl cert, String nickname)
        throws CryptoManager.NotInitializedException,
                CertificateEncodingException,
                NoSuchItemOnTokenException,
                TokenException,
                CryptoManager.NicknameConflictException,
                CryptoManager.UserCertConflictException {
        CryptoManager cm = CryptoManager.getInstance();

        cm.importUserCACertPackage(cert.getEncoded(), nickname);
        trustCertByNickname(nickname);
    }

    public static void importUserCertificate(X509CertImpl cert, String nickname,
      boolean trust)
        throws CryptoManager.NotInitializedException,
                CertificateEncodingException,
                NoSuchItemOnTokenException,
                TokenException,
                CryptoManager.NicknameConflictException,
                CryptoManager.UserCertConflictException {
        CryptoManager cm = CryptoManager.getInstance();

        cm.importUserCACertPackage(cert.getEncoded(), nickname);
        if (trust)
            trustCertByNickname(nickname);
    }

    public static java.security.cert.X509Certificate[] getX509CertificateFromPKCS7(byte[] b) throws IOException {
        ByteArrayInputStream bis = new ByteArrayInputStream(b);
        CertificateChain certchain = new CertificateChain();

        certchain.decode(bis);
        java.security.cert.X509Certificate[] certs = certchain.getChain(); 

        return certs;
    }

    public static String[] getECcurves() {
        return ecCurves;
    }

    public static Vector getECKeyCurve(X509Key key) throws Exception {
        AlgorithmId algid = key.getAlgorithmId();
        //System.out.println("CryptoUtil: getECKeyCurve: algid ="+ algid);

        /*
         * Get raw string representation of alg parameters, will give 
         * us the curve OID.
         */
        String params =  null;
        if (algid != null) {
            params = algid.getParametersString();
        }

        if ((params != null) && (params.startsWith("OID."))) {
            params = params.substring(4);
        }

        //System.out.println("CryptoUtil: getECKeyCurve: EC key OID ="+ params);
        Vector vect = ecOIDs.get(params);

        return vect;
    }
}


// START ENABLE_ECC
// This following can be removed when JSS with ECC capability 
// is integrated.
class CryptoAlgorithm extends Algorithm
{
    protected CryptoAlgorithm(int oidIndex, String name) {
        super(oidIndex, name);
    }
}

class CryptoKeyPairAlgorithm extends KeyPairAlgorithm
{
    protected CryptoKeyPairAlgorithm(int oidIndex, String name, Algorithm algFamily) {        super(oidIndex, name, algFamily);
    }
}

class CryptoSignatureAlgorithm extends SignatureAlgorithm
{
    protected CryptoSignatureAlgorithm(int oidIndex, String name,
        SignatureAlgorithm signingAlg, DigestAlgorithm digestAlg,
        OBJECT_IDENTIFIER oid)
    {
        super(oidIndex, name, signingAlg, digestAlg, oid);
    }
}
// END ENABLE_ECC
