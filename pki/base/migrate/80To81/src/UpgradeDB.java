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
// (C) 2011 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---


import netscape.ldap.*;
import java.io.*;
import java.util.*;
import java.text.*;


/**
 * This class provides in-place upgrade of internal DBs for all PKI subsystems
 * from CS version 8.0 to 8.1.
 * RHCS 8.0 was released with redhat-ds-base-8.1.0-0.14.el5dsrv
 */
public class UpgradeDB {

    private static LDAPConnection lc = null;
    private static int errorCode = LDAPException.SUCCESS;
    private static String bindDN = null;
    private static String bindPW = null;
    private static String hostname = "localhost";
    private static String logFileName = "upgrade_db.log";
    private static int port = 389;
    private static String[] namingContext = null;
    private static Hashtable<String, byte[]> ht = null;
    private static BufferedWriter writer = null;
    private static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");


    /* old and new values for attributes and objects */

    private static final int newMaxBerSize = 209715200;

    private static final String oldDescription =
        "People who manage the Fedora Certificate System";
    private static final String newDescription =
        "People who manage the Certificate System";

    private static final String oldCertificateRecord =
        "( certificateRecord-oid NAME 'certificateRecord' DESC 'CMS defined class'"+
        " SUP top STRUCTURAL MUST cn MAY ( serialno $ dateOfCreate $ dateOfModify"+
        " $ certStatus $ autoRenew $ issueInfo $ metaInfo $ revInfo $ version"+
        " $ duration $ notAfter $ notBefore $ algorithmId $ subject $ subjectName"+
        " $ signingAlgorithmId $ userCertificate $ issuedBy $ revokedBy $ revokedOn"+
        " $ extension $ publicKeyData $ issuerName ) X-ORIGIN 'user defined' )";
    private static final String newCertificateRecord =
        "( certificateRecord-oid NAME 'certificateRecord' DESC 'CMS defined class'"+
        " SUP top STRUCTURAL MUST cn MAY ( serialno $ dateOfCreate $ dateOfModify"+
        " $ certStatus $ autoRenew $ issueInfo $ metaInfo $ revInfo $ version"+
        " $ duration $ notAfter $ notBefore $ algorithmId $ subjectName"+
        " $ signingAlgorithmId $ userCertificate $ issuedBy $ revokedBy $ revokedOn"+
        " $ extension $ publicKeyData $ issuerName ) X-ORIGIN 'user defined' )";

    private static final String newPublishingStatus =
        "( publishingStatus-oid NAME 'publishingStatus' DESC 'CMS defined attribute'"+
        " SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'user defined' )";

    private static final String newRepository =
        "( repository-oid NAME 'repository' DESC 'CMS defined class'"+
        " SUP top STRUCTURAL MUST ou MAY ( serialno $ description $ nextRange"+
        " $ publishingStatus ) X-ORIGIN 'user defined' )";

    private static final String oldDeltaCRLAttribute =
        "( deltaCRL-oid NAME 'deltaCRL' DESC 'CMS defined attribute'"+
        " SYNTAX 1.3.6.1.4.1.1466.115.121.1.5 X-ORIGIN 'user defined' )";
    private static final String newDeltaCRLObjectClass =
        "( deltaCRL-oid NAME 'deltaCRL' DESC 'CMS defined class'"+
        " SUP top AUXILIARY MAY deltaRevocationList X-ORIGIN 'user defined' )";

    private static final String oldCrlIssuingPointRecord =
        "( crlIssuingPointRecord-oid NAME 'crlIssuingPointRecord' DESC 'CMS defined class'"+
        " SUP top STRUCTURAL MUST cn MAY ( dateOfCreate $ dateOfModify $ crlNumber $ crlSize"+
        " $ thisUpdate $ nextUpdate $ deltaNumber $ deltaSize $ firstUnsaved $ certificateRevocationList"+
        " $ deltaCRL $ crlCache $ revokedCerts $ unrevokedCerts $ expiredCerts $ cACertificate )"+
        " X-ORIGIN 'user defined' )";
    private static final String oldCrlIssuingPointRecordWithOutDeltaCRL =
        "( crlIssuingPointRecord-oid NAME 'crlIssuingPointRecord' DESC 'CMS defined class'"+
        " SUP top STRUCTURAL MUST cn MAY ( dateOfCreate $ dateOfModify $ crlNumber $ crlSize"+
        " $ thisUpdate $ nextUpdate $ deltaNumber $ deltaSize $ firstUnsaved $ certificateRevocationList"+
        " $ crlCache $ revokedCerts $ unrevokedCerts $ expiredCerts $ cACertificate )"+
        " X-ORIGIN 'user defined' )";
    private static final String newCrlIssuingPointRecord =
        "( crlIssuingPointRecord-oid NAME 'crlIssuingPointRecord' DESC 'CMS defined class'"+
        " SUP top STRUCTURAL MUST cn MAY ( dateOfCreate $ dateOfModify $ crlNumber $ crlSize"+
        " $ thisUpdate $ nextUpdate $ deltaNumber $ deltaSize $ firstUnsaved $ certificateRevocationList"+
        " $ deltaRevocationList $ crlCache $ revokedCerts $ unrevokedCerts $ expiredCerts $ cACertificate )"+
        " X-ORIGIN 'user defined' )";

    private static final String newPkiCA =
        "( pkiCA-oid NAME 'pkiCA' DESC 'CMS defined class' SUP top AUXILIARY MAY"+
        " ( cACertificate $ certificateRevocationList $ authorityRevocationList"+
        " $ crossCertificatePair ) X-ORIGIN 'user defined' )";

    private static final String newSecureEEClientAuthPort =
        "( SecureEEClientAuthPort-oid NAME 'SecureEEClientAuthPort'"+
        "  SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE X-ORIGIN 'user defined' )";
        // 2 spaces
    private static final String oldPkiSubsystem =
        "( pkiSubsystem-oid NAME 'pkiSubsystem' DESC 'CMS defined class'"+
        " SUP top STRUCTURAL MUST ( cn $ Host $ SecurePort $ SubsystemName $ Clone )"+
        " MAY ( DomainManager $ SecureAgentPort $ SecureAdminPort"+
        " $ UnSecurePort ) X-ORIGIN 'user defined' )";
    private static final String newPkiSubsystem =
        "( pkiSubsystem-oid NAME 'pkiSubsystem' DESC 'CMS defined class'"+
        " SUP top STRUCTURAL MUST ( cn $ Host $ SecurePort $ SubsystemName $ Clone )"+
        " MAY ( DomainManager $ SecureAgentPort $ SecureAdminPort $SecureEEClientAuthPort"+
        " $ UnSecurePort ) X-ORIGIN 'user defined' )";

    private static final String newCmsUserGroup =
        "( cmsUserGroup-oid NAME 'cmsUserGroup' DESC 'CMS defined attribute'"+
        " SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'user defined' )";
    private static final String newSecurityDomainSessionEntry =
        "( securityDomainSessionEntry-oid NAME 'securityDomainSessionEntry'"+
        " DESC 'CMS defined class' SUP top STRUCTURAL MUST ( cn $ host $ uid"+
        " $ cmsUserGroup $ dateOfCreate ) X-ORIGIN 'user defined' )";

    /* CA's old and new values for resourceACLS attributes */

    private static final String[] oldCAresourceACLs = {
        "certServer.usrgrp.administration:read,modify:allow (read) group=\"Admi"+
        "nistrators\" || group=\"Auditors\" || group=\"Certificate Manager Agen"+
        "ts\" || group=\"Registration Manager Agents\" || group=\"Data Recovery"+
        " Manager Agents\" || group=\"Online Certificate Status Manager Agents"+
        "\";allow (modify) group=\"Administrators\":Administrators, auditors, a"+
        "nd agents are allowed to read user and group configuration but only ad"+
        "ministrators are allowed to modify",

        "certServer.general.configuration:read,modify,delete:allow (read) group"+
        "=\"Administrators\" || group=\"Auditors\" || group=\"Certificate Manag"+
        "er Agents\" || group=\"Registration Manager Agents\" || group=\"Data R"+
        "ecovery Manager Agents\" || group=\"Online Certificate Status Manager "+
        "Agents\";allow (modify,delete) group=\"Administrators\":Administrators"+
        ", auditors, and agents are allowed to read CMS general configuration b"+
        "ut only administrators are allowed to modify and delete",

        "certServer.policy.configuration:read,modify:allow (read) group=\"Admin"+
        "istrators\" || group=\"Certificate Manager Agents\" || group=\"Registr"+
        "ation Manager Agents\" || group=\"Data Recovery Manager Agents\" || gr"+
        "oup=\"Online Certificate Status Manager Agents\" || group=\"Auditors\""+
        ";allow (modify) group=\"Administrators\":Administrators, agents and au"+
        "ditors are allowed to read policy configuration but only administrator"+
        "s allowed to modify",

        "certServer.acl.configuration:read,modify:allow (read) group=\"Administ"+
        "rators\" || group=\"Certificate Manager Agents\" || group=\"Registrati"+
        "on Manager Agents\" || group=\"Data Recovery Manager Agents\" || group"+
        "=\"Online Certificate Status Manager Agents\" || group=\"Auditors\";al"+
        "low (modify) group=\"Administrators\":Administrators, agents and audit"+
        "ors are allowed to read ACL configuration but only administrators allo"+
        "wed to modify",

        "certServer.log.configuration:read,modify:allow (read) group=\"Administ"+
        "rators\" || group=\"Auditors\" || group=\"Certificate Manager Agents\""+
        " || group=\"Registration Manager Agents\" || group=\"Data Recovery Man"+
        "ager Agents\" || group=\"Online Certificate Status Manager Agents\";al"+
        "low (modify) group=\"Administrators\":Administrators, Agents, and audi"+
        "tors are allowed to read the log configuration but only administrators"+
        " are allowed to modify",

        "certServer.log.configuration.fileName:read,modify:allow (read) group="+
        "\"Administrators\" || group=\"Auditors\" || group=\"Certificate Manage"+
        "r Agents\" || group=\"Registration Manager Agents\" || group=\"Data Re"+
        "covery Manager Agents\" || group=\"Online Certificate Status Manager A"+
        "gents\";deny (modify) user=anybody:Nobody is allowed to modify a fileN"+
        "ame parameter",

        "certServer.log.configuration.signedAudit.expirationTime:read,modify:al"+
        "low (read) group=\"Administrators\" || group=\"Auditors\" || group=\"C"+
        "ertificate Manager Agents\" || group=\"Registration Manager Agents\" |"+
        "| group=\"Data Recovery Manager Agents\" || group=\"Online Certificate"+
        " Status Manager Agents\";deny (modify) user=anybody:Nobody is allowed "+
        "to modify an expirationTime parameter.",

        "certServer.log.content.signedAudit:read:deny (read) group=\"Administra"+
        "tors\" || group=\"Certificate Manager Agents\" || group=\"Registration"+
        " Manager Agents\" || group=\"Data Recovery Manager Agents\" || group="+
        "\"Online Certificate Status Manager Agents\":Only auditor is allowed t"+
        "o read the signed audit log",

        "certServer.log.content:read:allow (read) group=\"Administrators\" || g"+
        "roup=\"Certificate Manager Agents\" || group=\"Registration Manager Ag"+
        "ents\" || group=\"Data Recovery Manager Agents\" || group=\"Online Cer"+
        "tificate Status Manager Agents\" || group=\"Auditors\":Administrators,"+
        " auditors, and agents are allowed to read the log content",

        "certServer.ca.configuration:read,modify:allow (read) group=\"Administr"+
        "ators\" || group=\"Certificate Manager Agents\" || group=\"Registratio"+
        "n Manager Agents\" || group=\"Data Recovery Manager Agents\" || group="+
        "\"Online Certificate Status Manager Agents\" || group=\"Auditors\";all"+
        "ow (modify) group=\"Administrators\":Administrators, auditors, and age"+
        "nts are allowed to read CA configuration but only administrators allow"+
        "ed to modify",

        "certServer.auth.configuration:read,modify:allow (read) group=\"Adminis"+
        "trators\" || group=\"Certificate Manager Agents\" || group=\"Registrat"+
        "ion Manager Agents\" || group=\"Data Recovery Manager Agents\" || grou"+
        "p=\"Online Certificate Status Manager Agents\" || group=\"Auditors\";a"+
        "llow (modify) group=\"Administrators\":Administrators, agents, and aud"+
        "itors are allowed to read authentication configuration but only admini"+
        "strators allowed to modify",

        "certServer.ocsp.configuration:read,modify:allow (read) group=\"Adminis"+
        "trators\" || group=\"Certificate Manager Agents\" || group=\"Registrat"+
        "ion Manager Agents\" || group=\"Data Recovery Manager Agents\" || grou"+
        "p=\"Online Certificate Status Manager Agents\" || group=\"Auditors\";a"+
        "llow (modify) group=\"Administrators\":Administrators, Agents, and aud"+
        "itors are allowed to read ocsp configuration but only administrators a"+
        "llowed to modify",

        "certServer.registry.configuration:read,modify:allow (read) group=\"Adm"+
        "inistrators\" || group=\"Certificate Manager Agents\" || group=\"Regis"+
        "tration Manager Agents\" || group=\"Data Recovery Manager Agents\" || "+
        "group=\"Online Certificate Status Manager Agents\" || group=\"Auditors"+
        "\";allow (modify) group=\"Administrators\":this acl is shared by all a"+
        "dmin servlets",

        "certServer.profile.configuration:read,modify:allow (read) group=\"Admi"+
        "nistrators\" || group=\"Certificate Manager Agents\" || group=\"Regist"+
        "ration Manager Agents\" || group=\"Data Recovery Manager Agents\" || g"+
        "roup=\"Online Certificate Status Manager Agents\" || group=\"Auditors"+
        "\";allow (modify) group=\"Administrators\":Administrators, agents, and"+
        " auditors are allowed to read profile configuration but only administr"+
        "ators allowed to modify",

        "certServer.job.configuration:read,modify:allow (read) group=\"Administ"+
        "rators\" || group=\"Certificate Manager Agents\" || group=\"Registrati"+
        "on Manager Agents\" || group=\"Data Recovery Manager Agents\" || group"+
        "=\"Online Certificate Status Manager Agents\" || group=\"Auditors\";al"+
        "low (modify) group=\"Administrators\":Administrators, agents, and audi"+
        "tors are allowed to read job configuration but only administrators all"+
        "owed to modify",

        "certServer.publisher.configuration:read,modify:allow (read) group=\"Ad"+
        "ministrators\" || group=\"Auditors\" || group=\"Certificate Manager Ag"+
        "ents\" || group=\"Registration Manager Agents\" || group=\"Data Recove"+
        "ry Manager Agents\" || group=\"Online Certificate Status Manager Agent"+
        "s\";allow (modify) group=\"Administrators\":Administrators, auditors, "+
        "and agents are allowed to read publisher configuration but only admini"+
        "strators allowed to modify",

        "certServer.kra.configuration:read,modify:allow (read) group=\"Administ"+
        "rators\" || group=\"Auditors\" || group=\"Certificate Manager Agents\""+
        " || group=\"Registration Manager Agents\" || group=\"Data Recovery Man"+
        "ager Agents\" || group=\"Online Certificate Status Manager Agents\";al"+
        "low (modify) group=\"Administrators\":Administrators, auditors, and ag"+
        "ents are allowed to read DRM configuration but only administrators all"+
        "owed to modify",

        "certServer.ra.configuration:read,modify:allow (read) group=\"Administr"+
        "ators\" || group=\"Auditors\" || group=\"Certificate Manager Agents\" "+
        "|| group=\"Registration Manager Agents\" || group=\"Data Recovery Mana"+
        "ger Agents\" || group=\"Online Certificate Status Manager Agents\";all"+
        "ow (modify) group=\"Administrators\":Administrators, auditors, and age"+
        "nts are allowed to read RA configuration but only administrators allow"+
        "ed to modify" };

    private static final String[] newCAresourceACLs = {
        "certServer.general.configuration:read,modify,delete:allow (read) group"+
        "=\"Administrators\" || group=\"Auditors\" || group=\"Certificate Manag"+
        "er Agents\" || group=\"Registration Manager Agents\";allow (modify,del"+
        "ete) group=\"Administrators\":Administrators, auditors, and agents are"+
        " allowed to read CMS general configuration but only administrators are"+
        " allowed to modify and delete",

        "certServer.policy.configuration:read,modify:allow (read) group=\"Admin"+
        "istrators\" || group=\"Certificate Manager Agents\" || group=\"Registr"+
        "ation Manager Agents\" || group=\"Auditors\";allow (modify) group=\"Ad"+
        "ministrators\":Administrators, agents and auditors are allowed to read"+
        " policy configuration but only administrators allowed to modify",

        "certServer.acl.configuration:read,modify:allow (read) group=\"Administ"+
        "rators\" || group=\"Certificate Manager Agents\" || group=\"Registrati"+
        "on Manager Agents\" || group=\"Auditors\";allow (modify) group=\"Admin"+
        "istrators\":Administrators, agents and auditors are allowed to read AC"+
        "L configuration but only administrators allowed to modify",

        "certServer.log.configuration:read,modify:allow (read) group=\"Administ"+
        "rators\" || group=\"Auditors\" || group=\"Certificate Manager Agents\""+
        " || group=\"Registration Manager Agents\";allow (modify) group=\"Admin"+
        "istrators\":Administrators, Agents, and auditors are allowed to read t"+
        "he log configuration but only administrators are allowed to modify",

        "certServer.log.configuration.fileName:read,modify:allow (read) group="+
        "\"Administrators\" || group=\"Auditors\" || group=\"Certificate Manage"+
        "r Agents\" || group=\"Registration Manager Agents\" ;deny (modify) use"+
        "r=anybody:Nobody is allowed to modify a fileName parameter",

        "certServer.log.content.signedAudit:read:allow (read) group=\"Auditors"+
        "\":Only auditor is allowed to read the signed audit log",

        "certServer.log.content.system:read:allow (read) group=\"Administrators"+
        "\" || group=\"Certificate Manager Agents\" || group=\"Registration Man"+
        "ager Agents\" || group=\"Auditors\":Administrators, auditors, and agen"+
        "ts are allowed to read the log content",

        "certServer.log.content.transactions:read:allow (read) group=\"Administ"+
        "rators\" || group=\"Certificate Manager Agents\" || group=\"Registrati"+
        "on Manager Agents\" || group=\"Auditors\":Administrators, auditors, an"+
        "d agents are allowed to read the log content",

        "certServer.ca.configuration:read,modify:allow (read) group=\"Administr"+
        "ators\" || group=\"Certificate Manager Agents\" || group=\"Registratio"+
        "n Manager Agents\" || group=\"Auditors\";allow (modify) group=\"Admini"+
        "strators\":Administrators, auditors, and agents are allowed to read CA"+
        " configuration but only administrators allowed to modify",

        "certServer.auth.configuration:read,modify:allow (read) group=\"Adminis"+
        "trators\" || group=\"Certificate Manager Agents\" || group=\"Registrat"+
        "ion Manager Agents\" || group=\"Auditors\";allow (modify) group=\"Admi"+
        "nistrators\":Administrators, agents, and auditors are allowed to read "+
        "authentication configuration but only administrators allowed to modify",

        "certServer.ocsp.configuration:read,modify:allow (read) group=\"Adminis"+
        "trators\" || group=\"Certificate Manager Agents\" || group=\"Registrat"+
        "ion Manager Agents\" || group=\"Auditors\";allow (modify) group=\"Admi"+
        "nistrators\":Administrators, Agents, and auditors are allowed to read "+
        "ocsp configuration but only administrators allowed to modify",

        "certServer.registry.configuration:read,modify:allow (read) group=\"Adm"+
        "inistrators\" || group=\"Certificate Manager Agents\" || group=\"Regis"+
        "tration Manager Agents\" || group=\"Auditors\";allow (modify) group=\""+
        "Administrators\":this acl is shared by all admin servlets",

        "certServer.profile.configuration:read,modify:allow (read) group=\"Admi"+
        "nistrators\" || group=\"Certificate Manager Agents\" || group=\"Regist"+
        "ration Manager Agents\" || group=\"Auditors\";allow (modify) group=\"A"+
        "dministrators\":Administrators, agents, and auditors are allowed to re"+
        "ad profile configuration but only administrators allowed to modify",

        "certServer.job.configuration:read,modify:allow (read) group=\"Administ"+
        "rators\" || group=\"Certificate Manager Agents\" || group=\"Registrati"+
        "on Manager Agents\" || group=\"Auditors\";allow (modify) group=\"Admin"+
        "istrators\":Administrators, agents, and auditors are allowed to read j"+
        "ob configuration but only administrators allowed to modify",

        "certServer.publisher.configuration:read,modify:allow (read) group=\"Ad"+
        "ministrators\" || group=\"Auditors\" || group=\"Certificate Manager Ag"+
        "ents\" || group=\"Registration Manager Agents\";allow (modify) group="+
        "\"Administrators\":Administrators, auditors, and agents are allowed to"+
        " read publisher configuration but only administrators allowed to modif"+
        "y",

        "certServer.kra.configuration:read,modify:allow (read) group=\"Administ"+
        "rators\" || group=\"Auditors\" || group=\"Certificate Manager Agents\""+
        " || group=\"Registration Manager Agents\";allow (modify) group=\"Admin"+
        "istrators\":Administrators, auditors, and agents are allowed to read D"+
        "RM configuration but only administrators allowed to modify",

        "certServer.ra.configuration:read,modify:allow (read) group=\"Administr"+
        "ators\" || group=\"Auditors\" || group=\"Certificate Manager Agents\" "+
        "|| group=\"Registration Manager Agents\";allow (modify) group=\"Admini"+
        "strators\":Administrators, auditors, and agents are allowed to read RA"+
        " configuration but only administrators allowed to modify" };

    /* TKS's old and new values for resourceACLS attributes */

    private static final String[] oldTKSresourceACLs = {
        "certServer.usrgrp.administration:read,modify:allow (read) group=\"Admi"+
        "nistrators\" || group=\"Auditors\" || group=\"Certificate Manager Agen"+
        "ts\" || group=\"Registration Manager Agents\" || group=\"Data Recovery"+
        " Manager Agents\" || group=\"Online Certificate Status Manager Agents"+
        "\";allow (modify) group=\"Administrators\":Administrators, auditors, a"+
        "nd agents are allowed to read user and group configuration but only ad"+
        "ministrators are allowed to modify",

        "certServer.general.configuration:read,modify:allow (read) group=\"Admi"+
        "nistrators\" || group=\"Auditors\" || group=\"Certificate Manager Agen"+
        "ts\" || group=\"Registration Manager Agents\" || group=\"Data Recovery"+
        " Manager Agents\" || group=\"Online Certificate Status Manager Agents"+
        "\";allow (modify) group=\"Administrators\":Administrators, auditors, a"+
        "nd agents are allowed to read CMS general configuration but only admin"+
        "istrators are allowed to modify",

        "certServer.acl.configuration:read,modify:allow (read) group=\"Administ"+
        "rators\" || group=\"Certificate Manager Agents\" || group=\"Registrati"+
        "on Manager Agents\" || group=\"Data Recovery Manager Agents\" || group"+
        "=\"Online Certificate Status Manager Agents\" || group=\"Auditors\";al"+
        "low (modify) group=\"Administrators\":Administrators, agents and audit"+
        "ors are allowed to read ACL configuration but only administrators allo"+
        "wed to modify",

        "certServer.log.configuration:read,modify:allow (read) group=\"Administ"+
        "rators\" || group=\"Auditors\" || group=\"Certificate Manager Agents\""+
        " || group=\"Registration Manager Agents\" || group=\"Data Recovery Man"+
        "ager Agents\" || group=\"Online Certificate Status Manager Agents\";al"+
        "low (modify) group=\"Administrators\":Administrators, Agents, and audi"+
        "tors are allowed to read the log configuration but only administrators"+
        " are allowed to modify",

        "certServer.log.configuration.fileName:read,modify:allow (read) group="+
        "\"Administrators\" || group=\"Auditors\" || group=\"Certificate Manage"+
        "r Agents\" || group=\"Registration Manager Agents\" || group=\"Data Re"+
        "covery Manager Agents\" || group=\"Online Certificate Status Manager A"+
        "gents\";deny (modify) user=anybody:Nobody is allowed to modify a fileN"+
        "ame parameter",

        "certServer.log.configuration.signedAudit.expirationTime:read,modify:al"+
        "low (read) group=\"Administrators\" || group=\"Auditors\" || group=\"C"+
        "ertificate Manager Agents\" || group=\"Registration Manager Agents\" |"+
        "| group=\"Data Recovery Manager Agents\" || group=\"Online Certificate"+
        " Status Manager Agents\";deny (modify) user=anybody:Nobody is allowed "+
        "to modify an expirationTime parameter",

        "certServer.log.content.signedAudit:read:deny (read) group=\"Administra"+
        "tors\" || group=\"Certificate Manager Agents\" || group=\"Registration"+
        " Manager Agents\" || group=\"Data Recovery Manager Agents\" || group="+
        "\"Online Certificate Status Manager Agents\":Only auditor is allowed t"+
        "o read the signed audit log",

        "certServer.log.content:read:allow (read) group=\"Administrators\" || g"+
        "roup=\"Certificate Manager Agents\" || group=\"Registration Manager Ag"+
        "ents\" || group=\"Data Recovery Manager Agents\" || group=\"Online Cer"+
        "tificate Status Manager Agents\" || group=\"Auditors\":Administrators,"+
        " auditors, and agents are allowed to read the log content",

        "certServer.auth.configuration:read,modify:allow (read) group=\"Adminis"+
        "trators\" || group=\"Certificate Manager Agents\" || group=\"Registrat"+
        "ion Manager Agents\" || group=\"Data Recovery Manager Agents\" || grou"+
        "p=\"Online Certificate Status Manager Agents\" || group=\"Auditors\";a"+
        "llow (modify) group=\"Administrators\":Administrators, agents, and aud"+
        "itors are allowed to read authentication configuration but only admini"+
        "strators allowed to modify",

        "certServer.registry.configuration:read,modify:allow (read) group=\"Adm"+
        "inistrators\" || group=\"Certificate Manager Agents\" || group=\"Regis"+
        "tration Manager Agents\" || group=\"Data Recovery Manager Agents\" || "+
        "group=\"Online Certificate Status Manager Agents\" || group=\"Auditors"+
        "\";allow (modify) group=\"Administrators\":this acl is shared by all a"+
        "dmin servlets",

        "certServer.admin.request.enrollment:submit,read,execute:allow (submit)"+
        " user=\"anybody\";allow (read,execute) group=\"Certificate Manager Age"+
        "nts\":Anybody may submit an enrollment request, Certificate Manager Ag"+
        "ents may read or execute request",

        "certServer.tks.group:read,modify:allow (modify,read) group=\"Administr"+
        "ators\":Only administrators are allowed to read and modify groups",

        "certServer.tks.encrypteddata:read:allow (read) group=\"Token Key Servi"+
        "ce Manager Agents\":Token Key Service Manager agents may read encrypte"+
        "d data information",

        "certServer.tks.keysetdata:read:allow (read) group=\"Token Key Service "+
        "Manager Agents\":Token Key Service Manager agents may read key set dat"+
        "a information",

        "certServer.tks.sessionkey:read:allow (read) group=\"Token Key Service "+
        "Manager Agents\":Token Key Service Manager agents may read session key" };

    private static final String[] newTKSresourceACLs = {
        "certServer.general.configuration:read,modify,delete:allow (read) group"+
        "=\"Administrators\" || group=\"Auditors\" || group=\"Token Key Service"+
        " Manager Agents\";allow (modify,delete) group=\"Administrators\":Admin"+
        "istrators, auditors, and agents are allowed to read CMS general config"+
        "uration but only administrators are allowed to modify and delete",

        "certServer.acl.configuration:read,modify:allow (read) group=\"Administ"+
        "rators\" || group=\"Auditors\" || group=\"Token Key Service Manager Ag"+
        "ents\";allow (modify) group=\"Administrators\":Administrators, agents "+
        "and auditors are allowed to read ACL configuration but only administra"+
        "tors allowed to modify",

        "certServer.log.configuration:read,modify:allow (read) group=\"Administ"+
        "rators\" || group=\"Auditors\" || group=\"Token Key Service Manager Ag"+
        "ents\";allow (modify) group=\"Administrators\":Administrators, Agents,"+
        " and auditors are allowed to read the log configuration but only admin"+
        "istrators are allowed to modify",

        "certServer.log.configuration.fileName:read,modify:allow (read) group="+
        "\"Administrators\" || group=\"Auditors\" || group=\"Token Key Service "+
        "Manager Agents\";deny (modify) user=anybody:Nobody is allowed to modif"+
        "y a fileName parameter",

        "certServer.log.content.signedAudit:read:allow (read) group=\"Auditors"+
        "\":Only auditor is allowed to read the signed audit log",

        "certServer.log.content.system:read:allow (read) group=\"Administrators"+
        "\" || group=\"Auditors\" || group=\"Token Key Service Manager Agents\""+
        ":Administrators, auditors, and agents are allowed to read the log cont"+
        "ent",

        "certServer.log.content.transactions:read:allow (read) group=\"Administ"+
        "rators\" || group=\"Auditors\" || group=\"Token Key Service Manager Ag"+
        "ents\":Administrators, auditors, and agents are allowed to read the lo"+
        "g content",

        "certServer.auth.configuration:read,modify:allow (read) group=\"Adminis"+
        "trators\" || group=\"Auditors\" || group=\"Token Key Service Manager A"+
        "gents\";allow (modify) group=\"Administrators\":Administrators, agents"+
        ", and auditors are allowed to read authentication configuration but on"+
        "ly administrators allowed to modify",

        "certServer.registry.configuration:read,modify:allow (read) group=\"Adm"+
        "inistrators\" || group=\"Auditors\" || group=\"Token Key Service Manag"+
        "er Agents\";allow (modify) group=\"Administrators\":this acl is shared"+
        " by all admin servlets",

        "certServer.admin.request.enrollment:submit,read,execute:allow (submit)"+
        " user=\"anybody\":Anybody may submit an enrollment request",

        "certServer.tks.group:read,modify:allow (modify,read) group=\"Administr"+
        "ators\";allow (read) group=\"Token Key Service Manager Agents\":Only a"+
        "dministrators are allowed to modify groups",

        "certServer.tks.encrypteddata:execute:allow (execute) group=\"Token Key"+
        " Service Manager Agents\":Token Key Service Manager agents may execute"+
        " encrypted data information servlet",

        "certServer.tks.keysetdata:execute:allow (execute) group=\"Token Key Se"+
        "rvice Manager Agents\":Token Key Service Manager agents may execute ke"+
        "y set data information servlet",

        "certServer.tks.sessionkey:execute:allow (execute) group=\"Token Key Se"+
        "rvice Manager Agents\":Token Key Service Manager agents may execute se"+
        "ssion key servlet",

        "certServer.tks.randomdata:execute:allow (execute) group=\"Token Key Se"+
        "rvice Manager Agents\":Token Key Service Manager agents may execute ra"+
        "ndom data servlet" };

    /* OCSP's old and new values for resourceACLS attributes */

    private static final String[] oldOCSPresourceACLs = {
        "certServer.usrgrp.administration:read,modify:allow (read) group=\"Admi"+
        "nistrators\" || group=\"Auditors\" || group=\"Certificate Manager Agen"+
        "ts\" || group=\"Registration Manager Agents\" || group=\"Data Recovery"+
        " Manager Agents\" || group=\"Online Certificate Status Manager Agents"+
        "\";allow (modify) group=\"Administrators\":Administrators, auditors, a"+
        "nd agents are allowed to read user and group configuration but only ad"+
        "ministrators are allowed to modify",

        "certServer.general.configuration:read,modify:allow (read) group=\"Admi"+
        "nistrators\" || group=\"Auditors\" || group=\"Certificate Manager Agen"+
        "ts\" || group=\"Registration Manager Agents\" || group=\"Data Recovery"+
        " Manager Agents\" || group=\"Online Certificate Status Manager Agents"+
        "\";allow (modify) group=\"Administrators\":Administrators, auditors, a"+
        "nd agents are allowed to read CMS general configuration but only admin"+
        "istrators are allowed to modify",

        "certServer.acl.configuration:read,modify:allow (read) group=\"Administ"+
        "rators\" || group=\"Certificate Manager Agents\" || group=\"Registrati"+
        "on Manager Agents\" || group=\"Data Recovery Manager Agents\" || group"+
        "=\"Online Certificate Status Manager Agents\" || group=\"Auditors\";al"+
        "low (modify) group=\"Administrators\":Administrators, agents and audit"+
        "ors are allowed to read ACL configuration but only administrators allo"+
        "wed to modify",

        "certServer.log.configuration:read,modify:allow (read) group=\"Administ"+
        "rators\" || group=\"Auditors\" || group=\"Certificate Manager Agents\""+
        " || group=\"Registration Manager Agents\" || group=\"Data Recovery Man"+
        "ager Agents\" || group=\"Online Certificate Status Manager Agents\";al"+
        "low (modify) group=\"Administrators\":Administrators, Agents, and audi"+
        "tors are allowed to read the log configuration but only administrators"+
        " are allowed to modify",

        "certServer.log.configuration.fileName:read,modify:allow (read) group="+
        "\"Administrators\" || group=\"Auditors\" || group=\"Certificate Manage"+
        "r Agents\" || group=\"Registration Manager Agents\" || group=\"Data Re"+
        "covery Manager Agents\" || group=\"Online Certificate Status Manager A"+
        "gents\";deny (modify) user=anybody:Nobody is allowed to modify a fileN"+
        "ame parameter",

        "certServer.log.configuration.signedAudit.expirationTime:read,modify:al"+
        "low (read) group=\"Administrators\" || group=\"Auditors\" || group=\"C"+
        "ertificate Manager Agents\" || group=\"Registration Manager Agents\" |"+
        "| group=\"Data Recovery Manager Agents\" || group=\"Online Certificate"+
        " Status Manager Agents\";deny (modify) user=anybody:Nobody is allowed "+
        "to modify an expirationTime parameter",

        "certServer.log.content.signedAudit:read:deny (read) group=\"Administra"+
        "tors\" || group=\"Certificate Manager Agents\" || group=\"Registration"+
        " Manager Agents\" || group=\"Data Recovery Manager Agents\" || group="+
        "\"Online Certificate Status Manager Agents\":Only auditor is allowed t"+
        "o read the signed audit log",

        "certServer.log.content:read:allow (read) group=\"Administrators\" || g"+
        "roup=\"Certificate Manager Agents\" || group=\"Registration Manager Ag"+
        "ents\" || group=\"Data Recovery Manager Agents\" || group=\"Online Cer"+
        "tificate Status Manager Agents\" || group=\"Auditors\":Administrators,"+
        " auditors, and agents are allowed to read the log content",

        "certServer.auth.configuration:read,modify:allow (read) group=\"Adminis"+
        "trators\" || group=\"Certificate Manager Agents\" || group=\"Registrat"+
        "ion Manager Agents\" || group=\"Data Recovery Manager Agents\" || grou"+
        "p=\"Online Certificate Status Manager Agents\" || group=\"Auditors\";a"+
        "llow (modify) group=\"Administrators\":Administrators, agents, and aud"+
        "itors are allowed to read authentication configuration but only admini"+
        "strators allowed to modify",

        "certServer.ocsp.configuration:read,modify:allow (read) group=\"Adminis"+
        "trators\" || group=\"Certificate Manager Agents\" || group=\"Registrat"+
        "ion Manager Agents\" || group=\"Data Recovery Manager Agents\" || grou"+
        "p=\"Online Certificate Status Manager Agents\" || group=\"Auditors\";a"+
        "llow (modify) group=\"Administrators\":Administrators, Agents, and aud"+
        "itors are allowed to read ocsp configuration but only administrators a"+
        "llowed to modify",

        "certServer.registry.configuration:read,modify:allow (read) group=\"Adm"+
        "inistrators\" || group=\"Certificate Manager Agents\" || group=\"Regis"+
        "tration Manager Agents\" || group=\"Data Recovery Manager Agents\" || "+
        "group=\"Online Certificate Status Manager Agents\" || group=\"Auditors"+
        "\";allow (modify) group=\"Administrators\":this acl is shared by all a"+
        "dmin servlets",

        "certServer.ca.ocsp:read:allow (read) group=\"Certificate Manager Agent"+
        "s\":Certificate Manager agents may read ocsp information",

        "certServer.ocsp.systemstatus:read:allow (read) group=\"Online Certific"+
        "ate Status Manager Agents\":online Certificate Status Manager agents m"+
        "ay view statistics",

        "certServer.ocsp.crl:add:allow (add) group=\"Online Certificate Status "+
        "Manager Agents\":Online Certificate Status Manager agents may add CRL",

        "certServer.admin.certificate:import:allow (import) user=\"anybody\":An"+
        "y user may import a certificate",

        "certServer.admin.request.enrollment:submit,read,execute:allow (submit)"+
        " user=\"anybody\";allow (read,execute) group=\"Certificate Manager Age"+
        "nts\":Anybody may submit an enrollment request, Certificate Manager Ag"+
        "ents may read or execute request" };

    private static final String[] newOCSPresourceACLs = {
        "certServer.general.configuration:read,modify,delete:allow (read) group"+
        "=\"Administrators\" || group=\"Auditors\" || group=\"Online Certificat"+
        "e Status Manager Agents\";allow (modify,delete) group=\"Administrators"+
        "\":Administrators, auditors, and agents are allowed to read CMS genera"+
        "l configuration but only administrators are allowed to modify and dele"+
        "te",

        "certServer.acl.configuration:read,modify:allow (read) group=\"Administ"+
        "rators\" || group=\"Online Certificate Status Manager Agents\" || grou"+
        "p=\"Auditors\";allow (modify) group=\"Administrators\":Administrators,"+
        " agents and auditors are allowed to read ACL configuration but only ad"+
        "ministrators allowed to modify",

        "certServer.log.configuration:read,modify:allow (read) group=\"Administ"+
        "rators\" || group=\"Auditors\" || group=\"Online Certificate Status Ma"+
        "nager Agents\";allow (modify) group=\"Administrators\":Administrators,"+
        " Agents, and auditors are allowed to read the log configuration but on"+
        "ly administrators are allowed to modify",

        "certServer.log.configuration.fileName:read,modify:allow (read) group="+
        "\"Administrators\" || group=\"Auditors\" || group=\"Online Certificate"+
        " Status Manager Agents\";deny (modify) user=anybody:Nobody is allowed "+
        "to modify a fileName parameter",

        "certServer.log.content.signedAudit:read:allow (read) group=\"Auditors"+
        "\":Only auditor is allowed to read the signed audit log",

        "certServer.log.content.system:read:allow (read) group=\"Administrators"+
        "\" || group=\"Online Certificate Status Manager Agents\" || group=\"Au"+
        "ditors\":Administrators, auditors, and agents are allowed to read the "+
        "log content",

        "certServer.log.content.transactions:read:allow (read) group=\"Administ"+
        "rators\" || group=\"Online Certificate Status Manager Agents\" || grou"+
        "p=\"Auditors\":Administrators, auditors, and agents are allowed to rea"+
        "d the log content",

        "certServer.auth.configuration:read,modify:allow (read) group=\"Adminis"+
        "trators\" || group=\"Online Certificate Status Manager Agents\" || gro"+
        "up=\"Auditors\";allow (modify) group=\"Administrators\":Administrators"+
        ", agents, and auditors are allowed to read authentication configuratio"+
        "n but only administrators allowed to modify",

        "certServer.ocsp.configuration:read,modify:allow (read) group=\"Adminis"+
        "trators\" || group=\"Online Certificate Status Manager Agents\" || gro"+
        "up=\"Auditors\";allow (modify) group=\"Administrators\":Administrators"+
        ", Agents, and auditors are allowed to read ocsp configuration but only"+
        " administrators allowed to modify",

        "certServer.registry.configuration:read,modify:allow (read) group=\"Adm"+
        "inistrators\" || group=\"Online Certificate Status Manager Agents\" ||"+
        " group=\"Auditors\";allow (modify) group=\"Administrators\":this acl i"+
        "s shared by all admin servlets",

        "certServer.ocsp.crl:add:allow (add) group=\"Online Certificate Status "+
        "Manager Agents\" || group=\"Trusted Managers\":Online Certificate Stat"+
        "us Manager agents and Trusted Managers may add CRL" };

    /* KRA's old and new values for resourceACLS attributes */

    private static final String[] oldKRAresourceACLs = {
        "certServer.usrgrp.administration:read,modify:allow (read) group=\"Admi"+
        "nistrators\" || group=\"Auditors\" || group=\"Certificate Manager Agen"+
        "ts\" || group=\"Registration Manager Agents\" || group=\"Data Recovery"+
        " Manager Agents\" || group=\"Online Certificate Status Manager Agents"+
        "\";allow (modify) group=\"Administrators\":Administrators, auditors, a"+
        "nd agents are allowed to read user and group configuration but only ad"+
        "ministrators are allowed to modify",

        "certServer.general.configuration:read,modify:allow (read) group=\"Admi"+
        "nistrators\" || group=\"Auditors\" || group=\"Certificate Manager Agen"+
        "ts\" || group=\"Registration Manager Agents\" || group=\"Data Recovery"+
        " Manager Agents\" || group=\"Online Certificate Status Manager Agents"+
        "\";allow (modify) group=\"Administrators\":Administrators, auditors, a"+
        "nd agents are allowed to read CMS general configuration but only admin"+
        "istrators are allowed to modify",

        "certServer.acl.configuration:read,modify:allow (read) group=\"Administ"+
        "rators\" || group=\"Certificate Manager Agents\" || group=\"Registrati"+
        "on Manager Agents\" || group=\"Data Recovery Manager Agents\" || group"+
        "=\"Online Certificate Status Manager Agents\" || group=\"Auditors\";al"+
        "low (modify) group=\"Administrators\":Administrators, agents and audit"+
        "ors are allowed to read ACL configuration but only administrators allo"+
        "wed to modify",

        "certServer.log.configuration:read,modify:allow (read) group=\"Administ"+
        "rators\" || group=\"Auditors\" || group=\"Certificate Manager Agents\""+
        " || group=\"Registration Manager Agents\" || group=\"Data Recovery Man"+
        "ager Agents\" || group=\"Online Certificate Status Manager Agents\";al"+
        "low (modify) group=\"Administrators\":Administrators, Agents, and audi"+
        "tors are allowed to read the log configuration but only administrators"+
        " are allowed to modify",

        "certServer.log.configuration.fileName:read,modify:allow (read) group="+
        "\"Administrators\" || group=\"Auditors\" || group=\"Certificate Manage"+
        "r Agents\" || group=\"Registration Manager Agents\" || group=\"Data Re"+
        "covery Manager Agents\" || group=\"Online Certificate Status Manager A"+
        "gents\";deny (modify) user=anybody:Nobody is allowed to modify a fileN"+
        "ame parameter",

        "certServer.log.configuration.signedAudit.expirationTime:read,modify:al"+
        "low (read) group=\"Administrators\" || group=\"Auditors\" || group=\"C"+
        "ertificate Manager Agents\" || group=\"Registration Manager Agents\" |"+
        "| group=\"Data Recovery Manager Agents\" || group=\"Online Certificate"+
        " Status Manager Agents\";deny (modify) user=anybody:Nobody is allowed "+
        "to modify an expirationTime parameter",

        "certServer.log.content.signedAudit:read:deny (read) group=\"Administra"+
        "tors\" || group=\"Certificate Manager Agents\" || group=\"Registration"+
        " Manager Agents\" || group=\"Data Recovery Manager Agents\" || group="+
        "\"Online Certificate Status Manager Agents\":Only auditor is allowed t"+
        "o read the signed audit log",

        "certServer.log.content:read:allow (read) group=\"Administrators\" || g"+
        "roup=\"Certificate Manager Agents\" || group=\"Registration Manager Ag"+
        "ents\" || group=\"Data Recovery Manager Agents\" || group=\"Online Cer"+
        "tificate Status Manager Agents\" || group=\"Auditors\":Administrators,"+
        " auditors, and agents are allowed to read the log content",

        "certServer.auth.configuration:read,modify:allow (read) group=\"Adminis"+
        "trators\" || group=\"Certificate Manager Agents\" || group=\"Registrat"+
        "ion Manager Agents\" || group=\"Data Recovery Manager Agents\" || grou"+
        "p=\"Online Certificate Status Manager Agents\" || group=\"Auditors\";a"+
        "llow (modify) group=\"Administrators\":Administrators, agents, and aud"+
        "itors are allowed to read authentication configuration but only admini"+
        "strators allowed to modify",

        "certServer.registry.configuration:read,modify:allow (read) group=\"Adm"+
        "inistrators\" || group=\"Certificate Manager Agents\" || group=\"Regis"+
        "tration Manager Agents\" || group=\"Data Recovery Manager Agents\" || "+
        "group=\"Online Certificate Status Manager Agents\" || group=\"Auditors"+
        "\";allow (modify) group=\"Administrators\":this acl is shared by all a"+
        "dmin servlets",

        "certServer.job.configuration:read,modify:allow (read) group=\"Administ"+
        "rators\" || group=\"Certificate Manager Agents\" || group=\"Registrati"+
        "on Manager Agents\" || group=\"Data Recovery Manager Agents\" || group"+
        "=\"Online Certificate Status Manager Agents\" || group=\"Auditors\";al"+
        "low (modify) group=\"Administrators\":Administrators, agents, and audi"+
        "tors are allowed to read job configuration but only administrators all"+
        "owed to modify",

        "certServer.kra.configuration:read,modify:allow (read) group=\"Administ"+
        "rators\" || group=\"Auditors\" || group=\"Certificate Manager Agents\""+
        " || group=\"Registration Manager Agents\" || group=\"Data Recovery Man"+
        "ager Agents\" || group=\"Online Certificate Status Manager Agents\";al"+
        "low (modify) group=\"Administrators\":Administrators, auditors, and ag"+
        "ents are allowed to read DRM configuration but only administrators all"+
        "owed to modify",

        "certServer.admin.request.enrollment:submit,read,execute:allow (submit)"+
        " user=\"anybody\";allow (read,execute) group=\"Certificate Manager Age"+
        "nts\":Anybody may submit an enrollment request, Certificate Manager Ag"+
        "ents may read or execute request",

        "certServer.kra.GenerateKeyPair:submit,read:allow (read,submit) group="+
        "\"Data Recovery Manager Agents\":Only Data Recovery Manager Agents are"+
        " allowed to submit requests",

        "certServer.kra.TokenKeyRecovery:submit,read:allow (read,submit) group="+
        "\"Data Recovery Manager Agents\":Only Data Recovery Manager Agents are"+
        " allowed to submit requests",

        "certServer.kra.getTransportCert:read,modify:allow (modify,read) group="+
        "\"Enterprise CA Administrators\" || group=\"Enterprise KRA Administrat"+
        "ors\" || group=\"Enterprise OCSP Administrators\" || group=\"Enterpris"+
        "e TKS Administrators\" || group=\"Enterprise TPS Administrators\":Only"+
        " Enterprise Administrators are allowed to retrieve the transport cert" };

    private static final String[] newKRAresourceACLs = {
        "certServer.general.configuration:read,modify,delete:allow (read) group"+
        "=\"Administrators\" || group=\"Auditors\" || group=\"Data Recovery Man"+
        "ager Agents\";allow (modify,delete) group=\"Administrators\":Administr"+
        "ators, auditors, and agents are allowed to read CMS general configurat"+
        "ion but only administrators are allowed to modify and delete",

        "certServer.acl.configuration:read,modify:allow (read) group=\"Administ"+
        "rators\" || group=\"Data Recovery Manager Agents\" || group=\"Auditors"+
        "\";allow (modify) group=\"Administrators\":Administrators, agents and "+
        "auditors are allowed to read ACL configuration but only administrators"+
        " allowed to modify",

        "certServer.log.configuration:read,modify:allow (read) group=\"Administ"+
        "rators\" || group=\"Auditors\" || group=\"Data Recovery Manager Agents"+
        "\";allow (modify) group=\"Administrators\":Administrators, Agents, and"+
        " auditors are allowed to read the log configuration but only administr"+
        "ators are allowed to modify",

        "certServer.log.configuration.fileName:read,modify:allow (read) group="+
        "\"Administrators\" || group=\"Auditors\" || group=\"Data Recovery Mana"+
        "ger Agents\";deny (modify) user=anybody:Nobody is allowed to modify a "+
        "fileName parameter",

        "certServer.log.content.signedAudit:read:allow (read) group=\"Auditors"+
        "\":Only auditor is allowed to read the signed audit log",

        "certServer.log.content.system:read:allow (read) group=\"Administrators"+
        "\" || group=\"Data Recovery Manager Agents\" || group=\"Auditors\":Adm"+
        "inistrators, auditors, and agents are allowed to read the log content",

        "certServer.log.content.transactions:read:allow (read) group=\"Administ"+
        "rators\" || group=\"Data Recovery Manager Agents\" || group=\"Auditors"+
        "\":Administrators, auditors, and agents are allowed to read the log co"+
        "ntent",

        "certServer.auth.configuration:read,modify:allow (read) group=\"Adminis"+
        "trators\" || group=\"Data Recovery Manager Agents\" || group=\"Auditor"+
        "s\";allow (modify) group=\"Administrators\":Administrators, agents, an"+
        "d auditors are allowed to read authentication configuration but only a"+
        "dministrators allowed to modify",

        "certServer.registry.configuration:read,modify:allow (read) group=\"Adm"+
        "inistrators\" || group=\"Data Recovery Manager Agents\" || group=\"Aud"+
        "itors\";allow (modify) group=\"Administrators\":this acl is shared by "+
        "all admin servlets",

        "certServer.job.configuration:read,modify:allow (read) group=\"Administ"+
        "rators\" || group=\"Data Recovery Manager Agents\" || group=\"Auditors"+
        "\";allow (modify) group=\"Administrators\":Administrators, agents, and"+
        " auditors are allowed to read job configuration but only administrator"+
        "s allowed to modify",

        "certServer.kra.configuration:read,modify:allow (read) group=\"Administ"+
        "rators\" || group=\"Auditors\" || group=\"Data Recovery Manager Agents"+
        "\";allow (modify) group=\"Administrators\":Administrators, auditors, a"+
        "nd agents are allowed to read DRM configuration but only administrator"+
        "s allowed to modify",

        "certServer.admin.request.enrollment:submit,read,execute:allow (submit)"+
        " user=\"anybody\":Anybody may submit an enrollment request",

        "certServer.kra.GenerateKeyPair:execute:allow (execute) group=\"Data Re"+
        "covery Manager Agents\":Only Data Recovery Manager Agents are allowed "+
        "to execute requests",

        "certServer.kra.TokenKeyRecovery:submit:allow (submit) group=\"Data Rec"+
        "overy Manager Agents\":Only Data Recovery Manager Agents are allowed t"+
        "o submit requests",

        "certServer.kra.getTransportCert:read:allow (read) group=\"Enterprise C"+
        "A Administrators\" || group=\"Enterprise KRA Administrators\" || group"+
        "=\"Enterprise OCSP Administrators\" || group=\"Enterprise TKS Administ"+
        "rators\" || group=\"Enterprise TPS Administrators\":Only Enterprise Ad"+
        "ministrators are allowed to retrieve the transport cert" };


    /**
     * Constructor.
     */
    public UpgradeDB() {
    }

    private static void usage(String args[]) {
        System.out.println("UpgradeDB <bindDN> <password> <hostname> <port> [<logFile>]");
    }

    /* Supporting methods */

    private static void createLog() {
        try {
            writer = new BufferedWriter(new FileWriter(logFileName, true));
        } catch (IOException e) {
            System.out.println("IOException: "+e);
        }
    }

    private static void logInfo(String info) {
        if (info != null) {
            String t =  "";
            if (info.length() > 0) {
                t = "["+dateFormat.format(new Date())+"]  " + info;
            }
            System.out.println(t);
            if (writer != null) {
                try {
                    writer.write(t);
                    writer.newLine();
                } catch (IOException e) {
                    System.out.println("IOException: "+e);
                }
            }
        }
    }
    
    private static void closeLog() {
        if (writer != null) {
            try {
                writer.flush();
                writer.close();
            } catch (IOException e) {
                System.out.println("IOException: "+e);
            }
        }
    }

    /**
     * Get array of attribute values from specified entry and its attribute.
     * <P>
     * @param entryDN The distinguished name of the entry holding attribute.
     * @param attributeName	The name of attribute to get.
     * @return An array of attribute values.
     */
    private static String[] getAttributeValues (String entryDN, String attributeName) {
        String[] values = null;
        LDAPAttribute attr = null;
        try {
            String getAttrs[] = { attributeName };
            LDAPSearchResults results = lc.search(entryDN, LDAPv3.SCOPE_BASE,
                                        "(objectclass=*)", getAttrs, false);
            LDAPEntry entry = results.next();
            if (entry != null) {
                attr = entry.getAttribute(attributeName);
                if (attr != null) {
                    values = attr.getStringValueArray();
                }
            }
        } catch(LDAPException e) {
            errorCode = e.getLDAPResultCode();
            if (errorCode != LDAPException.NO_SUCH_OBJECT) {
                logInfo("LDAPException: return code:" + errorCode);
                logInfo("Error: " + e.toString());
            }
        }
        return values;
    }

    /**
     * Get attribute or object definition specified by the schema.
     * <P>
     * @param type type of the definition: attribute or object.
     * @param name	The name of attribute or object.
     * @return attribute or object definition.
     */
    private static String getSchemaDefinition (String type, String name) {
        String value = null;
        if (name != null && type != null &&
            (type.equals("attributeTypes") || type.equals("objectClasses"))) {
            String[] values = getAttributeValues("cn=schema", type);
            for (int i = 0; values != null && i < values.length; i++) {
                if (values[i] != null && values[i].indexOf(name) > -1) {
                    //logInfo("Found '"+name+"' "+
                    //    (type.equals("attributeTypes")?"attribute":"objectClass")+
                    //    " definition: '"+values[i]+"'.");
                    value = values[i];
                    break;
                }
            }
        }
        return value;
    }

    /**
     * Build hashtable of DN's and attribute values from level 
     * one of the specified entry.
     * <P>
     * @param entryDN The distinguished name of the root entry.
     * @param attributeName	The name of attribute to get.
     * @return number of hashtable entries added.
     */
    private static int getEntriesAndValues (String entryDN, String attributeName) {
        LDAPAttribute attr = null;
        int n = 0;
        try {
            String getAttrs[] = { attributeName };
            LDAPSearchResults results = lc.search(entryDN, LDAPv3.SCOPE_ONE,
                                        "(objectclass=*)", getAttrs, false);
            while (results != null && results.hasMoreElements()) {
                LDAPEntry entry = results.next();
                if (entry != null) {
                    attr = entry.getAttribute(attributeName);
                    if (attr != null) {
                        Enumeration eValues = attr.getByteValues();
                        if (eValues != null && eValues.hasMoreElements()) {
                            byte[] value = (byte[])eValues.nextElement();
                            if (value != null && value.length > 0) {
                                ht.put(entry.getDN(), value);
                                logInfo("Saved '"+attributeName+"' attribute value"+
                                        " from '"+entry.getDN()+"' entry.");
                                n++;
                            }
                        }
                    }
                }
            }
        } catch(LDAPException e) {
            errorCode = e.getLDAPResultCode();
            if (errorCode != LDAPException.NO_SUCH_OBJECT) {
                logInfo("LDAPException: return code:" + errorCode);
                logInfo("Error: " + e.toString());
            }
        }
        return n;
    }

    /**
     * Add missing attribute to existing entry. 
     * <P>
     * @param entryDN The distinguished name of the entry.
     * @param attributeName Name of attribute to add if missing.
     * @param attributeValue Value of attribute to add if missing.
     */
    private static void addMissingAttribute (String entryDN, String attributeName, String attributeValue) {
        errorCode = LDAPException.SUCCESS;
        String[] values = null;
        LDAPAttribute attr = null;
        try {
            String getAttrs[] = { attributeName };
            LDAPSearchResults results = lc.search(entryDN, LDAPv3.SCOPE_BASE,
                                        "(objectclass=*)", getAttrs, false);
            LDAPEntry entry = results.next();
            if (entry != null) {
                attr = entry.getAttribute(attributeName);
                if (attr != null) {
                    values = attr.getStringValueArray();
                    logInfo("Found '"+attributeName+"' attribute in '"+entryDN+"' entry.");
                    errorCode = LDAPException.ATTRIBUTE_OR_VALUE_EXISTS;
                } else {
                    logInfo("Attribute '"+attributeName+"' is missing in '"+entryDN+"' entry.");
                    LDAPModificationSet mods = new LDAPModificationSet();
                    mods.add (LDAPModification.ADD, new LDAPAttribute(attributeName, attributeValue));
                    try {
                        lc.modify (entryDN, mods);
                    } catch(LDAPException me) {
                        errorCode = me.getLDAPResultCode();
                        logInfo("Error: " + me.toString());
                    }
                }
            }
        } catch(LDAPException e) {
            errorCode = e.getLDAPResultCode();
            if (errorCode != LDAPException.NO_SUCH_OBJECT) {
                logInfo("LDAPException: return code:" + errorCode);
                logInfo("Error: " + e.toString());
            }
        }
    }

    /**
     * Modify LDAP entry. 
     * <P>
     * @param entryDN Distinguished name of the entry.
     * @param changes LDAP modification set.
     * @return true if entry was updated, false otherwise.
     */
    private static boolean modifyEntry (String entryDN, LDAPModificationSet changes) {
        boolean done = true;
        try {
            lc.modify(entryDN, changes);
        } catch(LDAPException e) {
            errorCode = e.getLDAPResultCode();
            done = false;
            if (errorCode != LDAPException.NO_SUCH_OBJECT) {
                logInfo("LDAPException '"+errorCode+"' thrown modifying '"+entryDN+"' entry");
                logInfo("Error: " + e.toString());
            }
        }
        return done;
    }

    /**
     * Modify attribute. 
     * <P>
     * @param entryDN Distinguished name of the entry.
     * @param op modification type (add, delete, and replace)
     * @param name Name of attribute to modify.
     * @param value New value of attribute (String).
     * @return true if attribute value was updated, false otherwise.
     */
    private static boolean modifyAttribute (String entryDN, int op, String name, String value) {
        boolean done = true;
        LDAPModificationSet changes = new LDAPModificationSet();
        LDAPAttribute attr = new LDAPAttribute(name, value);
        changes.add (op, attr);
        if (modifyEntry(entryDN, changes)) {
            //logInfo("'"+name+"' attribute updated");
        } else {
            done = false;
            //logInfo("Failed to update '"+name+"' attribute.");
        }
        return done;
    }

    /**
     * Modify attribute. 
     * <P>
     * @param entryDN Distinguished name of the entry.
     * @param op modification type (add, delete, and replace)
     * @param name Name of attribute to modify.
     * @param value New value of attribute (byte array).
     * @return true if attribute value was updated, false otherwise.
     */
    private static boolean modifyAttribute (String entryDN, int op, String name, byte[] value) {
        boolean done = true;
        LDAPModificationSet changes = new LDAPModificationSet();
        LDAPAttribute attr = new LDAPAttribute(name, value);
        changes.add (op, attr);
        if (modifyEntry(entryDN, changes)) {
            //logInfo("'"+name+"' attribute updated");
        } else {
            done = false;
            //logInfo("Failed to update '"+name+"' attribute.");
        }
        return done;
    }

    /**
     * Replace attribute value. 
     * <P>
     * @param entryDN Distinguished name of the entry.
     * @param name Name of attribute to modify.
     * @param oldValue Old value of the attribute (to be replaced).
     * @param newValue New value of attribute (replacing the old value).
     * @return true if attribute value was updated, false otherwise.
     */
    private static boolean replaceAttributeValue (String entryDN, String name,
                                                  String oldValue, String newValue) {
        boolean done = true;
        LDAPModificationSet changes = new LDAPModificationSet();
        LDAPAttribute attr = new LDAPAttribute(name, oldValue);
        changes.add(LDAPModification.DELETE, attr);
        attr = new LDAPAttribute(name,  newValue);
        changes.add(LDAPModification.ADD, attr);
        if (modifyEntry(entryDN, changes)) {
            //logInfo("'"+name+"' attribute value updated");
        } else {
            done = false;
            //logInfo("Failed to update '"+name+"' attribute.");
        }
        return done;
    }

    /**
     * Replace attribute values. 
     * <P>
     * @param entryDN Distinguished name of the entry.
     * @param name Name of attribute to modify.
     * @param oldValue Array of old values of the attribute (to be replaced).
     * @param newValue Array of new values of attribute (replacing the old values).
     * @return true if attribute values were updated, false otherwise.
     */
    private static boolean replaceAttributeValue (String entryDN, String name,
                                                  String[] oldValue, String[] newValue) {
        boolean done = true;
        LDAPModificationSet changes = new LDAPModificationSet();
        LDAPAttribute attr = null;
        if (oldValue != null && oldValue.length > 0) {
            for (int i = 0; i < oldValue.length; i++) {
                attr = new LDAPAttribute(name, oldValue[i]);
                changes.add(LDAPModification.DELETE, attr);
            }
        }
        if (newValue != null && newValue.length > 0) {
            for (int i = 0; i < newValue.length; i++) {
                attr = new LDAPAttribute(name, newValue[i]);
                changes.add(LDAPModification.ADD, attr);
            }
        }
        if (changes != null && changes.size() > 0) {
            if (modifyEntry(entryDN, changes)) {
                //logInfo("Updated '"+name+"' attribute value.");
            } else {
                done = false;
                //logInfo("Failed to update '"+name+"' attribute.");
            }
        } else {
            logInfo("No changes to '"+name+"' attribute.");
        }
        return done;
    }

    /**
     * Get array of naming contexts.
     * <P>
     * @return An array of naming contexts.
     */
    private static String[] getNamingContexts () {
        return getAttributeValues("", "namingContexts");
    }


    /* Step methods */

    /**
     * Set value of 'nsslapd-maxbersize' to 209715200
     * if its value is lower than 209715200. 
     * <P>
     */
    private static void updateMaxBerSize () {
        int currentMaxBerSize = 0;

        logInfo("");
        logInfo("Updating 'nsslapd-maxbersize'.");
        String[] values = getAttributeValues ("cn=config", "nsslapd-maxbersize");
        if (values != null && values.length > 0) {
            try {
                currentMaxBerSize = Integer.parseInt(values[0]);
            } catch (NumberFormatException  e) {
                currentMaxBerSize = 0;
                logInfo("'nsslapd-maxbersize' has non numeric value: '"+values[0]+"'");
            }
        }

        if (currentMaxBerSize < newMaxBerSize) {
            logInfo("Current 'nsslapd-maxbersize' is "+currentMaxBerSize+" and it is smaller than "+newMaxBerSize);
            if (modifyAttribute ("cn=config", LDAPModification.REPLACE,
                                 "nsslapd-maxbersize", String.valueOf(newMaxBerSize))) {
                logInfo("'nsslapd-maxbersize' value is updated to "+newMaxBerSize);
            } else {
                logInfo("Failed to update 'nsslapd-maxbersize' value to "+newMaxBerSize);
            }
        }
    }

    /**
     * Remove 'Fedora' string from 'description' of Administrators group.
     * <P>
     */
    private static void updateAdministratorsEntry () {
        boolean done = true;

        logInfo("");
        logInfo("Updating 'description' attribute.");
        for (int i = 0; namingContext != null && i < namingContext.length; i++) {
            String[] values = getAttributeValues("cn=Administrators,ou=groups,"+namingContext[i], "description");
            if (values == null && errorCode == LDAPException.NO_SUCH_OBJECT) {
                errorCode = LDAPException.SUCCESS;
            }
            for (int j = 0; values != null && j < values.length; j++) {
                if (values[j].equals(oldDescription)) {
                    logInfo("Found 'description' attribute in 'cn=Administrators,ou=groups,"+
                             namingContext[i]+"' with value of '"+values[j]+"'.");
                    if (modifyAttribute ("cn=Administrators,ou=groups,"+namingContext[i],
                                         LDAPModification.REPLACE, "description", newDescription)) {
                        logInfo("Set 'description' attribute in 'cn=Administrators,ou=groups,"+
                                 namingContext[i]+"' to '"+newDescription+"'.");
                    } else {
                        done = false;
                        logInfo("Failed to update 'description' attribute in 'cn=Administrators,ou=groups,"+
                                 namingContext[i]+"' to '"+newDescription+"'.");
                    }
                }
            }
        }
        if (done) {
            logInfo("All 'description' attribute(s) are updated.");
        }
    }

    /**
     * Remove 'subject' attribute from definition of 'certificateRecord' object.
     * <P>
     */
    private static void updateCertificateRecord () {
        logInfo("");
        logInfo("Updating 'certificateRecord' objectClass definition.");
        String value = getSchemaDefinition ("objectClasses", "certificateRecord");
        if (value != null) {
            int i = value.indexOf("subject");
            int j = value.lastIndexOf("subject");
            if (i == j && value.startsWith("subjectName", i)) {
                logInfo("Definition of 'certificateRecord' objectClass does not include 'subject' attribute.");
            } else {
                logInfo("Definition of 'certificateRecord' includes 'subject' attribute.");
                if (replaceAttributeValue ("cn=schema", "objectClasses",
                                           oldCertificateRecord, newCertificateRecord)) {
                    logInfo("Removed 'subject' attribute from 'certificateRecord' objectClass.");
                } else {
                    logInfo("Failed to remove 'subject' attribute from 'certificateRecord' objectClass.");
                }
            }
        } else {
            logInfo("Missing 'certificateRecord' objectClass definition.");
        }
    }

    /**
     * Add definition of 'publishingStatus' attribute
     * Add 'publishingStatus' attribute to definition of 'repository' object.
     * Add 'publishingStatus' attribute to all 'ou=ca, ou=requests, ...' entries.
     * <P>
     */
    private static void updatePublishingStatus () {
        boolean done = true;
        boolean found = false;
        int i;

        logInfo("");
        logInfo("Updating all 'ou=ca,ou=requests,<namingContext>' entries.");
        String value = getSchemaDefinition ("attributeTypes", "publishingStatus");
        if (value == null) {
            logInfo("Adding 'publishingStatus' attribute definition.");
            if (modifyAttribute ("cn=schema", LDAPModification.ADD,
                                 "attributeTypes", newPublishingStatus)) {
                logInfo("Added 'publishingStatus' attribute definition.");
            } else {
                done = false;
                logInfo("Failed to add 'publishingStatus' attribute definition.");
            }
        }
        if (done) {
            value = getSchemaDefinition ("objectClasses", "repository");
            if (value != null && value.indexOf("publishingStatus") > -1) {
                found = true;
                logInfo("'repository' objectClass definition includes 'publishingStatus' attribute.");
            } else if (value != null) {
                logInfo("'repository' objectClass definition is missing 'publishingStatus' attribute.");
            } else {
                done = false;
                logInfo("Missing 'repository' definition.");
            }
        }
        if (done && (!found)) {
            if (replaceAttributeValue ("cn=schema", "objectClasses",
                                       value, newRepository)) {
                logInfo("Added 'publishingStatus' attribute to 'repository' objectClass definition.");
            } else {
                done = false;
                logInfo("Failed to add 'publishingStatus' attribute to 'repository' objectClass definition.");
            }
        }
        if (done) {
            for (i = 0; namingContext != null && i < namingContext.length; i++) {
                addMissingAttribute ("ou=ca,ou=requests,"+namingContext[i], "publishingStatus", "-2");
                if (errorCode == LDAPException.SUCCESS) {
                    logInfo("Added 'publishingStatus' attribute to 'ou=ca,ou=requests,"+
                                        namingContext[i]+"' entry.");
                } else if (errorCode == LDAPException.ATTRIBUTE_OR_VALUE_EXISTS ||
                           errorCode == LDAPException.ENTRY_ALREADY_EXISTS) {
                    logInfo("'publishingStatus' attribute already exists in 'ou=ca,ou=requests,"+
                                         namingContext[i]+"' entry.");
                } else if (errorCode == LDAPException.NO_SUCH_OBJECT) {
                    errorCode = LDAPException.SUCCESS;
                } else {
                    logInfo("Failed to add 'publishingStatus' attribute to 'ou=ca,ou=requests,"+
                             namingContext[i]+"' entry.");
                }
            }
        }
    }

    /**
     * Remove 'pkiCA' value from 'objectClass' attribute of 'ou=ca, ...' entries
     * Replace 'pkiCA' definition.
     * Add 'pkiCA' value to 'objectClass' attribute of 'cn=crossCerts, ...' entries.
     * <P>
     */
    private static void updatePkiCA () {
        boolean done = true;
        String[] values = null;

        logInfo("");
        logInfo("Updating all 'ou=ca,<namingContext>' entries.");
        for (int i = 0; namingContext != null && i < namingContext.length; i++) {
            values = getAttributeValues("ou=ca,"+namingContext[i], "objectClass");
            if (values == null && errorCode == LDAPException.NO_SUCH_OBJECT) {
                errorCode = LDAPException.SUCCESS;
            }
            for (int j = 0; values != null && j < values.length; j++) {
                if (values[j] != null && values[j].indexOf("pkiCA") > -1) {
                    //logInfo("Found '"+values[j]+"' as value of 'objectClass' attribute in 'ou=ca,"+
                    //         namingContext[i]+"' entry.");
                    if (modifyAttribute ("ou=ca,"+namingContext[i], LDAPModification.DELETE,
                                         "objectClass", "pkiCA")) {
                        logInfo("Removed '"+values[j]+"' from values of 'objectClass' attribute"+
                                           " in 'ou=ca,"+namingContext[i]+"' entry.");
                    } else {
                        done = false;
                        logInfo("Failed to removed '"+values[j]+"' from 'ou=ca,"+
                                 namingContext[i]+"' entry.");
                    }
                }
            }
        }
        String value = getSchemaDefinition ("objectClasses", "pkiCA");
        if (value.indexOf("STRUCTURAL") > -1) {
            if (replaceAttributeValue ("cn=schema", "objectClasses",
                                       value, newPkiCA)) {
                logInfo("Updated 'pkiCA' objectClass definition.");
            } else {
                done = false;
                logInfo("Failed to update 'pkiCA' objectClass definition.");
            }
        } else if (value.indexOf("AUXILIARY") > -1) {
            logInfo("Found new 'pkiCA' objectClass definition: '"+value+"'.");
        }
        if (done) {
            logInfo("Updating all 'ou=crossCerts,<namingContext>' entries.");
            for (int i = 0; namingContext != null && i < namingContext.length; i++) {
                values = getAttributeValues("cn=crossCerts,"+namingContext[i], "objectClass");
                if (values == null && errorCode == LDAPException.NO_SUCH_OBJECT) {
                    errorCode = LDAPException.SUCCESS;
                }
                for (int j = 0; values != null && j < values.length; j++) {
                    if (values[j] != null && values[j].indexOf("pkiCA") > -1) {
                        logInfo("Entry 'cn=crossCerts,"+namingContext[i]+"' is already updated.");
                    } else if (values[j] != null && values[j].indexOf("certificationAuthority") > -1) {
                        if (replaceAttributeValue ("cn=crossCerts,"+namingContext[i], "objectClass",
                                                   "certificationAuthority", "pkiCA")) {
                            logInfo("Replaced 'certificationAuthority' by 'pkiCA'"+
                                    " in 'objectClass' attribute of 'cn=crossCerts,"+
                                               namingContext[i]+"' entry.");
                        } else {
                            done = false;
                            logInfo("Failed to replace 'certificationAuthority' with 'pkiCA'"+
                                    " in 'objectClass' attribute of 'cn=crossCerts,"+
                                     namingContext[i]+"' entry.");
                        }
                    }
                }
            }
        }
    }

    /**
     * Read, save value, and remove 'deltaCRL' attributes from all CRL issuing points
     *  located in 'cn=..., ou=crlIssuingPoints, ou=ca, ...' entries. 
     * Replace 'crlIssuingPointRecord' definition by removing 'deltaCRL' attribute.
     * Remove old 'deltaCRL' definition.
     * Replace 'crlIssuingPointRecord' definition by including 'deltaRevocationList' attribute.
     * Add new 'deltaCRL' definition.
     * Add 'pkiCA' value to 'objectClass' attribute of 'cn=crossCerts, ...' entries.
     * Restore saved values of 'deltaCRL' attributes in all CRL issuing points
     *  using 'deltaRevocationList' attribute. 
     * <P>
     */
    private static void updateCrlIssuingPointRecord () {
        boolean done = true;
        boolean found = false;

        logInfo("");
        logInfo("Updating CRL issuing points.");
        String value = getSchemaDefinition ("objectClasses", "crlIssuingPointRecord");
        if (value != null && value.indexOf("deltaCRL") > -1) {
            logInfo("'crlIssuingPointRecord' objectClass definition"+
                    " includes 'deltaCRL' attribute.");
        } else if (value != null && value.indexOf("deltaRevocationList") > -1) {
            logInfo("'crlIssuingPointRecord' objectClass definition"+
                    " already includes 'deltaRevocationList' attribute.");
            found = true;
        } else {
            logInfo("'crlIssuingPointRecord' objectClass definition not found.");
            done = false;
        }

        int n = 0;
        if (done && (!found)) {
            ht = new Hashtable<String, byte[]>();
            int k = 0;
            for (int i = 0; namingContext != null && i < namingContext.length; i++) {
                k = getEntriesAndValues ("ou=crlIssuingPoints,ou=ca,"+namingContext[i], "deltaCRL");
                if (k == 0 && errorCode == LDAPException.NO_SUCH_OBJECT) {
                    errorCode = LDAPException.SUCCESS;
                } 
                n += k;
            }
            k = 0;
            for (Enumeration eKeys = ht.keys(); eKeys.hasMoreElements(); k++) {
                String entryDN = (String)eKeys.nextElement();
                if (modifyAttribute (entryDN, LDAPModification.DELETE,
                                     "deltaCRL", (byte[])(ht.get(entryDN)))) {
                    logInfo("Removed 'deltaCRL' attribute  from '"+entryDN+"' entry.");
                } else {
                    done = false;
                    logInfo("Failed to remove 'deltaCRL' attribute from '"+entryDN+"' entry.");
                }
            }
            if (errorCode != LDAPException.SUCCESS) done = false; 
        }

        if (!found) {
            if (done) {
                if (replaceAttributeValue ("cn=schema", "objectClasses",
                                           oldCrlIssuingPointRecord,
                                           oldCrlIssuingPointRecordWithOutDeltaCRL)) {
                    logInfo("Update definition of 'crlIssuingPointRecord' objectClass"+
                            " by removing 'deltaCRL' attribute");
                } else {
                    logInfo("Failed to update definition of 'crlIssuingPointRecord' objectClass"+
                            " by removing 'deltaCRL' attribute: "+errorCode);
                    done = false;
                }
            }
            if (done) {
                if (modifyAttribute ("cn=schema", LDAPModification.DELETE,
                                     "attributeTypes", oldDeltaCRLAttribute)) {
                    logInfo("Removed definition of 'deltaCRL' attribute.");
                } else {
                    logInfo("Failed to remove definition of 'deltaCRL' attribute: "+errorCode);
                    if (errorCode != LDAPException.NO_SUCH_ATTRIBUTE) done = false;
                }
            }
            if (done) {
                if (replaceAttributeValue ("cn=schema", "objectClasses",
                                           oldCrlIssuingPointRecordWithOutDeltaCRL,
                                           newCrlIssuingPointRecord)) {
                    logInfo("Update definition of 'crlIssuingPointRecord' objectClass"+
                            " by adding 'deltaRevocationList' attribute.");
                } else {
                    logInfo("Failed to update definition of 'crlIssuingPointRecord' objectClass"+
                            " by adding 'deltaRevocationList' attribute: "+errorCode);
                    done = false;
                }
            }
            if (done) {
                if (modifyAttribute ("cn=schema", LDAPModification.ADD,
                                     "objectClasses", newDeltaCRLObjectClass)) {
                    logInfo("Added definition of 'deltaCRL' objectClass.");
                } else {
                    logInfo("Failed to add definition of 'deltaCRL' objectClass: "+errorCode);
                }
            }
            if (done) {
                for (Enumeration eKeys = ht.keys(); eKeys.hasMoreElements(); ) {
                    String entryDN = (String)eKeys.nextElement();
                    if (modifyAttribute (entryDN, LDAPModification.REPLACE,
                                         "deltaRevocationList", (byte[])(ht.get(entryDN)))) {
                        logInfo("Added 'deltaRevocationList' attribute to '"+entryDN+"' entry.");

                    } else {
                        logInfo("Failed to add 'deltaRevocationList' attribute"+
                                " to '"+entryDN+"'  Error: "+errorCode);
                    }
                }
            }
        }
    }

    /**
     * Add new 'SecureEEClientAuthPort' attribute definition.
     * Add 'SecureEEClientAuthPort' to the definition of 'pkiSubsystem' object.
     * <P>
     */
    private static void updatePkiSubsystem () {
        logInfo("");
        logInfo("Updating pkiSubsystem.");
        String value = getSchemaDefinition ("attributeTypes", "SecureEEClientAuthPort");
        if (value == null) {
            if (modifyAttribute ("cn=schema", LDAPModification.ADD,
                                 "attributeTypes", newSecureEEClientAuthPort)) {
                logInfo("Added definition of 'SecureEEClientAuthPort' attribute.");
            } else {
                if (errorCode != LDAPException.ENTRY_ALREADY_EXISTS ||
                    errorCode != LDAPException.ATTRIBUTE_OR_VALUE_EXISTS) {
                    errorCode = LDAPException.SUCCESS;
                } else {
                    logInfo("Failed to add definition of 'SecureEEClientAuthPort' attribute: "+errorCode);
                }
            }
        } else {
            logInfo("Found attribute 'SecureEEClientAuthPort' definition: '"+value+"'.");
        }
        if (errorCode == LDAPException.SUCCESS) {
            if (replaceAttributeValue ("cn=schema", "objectClasses",
                                        oldPkiSubsystem, newPkiSubsystem)) {
                logInfo("Updated definition of 'pkiSubsystem' objectClass.");
            } else {
                logInfo("Failed to update definition of 'pkiSubsystem' objectClass: "+errorCode);
            }
        } else {
            logInfo("Did not attempt to update definition of 'pkiSubsystem' objectClass.");
        }
    }

    /**
     * Add new 'cmsUserGroup' attribute definition.
     * Add new 'securityDomainSessionEntry' object definition
     *  including 'cmsUserGroup' attribute.
     * <P>
     */
    private static void updateSecurityDomainSessionEntry () {
        logInfo("");
        logInfo("Adding securityDomainSessionEntry.");
        String value = getSchemaDefinition ("attributeTypes", "cmsUserGroup");
        if (value == null) {
            if (modifyAttribute ("cn=schema", LDAPModification.ADD,
                                 "attributeTypes", newCmsUserGroup)) {
                logInfo("Added definition of 'cmsUserGroup' attribute.");
            } else {
                logInfo("Failed to add definition of 'cmsUserGroup' attribute.");
                if (errorCode != LDAPException.ENTRY_ALREADY_EXISTS ||
                    errorCode != LDAPException.ATTRIBUTE_OR_VALUE_EXISTS) {
                    errorCode = LDAPException.SUCCESS;
                }
            }
        }
        if (errorCode == LDAPException.SUCCESS) {
            if (modifyAttribute ("cn=schema", LDAPModification.ADD,
                                 "objectClasses", newSecurityDomainSessionEntry)) {
                logInfo("Added definition of 'securityDomainSessionEntry' objectClass.");
            } else {
                logInfo("Failed to add definition of 'securityDomainSessionEntry' objectClass: "+errorCode);
            }
        } else {
            logInfo("Did not attempt to add definition of 'securityDomainSessionEntry' objectClass.");
        }
    }

    /**
     * Replace old with new values of 'resourceACLS' attribute
     *  in 'cn=aclResources, . . .' entries of CA, KRA, OCSP, and TKS.
     * <P>
     */
    private static void updateACLs () {
        boolean noError = true;
        String[] values = null;

        logInfo("");
        logInfo("Updating 'resourceACLS' attributes.");
        for (int i = 0; noError && namingContext != null && i < namingContext.length; i++) {
            values = getAttributeValues("ou=ca,"+namingContext[i], "ou");
            if (values == null && errorCode == LDAPException.NO_SUCH_OBJECT) {
                errorCode = LDAPException.SUCCESS;
            }

            if (values != null) {
                logInfo("Updating CA's 'resourceACLS' attribute in"+
                                   " 'cn=aclResources,"+namingContext[i]+"' entry.");
                for (int j = 0; noError && oldCAresourceACLs != null && j < oldCAresourceACLs.length; j++) {
                    if (!modifyAttribute ("cn=aclResources,"+namingContext[i],
                                          LDAPModification.DELETE,
                                          "resourceACLS", oldCAresourceACLs[j])) {
                        noError = false;
                        logInfo("Failed to remove '"+oldCAresourceACLs[j]+
                                "' from 'resourceACLS' attribute in"+
                                " 'cn=aclResources,"+namingContext[i]+"' entry."+
                                "  Error: "+errorCode);
                    }
                }
                for (int j = 0; noError && newCAresourceACLs != null && j < newCAresourceACLs.length; j++) {
                    if (!modifyAttribute ("cn=aclResources,"+namingContext[i],
                                          LDAPModification.ADD,
                                          "resourceACLS", newCAresourceACLs[j])) {
                        noError = false;
                        logInfo("Failed to add '"+newCAresourceACLs[j]+
                                "' to 'resourceACLS' attribute in"+
                                " 'cn=aclResources,"+namingContext[i]+"' entry."+
                                "  Error: "+errorCode);
                    }
                }
                if (noError) {
                    logInfo("Updated CA's 'resourceACLS' attribute in"+
                            " 'cn=aclResources,"+namingContext[i]+"' entry.");
                } else {
                    logInfo("Failed to update CA's 'resourceACLS' attribute in"+
                            " 'cn=aclResources,"+namingContext[i]+"' entry.");
                }
            }

            values = getAttributeValues("ou=kra,"+namingContext[i], "ou");
            if (values == null && errorCode == LDAPException.NO_SUCH_OBJECT) {
                errorCode = LDAPException.SUCCESS;
            }
            if (values != null && noError) {
                logInfo("Updating DRM's 'resourceACLS' attribute in"+
                        " 'cn=aclResources,"+namingContext[i]+"' entry.");
                for (int j = 0; noError && oldKRAresourceACLs != null && j < oldKRAresourceACLs.length; j++) {
                    if (!modifyAttribute ("cn=aclResources,"+namingContext[i],
                                          LDAPModification.DELETE,
                                          "resourceACLS", oldKRAresourceACLs[j])) {
                        noError = false;
                        logInfo("Failed to remove '"+oldKRAresourceACLs[j]+
                                "' from 'resourceACLS' attribute in"+
                                " 'cn=aclResources,"+namingContext[i]+"' entry."+
                                "  Error: "+errorCode);
                    }
                }
                for (int j = 0; noError && newKRAresourceACLs != null && j < newKRAresourceACLs.length; j++) {
                    if (!modifyAttribute ("cn=aclResources,"+namingContext[i],
                                          LDAPModification.ADD,
                                          "resourceACLS", newKRAresourceACLs[j])) {
                        noError = false;
                        logInfo("Failed to add '"+newKRAresourceACLs[j]+
                                "' to 'resourceACLS' attribute in"+
                                " 'cn=aclResources,"+namingContext[i]+"' entry."+
                                "  Error: "+errorCode);
                    }
                }
                if (noError) {
                    logInfo("Updated DRM's 'resourceACLS' attribute in"+
                            " 'cn=aclResources,"+namingContext[i]+"' entry.");
                } else {
                    logInfo("Failed to update DRM's 'resourceACLS' attribute in"+
                            " 'cn=aclResources,"+namingContext[i]+"' entry.");
                }
            }

            values = getAttributeValues("cn=Online Certificate Status Manager Agents,ou=groups,"+namingContext[i], "cn");
            if (values == null && errorCode == LDAPException.NO_SUCH_OBJECT) {
                errorCode = LDAPException.SUCCESS;
            }
            if (values != null) {
                logInfo("Updating OCSP's 'resourceACLS' attribute in"+
                                   " 'cn=aclResources,"+namingContext[i]+"' entry.");
                for (int j = 0; noError && oldOCSPresourceACLs != null && j < oldOCSPresourceACLs.length; j++) {
                    if (!modifyAttribute ("cn=aclResources,"+namingContext[i],
                                          LDAPModification.DELETE,
                                          "resourceACLS", oldOCSPresourceACLs[j])) {
                        noError = false;
                        logInfo("Failed to remove '"+oldOCSPresourceACLs[j]+
                                "' from 'resourceACLS' attribute in"+
                                " 'cn=aclResources,"+namingContext[i]+"' entry."+
                                "  Error: "+errorCode);
                    }
                }
                for (int j = 0; noError && newOCSPresourceACLs != null && j < newOCSPresourceACLs.length; j++) {
                    if (!modifyAttribute ("cn=aclResources,"+namingContext[i],
                                          LDAPModification.ADD,
                                          "resourceACLS", newOCSPresourceACLs[j])) {
                        noError = false;
                        logInfo("Failed to add '"+newOCSPresourceACLs[j]+
                                "' to 'resourceACLS' attribute in"+
                                " 'cn=aclResources,"+namingContext[i]+"' entry."+
                                "  Error: "+errorCode);
                    }
                }
                if (noError) {
                    logInfo("Updated OCSP's 'resourceACLS' attribute in"+
                            " 'cn=aclResources,"+namingContext[i]+"' entry.");
                } else {
                    logInfo("Failed to update OCSP's 'resourceACLS' attribute in"+
                            " 'cn=aclResources,"+namingContext[i]+"' entry.");
                }
            }

            values = getAttributeValues("cn=Token Key Service Manager Agents,ou=groups,"+namingContext[i], "cn");
            if (values == null && errorCode == LDAPException.NO_SUCH_OBJECT) {
                errorCode = LDAPException.SUCCESS;
            }
            if (values != null) {
                logInfo("Updating TKS's 'resourceACLS' attribute in"+
                        " 'cn=aclResources,"+namingContext[i]+"' entry.");
                for (int j = 0; noError && oldTKSresourceACLs != null && j < oldTKSresourceACLs.length; j++) {
                    if (!modifyAttribute ("cn=aclResources,"+namingContext[i],
                                          LDAPModification.DELETE,
                                          "resourceACLS", oldTKSresourceACLs[j])) {
                        noError = false;
                        logInfo("Failed to remove '"+oldTKSresourceACLs[j]+
                                "' from 'resourceACLS' attribute in"+
                                " 'cn=aclResources,"+namingContext[i]+"' entry."+
                                "  Error: "+errorCode);
                    }
                }
                for (int j = 0; noError && newTKSresourceACLs != null && j < newTKSresourceACLs.length; j++) {
                    if (!modifyAttribute ("cn=aclResources,"+namingContext[i],
                                          LDAPModification.ADD,
                                          "resourceACLS", newTKSresourceACLs[j])) {
                        noError = false;
                        logInfo("Failed to add '"+newTKSresourceACLs[j]+
                                "' to 'resourceACLS' attribute in"+
                                " 'cn=aclResources,"+namingContext[i]+"' entry."+
                                "  Error: "+errorCode);
                    }
                }
                if (noError) {
                    logInfo("Updated TKS's 'resourceACLS' attribute in"+
                            " 'cn=aclResources,"+namingContext[i]+"' entry.");
                } else {
                    logInfo("Failed to update TKS's 'resourceACLS' attribute in"+
                            " 'cn=aclResources,"+namingContext[i]+"' entry.");
                }
            }
        }
    }


    /**
     * Add missing TUS Operators group in TPS.
     * <P>
     */
    private static void updateTUSGroups () {
        boolean noError = true;
        String[] values = null;

        logInfo("");
        logInfo("Updating TUS groups.");
        for (int i = 0; noError && namingContext != null && i < namingContext.length; i++) {
            values = getAttributeValues("ou=Tokens,"+namingContext[i], "ou");
            if (values == null && errorCode == LDAPException.NO_SUCH_OBJECT) {
                errorCode = LDAPException.SUCCESS;
            }
            if (values != null) {
                logInfo("Checking for presence of 'TUS Operators' group.");
                values = getAttributeValues("cn=TUS Operators,ou=Groups,"+namingContext[i], "cn");
                if (values == null && errorCode == LDAPException.NO_SUCH_OBJECT) {
                    logInfo("Adding 'TUS Operators' group.");
                    errorCode = LDAPException.SUCCESS;
                    LDAPAttribute attr1 = new LDAPAttribute ("cn", "TUS Operators");
                    LDAPAttribute attr2 = new LDAPAttribute ("objectClass", "top");
                    LDAPAttribute attr3 = new LDAPAttribute ("objectClass", "groupOfNames");
                    LDAPAttribute attr4 = new LDAPAttribute ("description", "Operators for TUS");
                    LDAPAttributeSet attrs = new LDAPAttributeSet();
                    attrs.add (attr1);
                    attrs.add (attr2);
                    attrs.add (attr3);
                    attrs.add (attr4);
                    LDAPEntry entry = new LDAPEntry ("cn=TUS Operators,ou=Groups,"+namingContext[i], attrs);
                    try {
                        lc.add (entry);
                        logInfo ("Added 'cn=TUS Operators,ou=Groups,"+
                                  namingContext[i]+"' entry.");
                    } catch(LDAPException e) {
                        errorCode = e.getLDAPResultCode();
                        if (errorCode != LDAPException.ENTRY_ALREADY_EXISTS) {
                            logInfo("LDAPException '"+errorCode+"' thrown adding '"+
                                    "cn=TUS Operators,ou=Groups,"+namingContext[i]+"' entry");
                            logInfo("Error: " + e.toString());
                        }
                        noError = false;
                        logInfo ("Failed to add 'cn=TUS Operators,ou=Groups,"+
                                  namingContext[i]+"' entry."+"  Error: "+errorCode);
                    }
                } else if (values != null) {
                    logInfo("'cn=TUS Operators,ou=Groups,"+
                              namingContext[i]+"' entry already exists.");
                    errorCode = LDAPException.SUCCESS;
                } else if (errorCode != LDAPException.SUCCESS) {
                    noError = false;
                    logInfo("Error: "+errorCode);
                }
            }
        }
    }

    /**
     * Check tool arguments for errors
     * <P>
     * @param args array of arguments
     * @return true if error has been identified, false otherwise.
     */
    private static boolean checkArgs (String args[]) {
        boolean error = false;
        /*
        for (int i = 0; args != null && i < args.length; i++) {
            System.out.println("args["+i+"]="+args[i]);
        }
        */
        if (args.length < 4) {
            error = true;
        } else {
            bindDN = args[0];
            bindPW = args[1];
            hostname = args[2];
            port = Integer.parseInt(args[3]);
            if (args.length > 4) {
                logFileName = args[4];
            }
        }

        return error;
    }

    /**
     * Display naming contexts array
     * <P>
     */
    private static void displayNamingContexts () {
        if (namingContext != null && namingContext.length > 0) {
            logInfo("");
            logInfo("Found the following naming contexts:");
        }
        for (int i = 0; namingContext != null && i < namingContext.length; i++) {
            logInfo("  "+(i+1)+". "+namingContext[i]);
        }
    }


    /**
     * Main method
     * <P>
     * @param args array of arguments
     */
    public static void main(String args[]) {
        int i;

        if (checkArgs(args)) {
            usage(args);
            return;
        }

        createLog();

        try {
            lc = new LDAPConnection();
            lc.connect(hostname, port, bindDN, bindPW);
        } catch(LDAPException e) {
            errorCode = e.getLDAPResultCode();
            if (errorCode == LDAPException.CONNECT_ERROR) {
                logInfo("Cannot connect to the DS: "+hostname+":"+port);
            } else if (errorCode == LDAPException.INVALID_CREDENTIALS) {
                logInfo("Invalid credentials");
            } else {
                logInfo("LDAPException: return code:" + errorCode);
                logInfo("Error: " + e.toString());
            }
        }

        if (errorCode == LDAPException.SUCCESS) {
            namingContext = getNamingContexts();
            displayNamingContexts();

            if (namingContext != null && namingContext.length > 0) {
                if (errorCode == LDAPException.SUCCESS) {
                    updateMaxBerSize();
                }
                if (errorCode == LDAPException.SUCCESS) {
                    updateAdministratorsEntry();
                }
                if (errorCode == LDAPException.SUCCESS) {
                    updateCertificateRecord();
                }
                if (errorCode == LDAPException.SUCCESS) {
                    updatePublishingStatus();
                }
                if (errorCode == LDAPException.SUCCESS) {
                    updatePkiCA();
                }
                if (errorCode == LDAPException.SUCCESS) {
                    updateCrlIssuingPointRecord();
                }
                if (errorCode == LDAPException.SUCCESS) {
                    updatePkiSubsystem();
                }
                if (errorCode == LDAPException.SUCCESS) {
                    updateSecurityDomainSessionEntry();
                }
                if (errorCode == LDAPException.SUCCESS) {
                    updateACLs();
                }
                if (errorCode == LDAPException.SUCCESS) {
                    updateTUSGroups();
                }
                if (errorCode != LDAPException.SUCCESS) {
                    logInfo("LDAPException: return code:" + errorCode);
                } else {
                    logInfo("");
                    logInfo("Upgrade successfully completed.");
                }
                logInfo("");
            }
        }

        try {
            if (lc != null) lc.disconnect();
        } catch(LDAPException e) {
            errorCode = e.getLDAPResultCode();
            logInfo("LDAPException: return code:" + errorCode);
            logInfo("Error: " + e.toString());
        }

        closeLog();
    }
}
