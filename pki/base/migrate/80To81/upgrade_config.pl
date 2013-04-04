#!/usr/bin/perl
#
# --- BEGIN COPYRIGHT BLOCK ---
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2007-2010 Red Hat, Inc.
# All rights reserved.
# --- END COPYRIGHT BLOCK ---
#

use strict;
use warnings;
use Getopt::Long qw(GetOptions);
use File::Copy;
use FileHandle;
use File::Path qw(rmtree);
use common;


##############################################################
# This script is upgrade the config files for a given PKI subsystem
# instance from one version of the config rpm to a later version.
#
# Sample Invocation (for CA):
#
# ./upgrade_config.pl -pki_instance_root=/var/lib
#                     -pki_instance_name=pki-ca
#                     -subsystem_type=ca
#                     -old_subsystem_dir=/usr/share/pki/ca-8.1.0.1
#                     -verbose
#
##############################################################

##############################################################
# Execution Check
##############################################################

# Disallow 'others' the ability to 'write' to new files
umask 00002;

# Check to insure that this script's original
# invocation directory has not been deleted!
my $cwd = `/bin/pwd`;
chomp $cwd;
if (!$cwd) {
    emit("Cannot invoke '$0' from non-existent directory!\n", "error");
    exit 255;
}

##############################################################
# Command-Line Variables
##############################################################

my $ARGS = ($#ARGV + 1);

##############################################################
# Local Constants
##############################################################

my $pki_subsystem_common_area = "/usr/share/pki";

my $updateDomainServletData =
"<servlet>
     <servlet-name>  caUpdateDomainXML-admin  </servlet-name>
     <servlet-class> com.netscape.cms.servlet.csadmin.UpdateDomainXML  </servlet-class>
     <init-param>
         <param-name>  GetClientCert  </param-name>
         <param-value> true       </param-value>
     </init-param>
     <init-param>
         <param-name>  authority   </param-name>
         <param-value> ca          </param-value>
     </init-param>
     <init-param>
         <param-name>  ID          </param-name>
         <param-value> caUpdateDomainXML </param-value>
     </init-param>
     <init-param>
         <param-name>  interface   </param-name>
         <param-value> agent          </param-value>
     </init-param>
     <init-param>
         <param-name>  AuthMgr     </param-name>
         <param-value> certUserDBAuthMgr </param-value>
     </init-param>
     <init-param>
         <param-name>  AuthzMgr    </param-name>
         <param-value> BasicAclAuthz </param-value>
     </init-param>
     <init-param>
         <param-name>  resourceID  </param-name>
         <param-value> certServer.securitydomain.domainxml </param-value>
     </init-param>
 </servlet>";

my $updateDomainMappingData =
"<servlet-mapping>
     <servlet-name>  caUpdateDomainXML-admin </servlet-name>
     <url-pattern>   /admin/ca/updateDomainXML  </url-pattern>
 </servlet-mapping>";

##############################################################
# Local Data Structures
##############################################################

# hashes containing changes data 
# 
# These hashes have the following structure:
# key -> hash { 
#         old_val -> parameter value or sum for the old subsystem directory
#         new_val -> parameter value or sum for the new subsystem directory
#         old_s   -> parameter value or sum for the old subsystem directory with template substitutions 
#         new_s   -> parameter value or sum for the new subsystem directory with template substitutions
#         inst_val-> parameter value or sum of the current instance 
#        }
#
# For file_changes_hash, the keys are file names and the values are md5sums.  For cs_cfg and 
# registry_cfg, the keys are parameter names and values are parmeter values.
#
# This program essentially populates these hashes and looks for changes/actions based on the 
# hash values.

my %file_changes_hash = ();
my %cs_cfg_changes_hash = ();
my %registry_cfg_changes_hash = ();

# hash containing actions
my %file_actions = ();
my %cfg_actions = ();
my %registry_actions = ();
my %dir_changes_hash = ();

#ignore list
#
# These are files that are ignored when processing file changes.  There are a number of 
# reasons for this:  
#     *.ldif files are not changed or used post-configuration; 
#     CS.cfg and registry.cfg files are handled separately later;
#     applets files are not delivered to the instance
 
my @ignore = ("conf/acl.ldif", "conf/database.ldif", "conf/db.ldif", "conf/index.ldif", 
              "conf/schema.ldif", "conf/vlv.ldif", "conf/vlvtasks.ldif", 
              "conf/CS.cfg", "conf/registry.cfg", 
              "applets/1.4.4d40a449.ijc");

my %redirects = ();
 
##############################################################
# Local Variables
##############################################################

# Command-line variables (mandatory)
my $pki_instance_root          = undef;
my $pki_instance_name          = undef;
my $subsystem_type             = undef;
my $old_subsystem_dir          = undef;

# Command-line arguments (optional)
my $username                   = undef;
my $groupname                  = undef;

# path to common subsystem config pages
my $pki_subsystem_path         = undef;

# paths to instance
my $pki_instance_path = undef;

my $no_cleanup = 0;

##############################################################
# Subroutines
##############################################################

# no args
# no return value
sub usage
{
    print STDOUT <<'EOF';
###############################################################################
###   USAGE:  Script to upgrade configuration files for a CS instance       ###
###           Be sure to back up your instance configuration                ###
###           running this script.                                          ###
###############################################################################

perl upgrade_config.pl 
          -pki_instance_root=<pki_instance_root>   # Instance root directory
                                                   # destination

          -pki_instance_name=<pki_instance_id>     # Unique PKI subsystem
                                                   # instance name

          -subsystem_type=<subsystem_type>         # Subsystem type
                                                   # [ca|kra|ocsp|tks|ra|tps]

          -old_subsystem_dir=<old_subsystem_dir>   # Directory containing a 
                                                   # backup of the shared config
                                                   # files prior to upgrading 
                                                   # the subsystem rpm

          [-user=<username>]                       # User ownership
                                                   # (must ALSO specify
                                                   #  group ownership)
                                                   #
                                                   # [Default=pkiuser]

          [-group=<groupname>]                     # Group ownership
                                                   # (must ALSO specify
                                                   #  user ownership)
                                                   #
                                                   # [Default=pkiuser]

          [-verbose]                               # Print out liberal info
                                                   # during 'upgrade_ui.pl'.
                                                   # Specify multiple times
                                                   # to increase verbosity.

          [-dry_run]                               # Do not perform any actions.
                                                   # Just report what would have
                                                   # been done.

          [-overwrite]                             # Back up and perform actions
                                                   # on customized files.
                                                   # If this flag is not set, 
                                                   # required actions for these 
                                                   # files will just be reported.

          [-no_cleanup]                            # Temporary files in /tmp are not
                                                   # cleaned up on script exit.
                                                   # Useful for examining any issues.

          [-help]                                  # Print out this screen

EOF

    return;
}

# no args
# return 1 - success, or
# return 0 - failure
sub parse_arguments
{
    my $show_help            = 0;

    my $result = GetOptions("help"                         => \$show_help,
                            "pki_instance_root=s"          => \$pki_instance_root,
                            "pki_instance_name=s"          => \$pki_instance_name,
                            "subsystem_type=s"             => \$subsystem_type,
                            "old_subsystem_dir=s"          => \$old_subsystem_dir,
                            "user=s"                       => \$username,
                            "group=s"                      => \$groupname,
                            "verbose+"                     => \$verbose,
                            "overwrite"                    => \$overwrite,
                            "no_cleanup"                   => \$no_cleanup,
                            "dry_run"                      => \$dry_run);

    ## Optional "-help" option - no "mandatory" options are required
    if ($show_help) {
        usage();
        return 0;
    }

    ## Mandatory "-pki_instance_root=s" option
    if (!$pki_instance_root) {
        usage();
        emit("Must have value for -pki_instance_root!\n", "error");
        return 0;
    }

    # Remove all trailing directory separators ('/')
    $pki_instance_root =~ s/\/+$//;

    ## Mandatory "-subsystem_type=s" option
    if (!$subsystem_type) {
        usage();
        emit("Must have value for -subsystem_type!\n", "error");
        return 0;
    }

    if ($subsystem_type ne $CA   &&
        $subsystem_type ne $KRA  &&
        $subsystem_type ne $OCSP &&
        $subsystem_type ne $TKS  &&
        $subsystem_type ne $RA   &&
        $subsystem_type ne $TPS) {
        usage();
        emit("Illegal  value => $subsystem_type :  for -subsystem_type!\n",
              "error");
        return 0;
    }

    $pki_subsystem_path = "${pki_subsystem_common_area}/${subsystem_type}";

    if (!(-d $pki_subsystem_path)) {
        usage();
        emit("$pki_subsystem_path not present.  "
            . "Please install the corresponding subsystem RPM first!\n",
              "error");
        return 0;
    } else {
        emit("    subsystem_type      $subsystem_type\n");
    }

    ## Mandatory "-pki_instance_name=s" option
    if (!$pki_instance_name) {
        usage();
        emit("Must have value for -pki_instance_name!\n", "error");
        return 0;
    }

    $pki_instance_path  = "${pki_instance_root}/${pki_instance_name}";

    if (!(-d $pki_instance_path)) {
        usage();
        emit("The specified instance does not exist.", "error");
        return 0;
    }

    ## Mandatory "-old_subsystem_dir=s" option
    if (!$old_subsystem_dir) {
        usage();
        emit("Must have value for -old_subsystem_dir!\n", "error");
        return 0;
    }

    if (!(-d $old_subsystem_dir)) {
        usage();
        emit("The specified old subsystem directory does not exist.", "error");
        return 0;
    }

    ## Optional "-group=<groupname>" option
    if ($groupname) {
        if (!$username) {
            usage();
            emit("Must ALSO specify user ownership using -user!\n",
                  "error");
            return 0;
        }

        # Overwrite default value of $pki_group with user-specified $groupname
        $pki_group = $groupname;
    }

    ## Optional "-user=<username>" option
    if ($username) {
        if (!$groupname) {
            usage();
            emit("Must ALSO specify group ownership using -group!\n",
                  "error");
            return 0;
        }

        # Overwrite default value of $pki_user with user-specified $username
        $pki_user = $username;
    }

    # Capture installation information in a log file, always overwrite this file.
    my $logfile = "${pki_instance_path}/logs/config-upgrade-$$.log";
    if (!open_logfile($logfile, $default_file_permissions)) {
        emit("can not create logfile ($logfile)", "error");
        return 0;
    }

    emit("    pki_instance_root   $pki_instance_root\n");
    emit("    pki_instance_name   $pki_instance_name\n");

    if ($verbose) {
        emit("    verbose mode ENABLED (level=$verbose)\n");
    }

   if ($no_cleanup) {
        emit("    no_cleanup mode ENABLED, temp files in /tmp will be retained.\n");
   }

    if ($dry_run) {
        emit("    dry run mode ENABLED, system will not be modified\n");
        print STDOUT "dry run mode ENABLED, system will not be modified\n";
    }

    if ($overwrite) {
        emit("    overwrite mode ENABLED, customized files will be backed up and overwritten\n");
        print STDOUT "overwrite mode ENABLED, customized files will be backed up and overwritten\n";
    }

    return 1;
}

# args none
# return none
sub create_redirects
{
    $redirects{'etc/init.d/httpd'}     = "$pki_instance_path/$pki_instance_name";
    $redirects{'setup/config.desktop'} = "/usr/share/applications/${pki_instance_name}-config.desktop";
    $redirects{'conf/dtomcat5'}     = "/usr/bin/dtomcat5-$pki_instance_name";

}

# arg0 cs_cfg hash ref
# arg1 changes hash ref
# These should only be required from 8.0 to 8.1
sub add_new_config_values
{
    my ($cs_cfg, $changes_ref) = @_;

    # self test for java subsystems
    # also turn off verification for audit signing cert (which will have to be regenerated 
    # in any case)
    if (($subsystem_type eq $CA) || ($subsystem_type eq $KRA) || ($subsystem_type eq $OCSP) ||
        ($subsystem_type eq $TKS)) {
        if ($cs_cfg->{'cms.version'} >= 8.1) {
            return 1;
        }
        my $listname = lc($subsystem_type) . ".cert.list";
        my $certlist = $changes_ref->{$listname}{new_s};
        foreach my $tag (split(",", $certlist)) {
            chomp($tag);
            my $srctag = lc($subsystem_type) . "." . $tag . ".nickname";
            my $desttag = lc($subsystem_type) . ".cert." . $tag . ".nickname";
            $changes_ref->{$desttag}{new_s}   = $cs_cfg->{$srctag};
            $changes_ref->{$desttag}{new_val} = $cs_cfg->{$srctag};
        }
        $certlist =~ s/(.*),audit_signing/$1/;
        $changes_ref->{$listname}{new_s} = $certlist;
        $changes_ref->{$listname}{new_val} = $certlist;
    }
    if ($subsystem_type eq $TPS) {
        $changes_ref->{'tps.cert.list'}{new_s} = "sslserver,subsystem";
        $changes_ref->{'tps.cert.list'}{new_val} = "sslserver,subsystem";
        $changes_ref->{'tps.cert.audit_signing.nickname'}{new_s} = 
            $cs_cfg->{'logging.audit.signedAuditCertNickname'};
        $changes_ref->{'tps.cert.audit_signing.nickname'}{new_val} = 
            $cs_cfg->{'logging.audit.signedAuditCertNickname'};
        $changes_ref->{'tps.cert.subsystem.nickname'}{new_s} = 
            $cs_cfg->{'conn.ca1.clientNickname'};
        $changes_ref->{'tps.cert.subsystem.nickname'}{new_val} = 
            $cs_cfg->{'conn.ca1.clientNickname'};
        $changes_ref->{'selftests.plugin.TPSPresence.nickname'}{new_s} = 
            $cs_cfg->{'conn.ca1.clientNickname'};
        $changes_ref->{'selftests.plugin.TPSPresence.nickname'}{new_val} = 
            $cs_cfg->{'conn.ca1.clientNickname'};
        $changes_ref->{'selftests.plugin.TPSValidity.nickname'}{new_s} = 
            $cs_cfg->{'conn.ca1.clientNickname'};
        $changes_ref->{'selftests.plugin.TPSValidity.nickname'}{new_val} = 
            $cs_cfg->{'conn.ca1.clientNickname'};

        my $sslserver_nick = `grep -m1 NSSNickname ${pki_instance_path}/conf/nss.conf`;
        $sslserver_nick =~ s/NSSNickname "(.*)"/$1/; 
        chomp($sslserver_nick);

        $changes_ref->{'tps.cert.sslserver.nickname'}{new_s} = $sslserver_nick;
        $changes_ref->{'tps.cert.sslserver.nickname'}{new_val} = $sslserver_nick;
    }
 
    return 1;
}

# arg0 web_xml - path to web.xml file
# arg1 subsystem_type - subsystem type
# This is required for update from 8.1 to 8.1.errata
sub modify_web_xml
{
    my ($web_xml, $subsystem_type) = @_;
    my $parser = XML::LibXML->new();
    my $doc    = $parser->parse_file($web_xml);
    my $top_path = "/web-app";

    if ($subsystem_type eq $CA) {
        # change caUpdateNumberRange
        my $q = "//servlet[normalize-space(servlet-name) = 'caUpdateNumberRange']";
        foreach my $servlet ($doc->findnodes($q)) {
            my $q1 = "./init-param[normalize-space(param-name)='interface']" .
                     "/param-value/text()";
            &update_node_text($servlet, $q1, 'admin');
        }

        #modify servlet mapping for caUpdateNumberRange
        $q = "//servlet-mapping[normalize-space(servlet-name) = " .
             "'caUpdateNumberRange']/url-pattern/text()";
        &update_node_text($doc, $q, '/admin/ca/updateNumberRange');

        # remove getTokenInfo
        $q = "//servlet[normalize-space(servlet-name) = 'caGetTokenInfo']";
        &remove_node($doc, $q);

        # remove getTokenInfo servlet mapping
        $q = "//servlet-mapping[normalize-space(servlet-name) = 'caGetTokenInfo']";
        &remove_node($doc, $q);

        #add caUpdateDomainXML-admin
        $q = "//servlet[normalize-space(servlet-name) = 'caUpdateDomainXML-admin']";
        &add_node($doc, $parser, $q, $top_path, $updateDomainServletData);

        #add caUpdateDomainXML-admin servlet mapping
        $q = "//servlet-mapping[normalize-space(servlet-name) = " .
             "'caUpdateDomainXML-admin']";
        &add_node($doc,$parser, $q, $top_path, $updateDomainMappingData);
    } elsif ($subsystem_type eq $KRA) {
        # change kraUpdateNumberRange
        my $q = "//servlet[normalize-space(servlet-name) = 'kraUpdateNumberRange']";
        foreach my $servlet ($doc->findnodes($q)) {
            my $q1 = "./init-param[normalize-space(param-name)='interface']" .
                     "/param-value/text()";
            &update_node_text($servlet, $q1, 'admin');
        }

        #modify servlet mapping for kraUpdateNumberRange
        $q = "//servlet-mapping[normalize-space(servlet-name) = " .
             "'kraUpdateNumberRange']/url-pattern/text()";
        &update_node_text($doc, $q, '/admin/kra/updateNumberRange');

        # remove getTokenInfo
        $q = "//servlet[normalize-space(servlet-name) = 'kraGetTokenInfo']";
        &remove_node($doc, $q);

        # remove getTokenInfo servlet mapping
        $q = "//servlet-mapping[normalize-space(servlet-name) = 'kraGetTokenInfo']";
        &remove_node($doc, $q);
    } elsif ($subsystem_type eq $OCSP) {
        # remove getTokenInfo
        my $q = "//servlet[normalize-space(servlet-name) = 'ocspGetTokenInfo']";
        &remove_node($doc, $q);

        # remove getTokenInfo servlet mapping
        $q = "//servlet-mapping[normalize-space(servlet-name) = 'ocspGetTokenInfo']";
        &remove_node($doc, $q);
    } elsif ($subsystem_type eq $TKS) {
        # remove getTokenInfo
        my $q = "//servlet[normalize-space(servlet-name) = 'tksGetTokenInfo']";
        &remove_node($doc, $q);

        # remove getTokenInfo servlet mapping
        $q = "//servlet-mapping[normalize-space(servlet-name) = 'tksGetTokenInfo']";
        &remove_node($doc, $q);
    }

    if (!$dry_run) {
        my $backup_fname = "$web_xml.backup_$$";
        emit("Backing up $web_xml to $backup_fname");
        copy_file($web_xml, $backup_fname, $default_file_permissions, $pki_user, $pki_group);

        if (! open(INST, ">", $web_xml)) {
            emit("can not open $web_xml for writing", "error");
            return 0;
        }

        emit("Writing new $web_xml");
        print INST $doc->toString;
        close(INST);
    }

    return 1;
}


##############################################################
# Main Program
##############################################################

# no args
# no return value
sub main
{
    my $result = 0;
    my $parse_result = 0;

    print(STDOUT "PKI instance config upgrade utility ...\n\n");

    $result = check_for_root_UID();
    if (!$result) {
        usage();
        exit 255;
    }

    $parse_result = parse_arguments();
    if (!$parse_result || $parse_result == -1) {
        close_logfile();
        exit 255;
    }

    my $old_sum_file      = "/tmp/old_sums_$$";
    my $new_sum_file      = "/tmp/new_sums_$$";
    my $inst_sum_file     = "/tmp/inst_sums_$$";
    my $old_subs_sum_file = "/tmp/old_subs_sums_$$";
    my $new_subs_sum_file = "/tmp/new_subs_sums_$$";
    my $old_subs_dir      = "/tmp/inst_old_subs_conf_$$";
    my $new_subs_dir      = "/tmp/inst_new_subs_conf_$$";

    my %cs_cfg = ();
    exit 255 if !read_cfg("$pki_instance_path/conf/CS.cfg", \%cs_cfg);

    my $release_number = get_release_number(\%cs_cfg);

    ##################################
    # General File Processing
    ##################################

    # find added / removed directories
    exit 255 if !find_directory_changes($old_subsystem_dir, $pki_subsystem_path, \%dir_changes_hash);

    # find changed files
    exit 255 if !create_sums_file($old_sum_file, $old_subsystem_dir);
    exit 255 if !create_sums_file($new_sum_file, $pki_subsystem_path);
    exit 255 if !find_changes($old_sum_file, $new_sum_file, 1, \%file_changes_hash);

    # populate changes hash with instance sums
    exit 255 if !create_sums_file($inst_sum_file, $pki_instance_path);
    exit 255 if !populate_hash_values($inst_sum_file, 1, "inst_val", \%file_changes_hash);

    # create old substituted directory and populate the changes hash
    exit 255 if !create_subs_directory($old_subsystem_dir, $old_subs_dir, \%cs_cfg);
    exit 255 if !create_sums_file($old_subs_sum_file, $old_subs_dir);
    exit 255 if !populate_hash_values($old_subs_sum_file, 1, "old_s", \%file_changes_hash);

    # created new substituted directory and populate the changes hash
    exit 255 if !create_subs_directory($pki_subsystem_path, $new_subs_dir, \%cs_cfg);
    exit 255 if !create_sums_file($new_subs_sum_file, $new_subs_dir);
    exit 255 if !populate_hash_values($new_subs_sum_file, 1, "new_s", \%file_changes_hash);

    # check for customizations and perform file actions
    create_redirects();
    exit 255 if !check_for_customizations(\%file_changes_hash, \%file_actions, 1, 
                                          \@ignore, \%redirects);
 
    exit 255 if !perform_file_actions(\%file_actions, $pki_instance_path, 
                                      $new_subs_dir, \%dir_changes_hash, \%redirects);

    ##################################
    # CS.cfg Processing
    ##################################
    print STDOUT "\n\nConfig File CS.cfg Changes\n";

    my $old_cs_cfg = "$old_subsystem_dir/conf/CS.cfg";
    my $new_cs_cfg = "$pki_subsystem_path/conf/CS.cfg";
    my $inst_cs_cfg = "$pki_instance_path/conf/CS.cfg";

    exit 255 if !find_changes($old_cs_cfg, $new_cs_cfg, 0, \%cs_cfg_changes_hash);
    exit 255 if !populate_hash_values($inst_cs_cfg, 0, "inst_val", \%cs_cfg_changes_hash);
    exit 255 if !populate_hash_values("$old_subs_dir/conf/CS.cfg", 0, "old_s", 
                                      \%cs_cfg_changes_hash);
    exit 255 if !populate_hash_values("$new_subs_dir/conf/CS.cfg", 0, "new_s", 
                                      \%cs_cfg_changes_hash);
    exit 255 if !add_new_config_values(\%cs_cfg, \%cs_cfg_changes_hash);

    exit 255 if !check_for_customizations(\%cs_cfg_changes_hash, \%cfg_actions, 0, \@ignore);
    exit 255 if !perform_cs_actions($inst_cs_cfg, \%cs_cfg_changes_hash, \%cfg_actions);

    ####################################
    # registry.cfg processing
    ####################################

    if (($subsystem_type eq $CA) && (-e "$old_subsystem_dir/conf/registry.cfg")) {
        print STDOUT "\n\nRegistry File CS.cfg Changes\n";

        my $old_registry_cfg  = "$old_subsystem_dir/conf/registry.cfg";
        my $new_registry_cfg  = "$pki_subsystem_path/conf/registry.cfg";
        my $inst_registry_cfg = "$pki_instance_path/conf/registry.cfg";

        exit 255 if !find_changes($old_registry_cfg, $new_registry_cfg, 0, 
                                  \%registry_cfg_changes_hash);
        exit 255 if !populate_hash_values($inst_registry_cfg, 0, "inst_val", 
                                  \%registry_cfg_changes_hash);
        exit 255 if !populate_hash_values("$old_subs_dir/conf/registry.cfg", 0, "old_s",
                                      \%registry_cfg_changes_hash);
        exit 255 if !populate_hash_values("$new_subs_dir/conf/registry.cfg", 0, "new_s",
                                      \%registry_cfg_changes_hash);

        # defaultPolicy.ids may be in a different order
        if (defined $registry_cfg_changes_hash{'defaultPolicy.ids'}) {
            if (list_values_equal($registry_cfg_changes_hash{'defaultPolicy.ids'}{'old_s'}, 
                                  $registry_cfg_changes_hash{'defaultPolicy.ids'}{'inst_val'})) {
                $registry_cfg_changes_hash{'defaultPolicy.ids'}{'inst_val'} = 
                    $registry_cfg_changes_hash{'defaultPolicy.ids'}{'old_s'};
            }
        } 
        exit 255 if !check_for_customizations(\%registry_cfg_changes_hash, \%registry_actions, 
                                              0, \@ignore);
        exit 255 if !perform_cs_actions($inst_registry_cfg, \%registry_cfg_changes_hash, 
                                        \%registry_actions);
    }

    ###########################################
    # Miscellaneous actions for this migration
    # -- set permissions: these are the permissions explicitly set in pkicreate
    ###########################################

    if (($subsystem_type eq $CA) || ($subsystem_type eq $KRA) || ($subsystem_type eq $OCSP) ||
        ($subsystem_type eq $TKS)) {
        set_permissions("/usr/bin/dtomcat5-${pki_instance_name}", $default_exe_permissions);
    } else {
        set_permissions("/var/lib/${pki_instance_name}/scripts/nss_pcache", 
            $default_exe_permissions);
    }

    if ($subsystem_type eq $TPS) {
        my $cgibin_instance_path = "/var/lib/${pki_instance_name}/cgi-bin";
        set_permissions("$cgibin_instance_path/demo", $default_dir_permissions);
        set_permissions("$cgibin_instance_path/demo/*.cgi", $default_exe_permissions);
        set_permissions("$cgibin_instance_path/demo/*.html",  $default_file_permissions);
        set_permissions("$cgibin_instance_path/home", $default_dir_permissions);
        set_permissions("$cgibin_instance_path/home/*.cgi", $default_exe_permissions);
        set_permissions("$cgibin_instance_path/home/*.html", $default_file_permissions);
        set_permissions("$cgibin_instance_path/so", $default_dir_permissions);
        set_permissions("$cgibin_instance_path/so/*.cgi", $default_exe_permissions);
        set_permissions("$cgibin_instance_path/so/*.html", $default_file_permissions);
        set_permissions("$cgibin_instance_path/sow", $default_dir_permissions);
        set_permissions("$cgibin_instance_path/sow/*.cgi", $default_exe_permissions);
        set_permissions("$cgibin_instance_path/sow/*.html", $default_file_permissions);
        set_permissions("$cgibin_instance_path/sow/*.pl", $default_exe_permissions);

        set_permissions("/var/lib/${pki_instance_name}/bin/apachectl", 
            $default_exe_permissions);
    }

    set_permissions("/etc/init.d/${pki_instance_name}", $default_exe_permissions);

    ########################################
    # For errata 1, modify the web.xml
    ########################################
    if (($release_number == 0 ) && 
       (($subsystem_type eq $CA) || ($subsystem_type eq $KRA) || ($subsystem_type eq $OCSP) ||
        ($subsystem_type eq $TKS))) {
        return 255 if ! modify_web_xml(
            "/var/lib/${pki_instance_name}/webapps/${subsystem_type}/WEB-INF/web.xml",
            $subsystem_type);
    }

    ################################
    # Cleanup
    ################################
    if (!$no_cleanup) {
        unlink($old_sum_file);
        unlink($new_sum_file);
        unlink($inst_sum_file);
        unlink($old_subs_sum_file);
        unlink($new_subs_sum_file);
        rmtree($old_subs_dir);
        rmtree($new_subs_dir);
    }
    return;
}


##############################################################
# Run Utility
##############################################################

main();

exit 0;
