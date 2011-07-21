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
# This script is upgrade the UI files for a given PKI subsystem
# instance from one version of the UI rpm to a later version.
#
# Sample Invocation (for CA):
#
# ./upgrade_ui.pl -pki_instance_root=/var/lib
#                 -pki_instance_name=pki-ca
#                 -subsystem_type=ca
#                 -old_ui_dir=/usr/share/pki/ca-ui-8.1.0.1
#                 -verbose
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

##############################################################
# Local Data Structures
##############################################################

# hash containing changes data 
# 
# This hash has the following structure:
# key -> hash { 
#         old_val -> parameter value or sum for the old subsystem directory
#         new_val -> parameter value or sum for the new subsystem directory
#         old_s   -> parameter value or sum for the old subsystem directory with template substitutions 
#         new_s   -> parameter value or sum for the new subsystem directory with template substitutions
#         inst_val-> parameter value or sum of the current instance 
#        }
#
# For the file changes hash, the keys are file names and the values are md5sums.
# This program essentially populates these hashes and looks for changes/actions based on the 
# hash values.
my %file_changes_hash = ();

# actions hash
my %file_actions = ();
my %dir_changes_hash = ();
 
my @ignore;

##############################################################
# Local Variables
##############################################################

# Command-line variables (mandatory)
my $pki_instance_root          = undef;
my $pki_instance_name          = undef;
my $subsystem_type             = undef;
my $old_ui_dir                 = undef;

# Command-line arguments (optional)
my $username                   = undef;
my $groupname                  = undef;

# path to common subsystem ui pages
my $pki_subsystem_ui_path      = undef;

# instance paths
my $pki_instance_path = undef;
my $pki_instance_conf_path = undef;

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
###   USAGE:  Script to upgrade UI for a CS instance                        ###
###           Be sure to back up your instance UI prior to                  ###
###           running this script.                                          ###
###############################################################################

perl upgrade_ui.pl 
          -pki_instance_root=<pki_instance_root>   # Instance root directory
                                                   # destination

          -pki_instance_name=<pki_instance_id>     # Unique PKI subsystem
                                                   # instance name

          -subsystem_type=<subsystem_type>         # Subsystem type
                                                   # [ca|kra|ocsp|tks|ra|tps]

          -old_ui_dir=<old_ui_dir>                 # Directory containing a 
                                                   # backup of the shared UI
                                                   # files prior to upgrading 
                                                   # the UI rpm

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
                            "old_ui_dir=s"                 => \$old_ui_dir,
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

    $pki_subsystem_ui_path = "${pki_subsystem_common_area}/${subsystem_type}-ui";

    if (!(-d $pki_subsystem_ui_path)) {
        usage();
        emit("$pki_subsystem_ui_path not present.  "
            . "Please install the corresponding subsystem UI RPM first!\n",
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

    $pki_instance_conf_path = "$pki_instance_path/conf";
    if (!(-d $pki_instance_conf_path)) {
        usage();
        emit("The specified instance does not have a configuration directory.", "error");
        return 0;
    }

    ## Mandatory "-old_ui_dir=s" option
    if (!$old_ui_dir) {
        usage();
        emit("Must have value for -old_ui_dir!\n", "error");
        return 0;
    }

    if (!(-d $old_ui_dir)) {
        usage();
        emit("The specified old UI directory does not exist.", "error");
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
    my $logfile = "${pki_instance_path}/logs/ui-upgrade-$$.log";
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
        emit("    no_cleanup mode ENABLED, temp files in /tmp will be retained. \n");
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

##############################################################
# Main Program
##############################################################

# no args
# no return value
sub main
{
    my $result = 0;
    my $parse_result = 0;

    print(STDOUT "PKI instance UI upgrade utility ...\n\n");

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

    my $old_sum_file      = "/tmp/old_ui_sums_$$";
    my $new_sum_file      = "/tmp/new_ui_sums_$$";
    my $inst_sum_file     = "/tmp/inst_ui_sums_$$";
    my $old_subs_sum_file = "/tmp/old_ui_subs_sums_$$";
    my $new_subs_sum_file = "/tmp/new_ui_subs_sums_$$";
    my $old_subs_dir      = "/tmp/inst_ui_old_subs_$$";
    my $new_subs_dir      = "/tmp/inst_ui_new_subs_$$";

    my %cs_cfg = ();
    exit 255 if !read_cfg("$pki_instance_conf_path/CS.cfg", \%cs_cfg);

    # find added / removed directories
    exit 255 if !find_directory_changes($old_ui_dir, $pki_subsystem_ui_path, \%dir_changes_hash);

    # find changed files
    exit 255 if !create_sums_file($old_sum_file, $old_ui_dir);
    exit 255 if !create_sums_file($new_sum_file, $pki_subsystem_ui_path);
    exit 255 if !find_changes($old_sum_file, $new_sum_file, 1, \%file_changes_hash);

    # populate changes hash with instance sums
    exit 255 if !create_sums_file($inst_sum_file, $pki_instance_path);
    exit 255 if !populate_hash_values($inst_sum_file, 1, "inst_val", \%file_changes_hash);

    # create old substituted directory and populate the changes hash
    exit 255 if !create_subs_directory($old_ui_dir, $old_subs_dir, \%cs_cfg);
    exit 255 if !create_sums_file($old_subs_sum_file, $old_subs_dir);
    exit 255 if !populate_hash_values($old_subs_sum_file, 1, "old_s", \%file_changes_hash);

    # created new substituted directory and populate the changes hash
    exit 255 if !create_subs_directory($pki_subsystem_ui_path, $new_subs_dir, \%cs_cfg);
    exit 255 if !create_sums_file($new_subs_sum_file, $new_subs_dir);
    exit 255 if !populate_hash_values($new_subs_sum_file, 1, "new_s", \%file_changes_hash);

    # check for customizations and perform file actions
    exit 255 if !check_for_customizations(\%file_changes_hash, \%file_actions, 1, \@ignore);
    exit 255 if !perform_file_actions(\%file_actions, $pki_instance_path, 
                                      $new_subs_dir, \%dir_changes_hash);

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
