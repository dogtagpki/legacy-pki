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

##############################################################
# This script is upgrade the UI files for a given PKI subsystem
# instance from one version of the UI rpm to a later version.
#
# Sample Invocation (for CA):
#
# ./upgrade_ui.pl -pki_instance_root=/var/lib
#                 -pki_instance_name=pki-ca
#                 -subsystem_type=ca
#                 -old_sum_file=/usr/share/pki/ui-backup/redhat-pki-ca-ui-8.1.0-1.sum
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

my $ROOTUID = 0;
# Subsystem names
my $CA   = "ca";
my $KRA  = "kra";
my $OCSP = "ocsp";
my $TKS  = "tks";
my $RA   = "ra";
my $TPS  = "tps";

my $pki_subsystem_common_area = "/usr/share/pki";
my $default_file_permissions = 00660;
my $PKI_USER  = "pkiuser";
my $PKI_GROUP = "pkiuser";

##############################################################
# Local Data Structures
##############################################################

# hash containing data for all UI files
my %ui_files_hash = ();

# arrays of files to be acted upon
my @to_be_added;
my @to_be_deleted;
my @to_be_replaced;
my @to_be_checked_add;
my @to_be_checked_delete;
my @to_be_checked_replace;
my @to_be_checked_replace_add;
my @no_action_required;

##############################################################
# Local Variables
##############################################################

# Command-line variables (mandatory)
my $pki_instance_root          = undef;
my $pki_instance_name          = undef;
my $subsystem_type             = undef;
my $old_sum_file               = undef;

# Command-line arguments (optional)
my $username                   = undef;
my $groupname                  = undef;
my $pki_user                   = $PKI_USER;
my $pki_group                  = $PKI_GROUP;

# Whether or not to do verbose mode
my $verbose = 0;

# Controls whether actions are executed (dry_run == false)
# or if actions are only reported (dry_run == true).
my $dry_run = 0;

# Controls whether customized files are backed up and overwritten  (overwrite == true)
# or just reported (overwrite == false).
my $overwrite = 0;

# path to common subsystem ui pages
my $pki_subsystem_ui_path      = undef;

# path to instance and ui pages
my $pki_instance_path = undef;

# "logging" parameters
my $logfd = undef;
my $logfile_path = undef;

##############################################################
# Utility Subroutines
##############################################################

# no args
# return time stamp
sub get_time_stamp
{
    my ($sec, $min, $hour, $mday,
        $mon, $year, $wday, $yday, $isdst) = localtime(time);

    my $stamp = sprintf "%4d-%02d-%02d %02d:%02d:%02d",
                        $year+1900, $mon+1, $mday, $hour, $min, $sec;

    return $stamp;
}

# no return value
sub emit
{
    my ($string, $type) = @_;

    my $force_emit = 0;
    my $log_entry = "";

    $type = "debug" if !defined($type);

    if ($type eq "error" || $type eq "warning" || $type eq "info") {
        $force_emit = 1;
    }

    return if !$string;

    chomp($string);
    my $stamp = get_time_stamp();

    if ($verbose || $force_emit) {
        # print to stdout
        if ($type ne "log") {
            print(STDERR "[$type] $string\n");
        }
    }

    # If a log file exists, write all types
    # ("debug", "error", "info", or "log")
    # to this specified log file
    if (defined($logfd)) {
        $log_entry = "[$stamp] [$type] $string\n";
        $logfd->print($log_entry);
    }

    return;
}

# no args
# return 1 - success, or
# return 0 - failure
sub check_for_root_UID
{
    my $result = 0;

    if (($< != $ROOTUID) && ($> != $ROOTUID)) {
        emit("This script must be run as root!\n", "error");
        $result = 0;
    } else {
        # Success -- running script as root
        $result = 1;
    }

    return $result;
}

# Return 1 if success, 0 if failure
sub remove_file
{
    my ($path) = @_;
    my $result = 0;

    emit(sprintf("remove_file(%s)\n", join(", ", @_)), "debug");

    return 1 if $dry_run;

    if (!unlink($path)) {
        emit("remove_file(): failed to remove file \"$path\" ($!)\n", "error");
        return 0;
    }

    return 1;
}

# Return 1 if success, 0 if failure
sub copy_file
{
    my ($src_path, $dst_path, $permissions, $owner, $group) = @_;

    emit(sprintf("copy_file(%s, %s, %s, %s, %s)\n",
                 $src_path, $dst_path,
                 defined($permissions) ? sprintf("%o", $permissions) : "",
                 $owner, $group), "debug");

    if (!$dry_run) {
        if (!copy($src_path, $dst_path)) {
            emit("copy_file(): \"$src_path\" => \"$dst_path\" ($!)\n", "error");
            return 0;
        }
    }

    if (defined($permissions)) {
        return 0 if !set_permissions($dst_path, $permissions);
    }

    if (defined($owner) && defined($group)) {
        return 0 if !set_owner_group($dst_path, $owner, $group);
    }

    return 1;
}

# set_owner_group(path_glob, owner, group)
# Return 1 if success, 0 if failure
sub set_owner_group
{
    my ($path_glob, $owner, $group) = @_;
    my (@paths, $errstr, $result, $count);
    my ($uid, $gid);

    $errstr = undef;
    $count = 0;
    $result = 1;

    emit(sprintf("set_owner_group(%s)\n", join(", ", @_)), "debug");

    return 1 if $dry_run;

    $uid   = getpwnam($owner);
    $gid   = getgrnam($group);
    @paths = glob($path_glob);

    if (($count = chown($uid, $gid, @paths)) != @paths) {
        $errstr = "$!";
        $result = 0;
        emit(sprintf("failed to set ownership (%s) on \"%s\" => (%s), %d out of %d failed, \"%s\"\n",
                     "${owner}:${group}", $path_glob, "@paths", @paths - $count, @paths+0, $errstr), 'error');
    }
    return $result;
}

# set_permissions(path_glob, permissions)
# Return 1 if success, 0 if failure
sub set_permissions
{
    my ($path_glob, $permissions) = @_;
    my (@paths, $errstr, $result, $count);

    $errstr = undef;
    $count = 0;
    $result = 1;

    emit(sprintf("set_permissions(%s, %s)\n",
                 $path_glob,
                 defined($permissions) ? sprintf("%o", $permissions) : ""), "debug");

    return 1 if $dry_run;

    @paths = glob($path_glob);

    if (($count = chmod($permissions, @paths)) != @paths) {
        $errstr = "$!";
        $result = 0;
        emit(sprintf("failed to set permission (%o) on \"%s\" => (%s), %d out of %d failed, \"%s\"\n",
                     $permissions, $path_glob, "@paths", @paths - $count, @paths+0, $errstr), 'error');
    }
    return $result;
}

# Return 1 if success, 0 if failure
sub open_logfile
{
    my ($path, $permissions, $owner, $group) = @_;

   
    $logfd = FileHandle->new("> $path");

    if (defined($logfd)) {
        $logfile_path = $path;
    } else {
        return 0;
    }

    if (defined($permissions)) {
        return 0 if !set_permissions($logfile_path, $permissions);
    }

    if (defined($owner) && defined($group)) {
        return 0 if !set_owner_group($logfile_path, $owner, $group);
    }

    return 1;
}

# no return value
sub close_logfile
{
    if (defined($logfd)) {
        $logfd->close();
    }

    $logfd = undef;
    return;
}

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

          -old_sum_file=<old_sum_file>             # Path to file containing 
                                                   # sums of UI files prior to
                                                   # upgrading the UI rpm

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
                            "old_sum_file=s"               => \$old_sum_file,
                            "user=s"                       => \$username,
                            "group=s"                      => \$groupname,
                            "verbose+"                     => \$verbose,
                            "overwrite"                    => \$overwrite,
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

    ## Mandatory "-old_sum_file=s" option
    if (!$old_sum_file) {
        usage();
        emit("Must have value for -old_sum_file!\n", "error");
        return 0;
    }

    if (!(-r $old_sum_file)) {
        usage();
        emit("The specified old sum file does not exist or cannot be read.", "error");
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
    my $logfile = "/var/log/${pki_instance_name}-ui-upgrade.log";
    if (!open_logfile($logfile, $default_file_permissions)) {
        emit("can not create logfile ($logfile)", "error");
        return 0;
    }

    emit("    pki_instance_root   $pki_instance_root\n");
    emit("    pki_instance_name   $pki_instance_name\n");

    if ($verbose) {
        emit("    verbose mode ENABLED (level=$verbose)\n");
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

# no args
# return 1 - success, or
# return 0 - failure
sub populate_ui_files_hash
{
    # read sums from old_sum_file and store in hash
    if (! open(OLDSUMS, $old_sum_file)) {
        emit("can not open old sum file $old_sum_file", "error");
        return 0;
    }
    
    while (my $line = <OLDSUMS>) {
        my ($sum, $fname) = split("  ", $line);
        chomp($fname);
        $fname =~ s/^\.\///;
        $ui_files_hash{$fname} = { old_sum => $sum };
    }
    close (OLDSUMS);

    # get new sums and store in hash
    # remove entries for files that have not changed
    my $new_sum_file = "/tmp/sums-$$";
    system("cd $pki_subsystem_ui_path; find . -type f |xargs md5sum >> $new_sum_file");
    
    if (!open(NEWSUMS, $new_sum_file)) {
        emit("cannot open new sum file $new_sum_file", "error");
        return 0;
    }
    
    while (my $line = <NEWSUMS>) {
        my ($sum, $fname) = split("  ", $line);
        chomp($fname);
        $fname =~ s/^\.\///;
        if (defined $ui_files_hash{$fname}) {
            if ($ui_files_hash{$fname}{old_sum} eq $sum) {
                delete $ui_files_hash{$fname};
            } else {
                $ui_files_hash{$fname}{new_sum} = $sum;
            }
        } else {
            $ui_files_hash{$fname} = { new_sum => $sum };
        }
    }
    close (NEWSUMS);

    return 1;
}

# no args
# return 1 - success or
# return 0 - failure
sub check_for_customizations
{
    while ( my ($fname, $fhash) = each(%ui_files_hash)) {
        my $sum = undef;
        my $instance_fname = "${pki_instance_path}/${fname}";
        chomp($instance_fname);
        emit($instance_fname);
        
       
        if (-f $instance_fname) {
            $sum = `md5sum $instance_fname |cut -f 1 -d " "`;
            chomp($sum);
        }

        if (defined $fhash->{new_sum}) {
            if (defined $fhash->{old_sum}) {        # replaced file
                if (defined $sum) {                 # instance file exists
                    if ($sum eq $fhash->{old_sum}) {
                        push @to_be_replaced, $fname;
                    } else {
                        if ($sum eq $fhash->{new_sum}) { # file already replaced
                            push @no_action_required, $fname;
                        } else {
                            push @to_be_checked_replace, $fname;
                        }
                    }
                } else {                            # instance file does not exist
                    push @to_be_checked_replace_add, $fname;
                }
            } else {                                # new file
                if (defined $sum) {                 # instance file already exists
                    if ($sum eq $fhash->{new_sum}) {
                        push @no_action_required, $fname;
                    } else {
                        push @to_be_checked_add, $fname;
                    }
                } else {
                    push @to_be_added, $instance_fname;
                }
            }
        } else {                                     # file deleted
            if (defined $sum) {                      # file exists
                if ($sum eq $fhash->{old_sum}) {
                    push @to_be_deleted, $fname;
                } else {
                    push @to_be_checked_delete, $fname;
                }
            } else {                                 # file already deleted
                push @no_action_required, $fname;
            }
        }
    }
    return 1;
}

# no args
# return 1 - success or
# return 0 - failure
sub perform_actions
{
    if (!$dry_run) {
        emit("The following actions are being performed:\n", "info");
    } else {
        emit("If dry_run were not set to true, the following actions would be performed:\n", "info");
    }
  
    # Added files
    foreach my $fname (@to_be_added) {
        emit("Copying the new file ${pki_instance_path}/${fname} from ${pki_subsystem_ui_path}/${fname}", "info");
        if (!$dry_run) {
            copy_file("${pki_subsystem_ui_path}/${fname}", "${pki_instance_path}/${fname}", $default_file_permissions, $pki_user, $pki_group);
        }
    }
        
    # Replaced files
    foreach my $fname (@to_be_replaced) {
        emit("Replacing the file ${pki_instance_path}/${fname} from ${pki_subsystem_ui_path}/${fname}", "info");
        if (!$dry_run) {
            remove_file("${pki_instance_path}/${fname}");
            copy_file("${pki_subsystem_ui_path}/${fname}", "${pki_instance_path}/${fname}", $default_file_permissions, $pki_user, $pki_group);
        }
    }
  
    # Deleted files
    foreach my $fname (@to_be_deleted) {
        emit("Deleting the following file:  ${pki_instance_path}/${fname}", "info");
        if (!$dry_run) {
            remove_file("${pki_instance_path}/${fname}");
        }
    }

    # Check add files
    if (scalar(@to_be_checked_add) > 0) {
        if (!$overwrite) {
            emit("The following files are new files that are supposed to be copied from $pki_subsystem_ui_path to $pki_instance_path \n" .
                 "However, different (possibly customized) files currently exist at $pki_instance_path. \n" .
                 "Please check and address\n", "info");
            foreach my $fname (@to_be_checked_add) {
                emit("    $fname", "info");
            }
        } else {
            emit("The following files are new files that will be copied from $pki_subsystem_ui_path to $pki_instance_path \n" .
                 "However, different (possibly customized) files currently exist at $pki_instance_path. \n" .
                 "As the overwrite option is enabled, the existing files will be backed up and overwritten. \n" .
                 "Please check and address any issues\n", "info");
            foreach my $fname (@to_be_checked_add) {
                emit("Backing up and replacing the file ${pki_instance_path}/${fname} from ${pki_subsystem_ui_path}/${fname}", "info");
                copy_file("${pki_instance_path}/${fname}", "${pki_instance_path}/${fname}.orig", $default_file_permissions, $pki_user, $pki_group);
                remove_file("${pki_instance_path}/${fname}");
                copy_file("${pki_subsystem_ui_path}/${fname}", "${pki_instance_path}/${fname}", $default_file_permissions, $pki_user, $pki_group);
            }
        }
    }  
     
    # Check delete files
    if (scalar(@to_be_checked_delete) > 0) {
        if (!$overwrite) {
            emit("The following files are supposed to be deleted from $pki_instance_path \n" .
                 "However, the files that exist at that location appear to have been customized. \n" .
                 "Please check and address\n", "info");
            foreach my $fname (@to_be_checked_delete) {
                emit("    $fname", "info");
            }
        } else {
            emit("The following files are supposed to be deleted from $pki_instance_path \n" .
                 "However, the files that exist at that location appear to have been customized. \n" .
                 "As the overwrite option is enabled, the existing files will be backed up and deleted.\n" .
                 "Please check and address any issues\n", "info");
            foreach my $fname (@to_be_checked_delete) {
                emit("Backing up and deleting the file ${pki_instance_path}/${fname}");
                copy_file("${pki_instance_path}/${fname}", "${pki_instance_path}/${fname}.orig", $default_file_permissions, $pki_user, $pki_group);
                remove_file("${pki_instance_path}/${fname}");
            }
        }
    }  
     
    # Check replace files
    if (scalar(@to_be_checked_replace) > 0) {
        if (!$overwrite) {
            emit("The following files in $pki_instance_path are supposed to be replaced by new versions in $pki_subsystem_ui_path \n" .
                 "However, the files that exist at that location appear to have been customized. \n" .
                 "Please check and address\n", "info");
            foreach my $fname (@to_be_checked_replace) {
                emit("    $fname", "info");
            }
        } else {
            emit("The following files in $pki_instance_path are supposed to be replaced by new versions in $pki_subsystem_ui_path \n" .
                 "However, the files that exist at that location appear to have been customized. \n" .
                 "As the overwrite option is enabled, the existing files will be backed up and replaced. \n" .
                 "Please check and address any issues\n", "info");
            foreach my $fname (@to_be_checked_replace) {
                emit("Backing up and replacing the file ${pki_instance_path}/${fname} from ${pki_subsystem_ui_path}/${fname}", "info");
                copy_file("${pki_instance_path}/${fname}", "${pki_instance_path}/${fname}.orig", $default_file_permissions, $pki_user, $pki_group);
                remove_file("${pki_instance_path}/${fname}");
                copy_file("${pki_subsystem_ui_path}/${fname}", "${pki_instance_path}/${fname}", $default_file_permissions, $pki_user, $pki_group);
            }
        }
    }  
     
    # Check replace add files
    if (scalar(@to_be_checked_replace_add) > 0) {
        if ($overwrite) {
            emit("The following files in $pki_instance_path are supposed to be replaced by new versions in $pki_subsystem_ui_path \n" .
                 "However, the old files in $pki_instance_path do not exist, and may have been deleted as part of a customization. \n" .
                 "Please check and address\n", "info");
            foreach my $fname (@to_be_checked_replace_add) {
                emit("    $fname", "info");
            }
        } else {
            emit("The following files in $pki_instance_path are supposed to be replaced by new versions in $pki_subsystem_ui_path \n" .
                 "However, the old files in $pki_instance_path do not exist, and may have been deleted as part of a customization. \n" .
                 "As the overwrite option is enabled, the file will be copied over from $pki_subsystem_ui_path notwithstanding.\n" .
                 "Please check and address any issues\n", "info");
            foreach my $fname (@to_be_checked_replace_add) {
                emit("Adding the file ${pki_instance_path}/${fname} from ${pki_subsystem_ui_path}/${fname}", "info");
                copy_file("${pki_subsystem_ui_path}/${fname}", "${pki_instance_path}/${fname}", $default_file_permissions, $pki_user, $pki_group);
            }
        }
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

    exit 255 if !populate_ui_files_hash();

    exit 255 if !check_for_customizations();

    exit 255 if !perform_actions();

    return;
}


##############################################################
# Run Utility
##############################################################

main();

exit 0;
