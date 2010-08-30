#!/usr/bin/pkiperl
#
# --- BEGIN COPYRIGHT BLOCK ---
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation;
# version 2.1 of the License.
# 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor,
# Boston, MA  02110-1301  USA 
# 
# Copyright (C) 2009 Red Hat, Inc.
# All rights reserved.
# --- END COPYRIGHT BLOCK ---
#

# startup - 
#  Fedora Certificate System -  handler to start up the server
use strict;
use warnings;

use PKI::TPS::Config;
use Apache2::Const -compile => 'OK';
use Nuxwdogclient;

package PKI::TPS::Startup;
$PKI::TPS::Startup::VERSION = '1.00';

my $x_global_bindpwd;
my $logfile;

my $default_hardware_platform="";
my $ldapsearch="";
$default_hardware_platform=`pkiarch`;
chomp($default_hardware_platform);
if( $^O eq "linux" ) {
        if( $default_hardware_platform eq "i386" ) {
                $ldapsearch = "/usr/lib/mozldap/ldapsearch";
        } elsif( $default_hardware_platform eq "x86_64" ) {
                $ldapsearch = "/usr/lib64/mozldap/ldapsearch";
        }
} elsif( $^O eq "solaris" ) {
        if( $default_hardware_platform eq "sparc" ) {
                $ldapsearch = "/usr/lib/mozldap6/ldapsearch";
        } elsif( $default_hardware_platform eq "sparcv9" ) {
                $ldapsearch = "/usr/lib/sparcv9/mozldap6/ldapsearch";
        }
}

sub handler {
  my ($conf_pool, $log_pool, $temp_pool, $s) = @_;

  # read configuration file
  my $flavor = `pkiflavor`;
  $flavor =~ s/\n//g;
  my $pkiroot = $ENV{PKI_ROOT};
  my $config = PKI::TPS::Config->new();
  $config->load_file("$pkiroot/conf/CS.cfg");

  # check cs.state 
  # if 0, then we need to run config, exit OK
  my $state = $config->get("tps.configured");

  if (! $state) {
    #tps is not yet configured
    return Apache2::Const::OK;
  }

  # open debug log
  $logfile = $config->get("service.instanceDir") .  "/logs/error_log";
  open( DEBUG, ">>" . $logfile ) ||
  warn( "Could not open '" . $logfile . "':  $!" );

  # get ldap parameters for internal db 
  # needed to test password
  my $hostport = $config->get("tokendb.hostport");
  my $host = substr($hostport, 0, index($hostport, ":"));
  my $port = substr($hostport, index($hostport, ":") +1);
  my $binddn = $config->get("tokendb.bindDN");
  # my $ssl = $config->get("tokendb.ssl");
  my $pwdfile = $config->get("tokendb.bindPassPath");
  my $basedn = $config->get("tokendb.baseDN");

  my $status =0;
  my $iteration = 0;
  do {
    #read password file
    if ((-e $pwdfile) && (-r $pwdfile) && ($iteration == 0)) {
      $x_global_bindpwd = `grep -e "^tokendbBindPass" $pwdfile | cut -c17-`;
      chomp($x_global_bindpwd);
    } else {
      &debug_log("startup::post_config: bindpwd not found or iteration>0. Prompting for it");

      #initialize client socket connection - TODO: check status
      my $status = Nuxwdogclient::call_WatchdogClient_init();
      &debug_log("startup::post_config: watchdog client initialized.");

      #get password
      my $prompt = "Please enter the password for tokendbBindPass:";
      $x_global_bindpwd = Nuxwdogclient::call_WatchdogClient_getPassword($prompt, $iteration);
    }

    #test the password
    # 49 == INVALID_CREDENTIALS
    $status = &test_ldap_password($host, $port, $binddn, $basedn, $x_global_bindpwd);
    $iteration ++;
  } while ($status == 49);

  if ($status != 0) {
    # something bad happened when connecting to the database. abort the startup.
    &debug_log("startup::post_config: test_ldap returns $status. Is the database up?");
    return Apache2::Const::DONE;
  }

  return Apache2::Const::OK;
}

sub debug_log
{
  my ($msg) = @_;
  my $date = `date`;
  chomp($date);
  if( -w $logfile ) {
      print DEBUG "$date - $msg\n";
  }
}

sub global_bindpwd
{
  return $x_global_bindpwd;
}

sub test_ldap_password
{
  my ($host, $port, $binddn, $basedn, $passwd) = @_;
  if ($passwd eq "") {
      return 49;
  }
  system("$ldapsearch -1 -h '$host' -p $port -D '$binddn' -x -w $passwd -b '$basedn' -s base '(objectclass=*)' >/dev/null");
  return $? >>8;
}

1;
