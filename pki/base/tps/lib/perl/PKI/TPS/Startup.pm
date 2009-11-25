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
use Pkidogclient;

package PKI::TPS::Startup;
$PKI::TPS::Startup::VERSION = '1.00';

my $x_global_bindpwd;
my $logfile;

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

  #read password file
  my $pwdfile = $config->get("tokendb.bindPassPath");
  if ((-e $pwdfile) && (-r $pwdfile)) {
    $x_global_bindpwd = `grep -e "^tokendbBindPass" $pwdfile | cut -c17-`;
    if ($x_global_bindpwd) {
      return Apache2::Const::OK;
    }
  }

  &debug_log("startup::post_config: bindpwd not found. Prompting for it");

  #initialize client socket connection - TODO: check status
  my $status = Pkidogclient::call_WatchdogClient_init();
  &debug_log("startup::post_config: watchdog client initialized.");

  #get password
  my $prompt = "Please enter the password for tokendbBindPass:";
  $x_global_bindpwd = Pkidogclient::call_WatchdogClient_getPassword($prompt, 0);

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

1;
