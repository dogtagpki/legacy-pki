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
# Copyright (C) 2007 Red Hat, Inc.
# All rights reserved.
# --- END COPYRIGHT BLOCK ---
#

use strict;
use warnings;
use PKI::TPS::GlobalVar;
use PKI::TPS::Common;
use Net::LDAP;

package PKI::TPS::AuthDBPanel;
$PKI::TPS::AuthDBPanel::VERSION = '1.00';

use PKI::TPS::BasePanel;
our @ISA = qw(PKI::TPS::BasePanel);

sub new { 
    my $class = shift;
    my $self = {}; 

    $self->{"isSubPanel"} = \&is_sub_panel;
    $self->{"hasSubPanel"} = \&has_sub_panel;
    $self->{"isPanelDone"} = \&is_panel_done;
    $self->{"getPanelNo"} = &PKI::TPS::Common::r(7);
    $self->{"getName"} = &PKI::TPS::Common::r("Authentication Directory");
    $self->{"vmfile"} = "authdbpanel.vm";
    $self->{"update"} = \&update;
    $self->{"panelvars"} = \&display;
    bless $self,$class; 
    return $self; 
}

sub is_sub_panel
{
    my ($q) = @_;
    return 0;
}

sub has_sub_panel
{
    my ($q) = @_;
    return 0;
}

sub validate
{
    my ($q) = @_;
    &PKI::TPS::Wizard::debug_log("AuthDBPanel: validate");
    return 1;
}

sub update
{
    my ($q) = @_;
    &PKI::TPS::Wizard::debug_log("AuthDBPanel: update");

    my $host = $q->param('host');
    my $port = $q->param('port');
    my $basedn = $q->param('basedn');
    my $secureconn = $q->param('secureConn') || "false";
    my $instDir =  $::config->get("service.instanceDir");
    my $certdir = $::config->get("auth.instance.0.certdir") || "$instDir/conf";

    &PKI::TPS::Wizard::debug_log("AuthDBPanel: host=" . $host);
    &PKI::TPS::Wizard::debug_log("AuthDBPanel: port=" . $port);
    &PKI::TPS::Wizard::debug_log("AuthDBPanel: basedn=" . $basedn);
    &PKI::TPS::Wizard::debug_log("AuthDBPanel: secureconn=" . $secureconn);

    if (!($port =~ /^[0-9]+$/)) {
      &PKI::TPS::Wizard::debug_log("AuthDBPanel: bad port " . $port);
      $::symbol{errorString} = "Bad Port";
      return 0;
    }

    # try to make a connection
    # we need to test the ldaps connection first because testing an ldaps port with ldap:// will hang the query!
    my $hostport = $host . ":" . $port;
    my $ldap;
    my $msg;
    if (! ($ldap = &PKI::TPS::Common::test_and_make_connection($hostport, $secureconn, \$msg, $certdir))) { 
      &PKI::TPS::Wizard::debug_log("AuthDBPanel: failed to connect to auth db: $msg");
      $::symbol{errorString} = $msg;
      return 0; 
    };

    $msg = $ldap->bind ( version => 3 );
    if ($msg->is_error) {
      &PKI::TPS::Wizard::debug_log("AuthDBPanel: failed to bind to the db: " . $msg->error_text);
      $::symbol{errorString} = "Failed to bind to the authentication database";
      return 0;
    }

    $msg = $ldap->search ( base => $basedn,
                           scope   => "base",
                           filter  => "objectclass=*",
                           attrs   =>  []
                         );
    if ($msg->is_error) {
      &PKI::TPS::Wizard::debug_log("AuthDBPanel: search for basedn failed: " . $msg->error_text);
      $::symbol{errorString} = "Search for base DN failed. Does the base DN exist?";
      $ldap->unbind();
      return 0;
    }

    &PKI::TPS::Wizard::debug_log("AuthDBPanel: auth database looks ok");

    $ldap->unbind();

    # save values to CS.cfg
    $::config->put("auth.instance.0.baseDN", $basedn);
    $::config->put("auth.instance.0.hostport", $host . ":" . $port);
    $::config->put("auth.instance.0.ssl", $secureconn);
    $::config->put("preop.authdb.done", "true");
    $::config->commit();

    return 1;
}

sub display
{
    my ($q) = @_;
    &PKI::TPS::Wizard::debug_log("AuthDBPanel: display");

    my $machineName = $::config->get("service.machineName");
    my $instanceId = $::config->get("service.instanceID");

    my $basedn = $::config->get("auth.instance.0.baseDN");
    if ($basedn =~ /\[/) {
      $basedn = $machineName;    
      $basedn =~ s/^[^.]+\.//;
      if ($basedn eq "") {
        $basedn = "dc=" . $machineName;    
      } else {
        $basedn =~ s/\./,dc=/g;
        $basedn = "dc=" . $basedn;
      }
    }
    my $host = "";
    my $port = "";
    my $hostport = $::config->get("auth.instance.0.hostport");
    if ($hostport =~ /\[/) {
      $host = "localhost";
      $port = "389";
    } else {
      my ($hostx, $portx) = split(/:/, $hostport);
      $host = $hostx;
      $port = $portx;
    }

    my $secureconn = $::config->get("auth.instance.0.ssl") || "false";

    $::symbol{hostname} = $host;
    $::symbol{portStr} = $port;
    $::symbol{basedn} = $basedn;
    $::symbol{secureconn}=$secureconn;

    return 1;
}

sub is_panel_done
{
   return $::config->get("preop.authdb.done");
}

1;
