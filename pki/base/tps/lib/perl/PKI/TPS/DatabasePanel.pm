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

package PKI::TPS::DatabasePanel;
$PKI::TPS::DatabasePanel::VERSION = '1.00';

use PKI::TPS::BasePanel;
our @ISA = qw(PKI::TPS::BasePanel);

sub new { 
    my $class = shift;
    my $self = {}; 

    $self->{"isSubPanel"} = \&is_sub_panel;
    $self->{"hasSubPanel"} = \&has_sub_panel;
    $self->{"isPanelDone"} = \&is_panel_done;
    $self->{"getPanelNo"} = &PKI::TPS::Common::r(8);
    $self->{"getName"} = &PKI::TPS::Common::r("Internal Database");
    $self->{"vmfile"} = "databasepanel.vm";
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
    &PKI::TPS::Wizard::debug_log("DatabasePanel: validate");
    return 1;
}

sub update
{
    my ($q) = @_;
    &PKI::TPS::Wizard::debug_log("DatabasePanel: update");
    my $instDir =  $::config->get("service.instanceDir");
    my $certdir = $::config->get("auth.instance.1.certdir") || "$instDir/conf";

    my $host = $q->param('host');
    my $port = $q->param('port');
    my $basedn = $q->param('basedn');
    my $database = $q->param('database');
    my $binddn = $q->param('binddn');
    my $bindpwd = $q->param('__bindpwd');
    my $secureconn = $q->param('secureConn') || "false";

    &PKI::TPS::Wizard::debug_log("DatabasePanel: host=$host port=$port basedn=$basedn");
    &PKI::TPS::Wizard::debug_log("DatabasePanel: database=$database binddn=$binddn");
    &PKI::TPS::Wizard::debug_log("DatabasePanel: secureconn=$secureconn");

    # try to make a connection
    # we need to test the ldaps connection first because testing an ldaps port with ldap:// will hang the query!
    my $hostport = $host . ":" . $port;
    my $ldap;
    my $msg;

    if (! ($ldap = &PKI::TPS::Common::test_and_make_connection($hostport, $secureconn, \$msg, $certdir))) { 
      &PKI::TPS::Wizard::debug_log("DatabasePanel: failed to connect to internal db: $msg");
      $::symbol{errorString} = $msg;
      return 0; 
    };

    $msg = $ldap->bind ( $binddn, version => 3, password => $bindpwd );
    if ($msg->is_error) {
      &PKI::TPS::Wizard::debug_log("DatabasePanel: failed to bind to the internal db: " . $msg->error_text);
      $::symbol{errorString} = "Failed to bind to the internal database";
      return 0;
    }

    # save values to CS.cfg
    $::config->put("preop.database.host", $host);
    $::config->put("preop.database.port", $port);
    $::config->put("preop.database.basedn", $basedn);
    $::config->put("preop.database.database", $database);
    $::config->put("preop.database.binddn", $binddn);
    $::config->put("tokendb.activityBaseDN", "ou=Activities," . $basedn);
    $::config->put("tokendb.baseDN", "ou=Tokens," . $basedn);
    $::config->put("tokendb.certBaseDN", "ou=Certificates," . $basedn);
    $::config->put("tokendb.hostport", $host . ":" . $port);
    $::config->put("tokendb.userBaseDN", $basedn);
    $::config->put("tokendb.ssl", $secureconn);
    $::config->put("auth.instance.1.hostport", $host . ":" . $port);
    $::config->put("auth.instance.1.baseDN", $basedn);
    $::config->put("auth.instance.1.ssl", $secureconn);
    $::config->commit();

#    $::config->put("tokendb.bindPass", $bindpwd);
    if ($bindpwd ne "") {
      open(PWD_CONF, ">>$instDir/conf/password.conf");
      print PWD_CONF "tokendbBindPass:$bindpwd\n";
      close (PWD_CONF);
    }

    my $rdn = $basedn;
    $rdn =~ s/,.*//g;
    my ($type, $value) = split(/=/, $rdn);
    my $objectclass = "domain";
    if ($type eq "O" || $type eq "o") {
      $objectclass = "organization";
    } elsif ($type eq "OU" || $type eq "ou") {
      $objectclass = "organizationalUnit";
    }

    my $flavor = `pkiflavor`;
    $flavor =~ s/\n//g;

    # creating database
    my $tmp = "/tmp/database-$$.ldif";
    system("sed -e 's/\$DATABASE/$database/' " .
              "-e 's/\$BASEDN/$basedn/' " .
              "-e 's/\$OBJECTCLASS/$objectclass/' " .
              "-e 's/\$TYPE/$type/' " .
              "-e 's/\$VALUE/$value/' " .
              "/usr/share/$flavor/tps/scripts/database.ldif > $tmp");
    if (! &PKI::TPS::Common::import_ldif($ldap, $tmp, \$msg)) { 
      &PKI::TPS::Wizard::debug_log("DatabasePanel: $msg");
      $::symbol{errorString} = "Failed to create database";
      $ldap->unbind();
      return 0; 
    };
    system("rm $tmp");

    # add schema
    if (! &PKI::TPS::Common::import_ldif($ldap, "/usr/share/$flavor/tps/scripts/schemaMods.ldif", \$msg)) { 
      &PKI::TPS::Wizard::debug_log("DatabasePanel: $msg");
      $::symbol{errorString} = "Failed to add schema";
      $ldap->unbind();
      return 0; 
    };

    # populate database
    $tmp = "/tmp/addTokens-$$.ldif";
    system("sed -e 's/\$TOKENDB_ROOT/$basedn/g' " .
              "/usr/share/$flavor/tps/scripts/addTokens.ldif > $tmp");
    if (! &PKI::TPS::Common::import_ldif($ldap, $tmp, \$msg)) { 
      &PKI::TPS::Wizard::debug_log("DatabasePanel: $msg");
      $::symbol{errorString} = "Failed to populate database";
      $ldap->unbind();
      return 0; 
    };
    system("rm $tmp");

    # add regular indexes
    $tmp = "/tmp/addIndexes-$$.ldif";
    system("sed -e 's/userRoot/$database/g' " .
              "/usr/share/$flavor/tps/scripts/addIndexes.ldif > $tmp");
    if (! &PKI::TPS::Common::import_ldif($ldap, $tmp, \$msg)) { 
      &PKI::TPS::Wizard::debug_log("DatabasePanel: $msg");
      $::symbol{errorString} = "Failed to add indexes";
      $ldap->unbind();
      return 0; 
    };
    system("rm $tmp");

    # add VLV indexes
    $tmp = "/tmp/addVLVIndexes-$$.ldif";
    system("sed -e 's/userRoot/$database/g;s/\$TOKENDB_ROOT/$basedn/g' " .
              "/usr/share/$flavor/tps/scripts/addVLVIndexes.ldif > $tmp");
    if (! &PKI::TPS::Common::import_ldif($ldap, $tmp, \$msg)) { 
      &PKI::TPS::Wizard::debug_log("DatabasePanel: $msg");
      $::symbol{errorString} = "Failed to add vlv indexes";
      $ldap->unbind();
      return 0; 
    };
    system("rm $tmp");

    $ldap->unbind();

    $::config->put("preop.database.done", "true");
    $::config->commit();

    return 1;
}

sub display
{
    my ($q) = @_;
    &PKI::TPS::Wizard::debug_log("DatabasePanel: display");

    my $machineName = $::config->get("service.machineName");
    my $instanceId =  $::config->get("service.instanceID");

    my $host = $::config->get("preop.database.host") || "";
    $::symbol{hostname} = "localhost"; # default
    if ($host ne "") {
      $::symbol{hostname} = $host;
    }
    my $port = $::config->get("preop.database.port") || "";
    $::symbol{portStr} = "389";
    if ($port ne "") {
      $::symbol{portStr} = $port;
    }
    my $basedn = $::config->get("preop.database.basedn") || "";
    $::symbol{basedn} = "dc=" . $machineName . "-" . $instanceId;
    if ($basedn ne "") {
      $::symbol{basedn} = $basedn;
    }
    my $database = $::config->get("preop.database.database") || "";
    $::symbol{database} = $machineName . "-" . $instanceId;
    if ($database ne "") {
      $::symbol{database} = $database;
    }
    my $binddn = $::config->get("preop.database.binddn") || "";
    $::symbol{binddn} = "cn=directory manager";
    if ($binddn ne "") {
      $::symbol{binddn} = $binddn;
    }
    
    my $secureconn = $::config->get("auth.instance.1.ssl") || "false";
    $::symbol{secureconn} =  $secureconn;

    $::symbol{bindpwd} = "";

    return 1;
}

sub is_panel_done
{
   return $::config->get("preop.database.done");
}


1;
