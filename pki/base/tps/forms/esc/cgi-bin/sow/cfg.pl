#! /usr/bin/perl
#
# --- BEGIN COPYRIGHT BLOCK ---
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation.
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

use lib "/usr/share/pki/tps/lib/perl";
use Net::LDAP;
use Net::LDAP::Constant;
use PKI::TPS::Common;
require PKI::TPS::Startup;

#
# Feel free to modify the following parameters:
#
my $ldapHost = "localhost";
my $ldapPort = "389";
my $basedn = "ou=People,dc=sfbay,dc=redhat,dc=com";
my $port = "7888";
my $secure_port = "7889";
my $host = "localhost";

my $cfg = "[SERVER_ROOT]/conf/CS.cfg";

sub get_ldap_hostport()
{
  my $ldapport = `grep auth.instance.0.hostport $cfg | cut -c26-`;
  chomp($ldapport);
  return $ldapport;  
}

sub get_ldap_secure()
{
  my $ldapsecure = `grep auth.instance.0.ssl $cfg | cut -c21-`;
  chomp($ldapsecure);
  return $ldapsecure;
}

sub get_ldap_certdir()
{
  my $ldapcertdir = `grep auth.instance.0.certdir $cfg | cut -c25-`;
  chomp($ldapcertdir);
  return $ldapcertdir;
}

sub get_base_dn()
{
  my $basedn = `grep auth.instance.0.baseDN $cfg | cut -c24-`;
  chomp($basedn);
  return $basedn;
}

sub get_port()
{
  my $port = `grep service.unsecurePort $cfg | cut -c22-`;
  chomp($port);
  return $port;
}

sub get_secure_port()
{
  my $secure_port = `grep service.securePort $cfg | cut -c20-`;
  chomp($secure_port);
  return $secure_port;
}

sub get_host()
{
  my $host = `grep service.machineName $cfg | cut -c21-`;
  chomp($host);
  return $host;
}

sub is_agent()
{
  my ($dn) = @_;

  my $uid = $dn;
  # need to map a subject dn into user DN
  $uid =~ /uid=([^,]*)/; # retrieve the uid
  $uid = $1;

  my $x_hostport = `grep -e "^tokendb.hostport" $cfg | cut -c18-`;
  chomp($x_hostport);
  my $x_secureconn = `grep -e "^tokendb.ssl" $cfg | cut -c13-`;
  chomp($x_secureconn);
  my $x_basedn = `grep -e "^tokendb.userBaseDN" $cfg | cut -c20-`;
  chomp($x_basedn);
  my $x_binddn = `grep -e "^tokendb.bindDN" $cfg | cut -c16-`;
  chomp($x_binddn);
  my $x_bindpwd = PKI::TPS::Startup::global_bindpwd();
  chomp($x_bindpwd);
  my $x_certdir = `grep -e "^tokendb.certdir" $cfg | cut -c17-`;
  chomp($x_certdir);


  my $ldap;
  my $msg;
  return 0 if (! ($ldap = &PKI::TPS::Common::make_connection($x_hostport, $x_secureconn, \$msg, $certdir)));

  $msg = $ldap->bind ( $x_binddn,  version => 3, password => $x_bindpwd );
  return 0 if ($msg->is_error);

  $msg = $ldap->search ( base => "cn=TUS Officers,ou=Groups,$x_basedn",
                         scope   => "sub",
                         filter  => "uid=$uid",
                         attrs   =>  []
                       );
  if ($msg->is_error) {
    $ldap->unbind();
    return 0;
  }
 
  if ($msg->count() > 0) {
    return 1;
  } 
  
  return 0;
}

sub is_user()
{
  my ($dn) = @_;

  my $uid = $dn;
  # need to map a subject dn into user DN
  $uid =~ /uid=([^,]*)/; # retrieve the uid
  $uid = $1;

  my $x_hostport = get_ldap_hostport();
  my $x_secureconn = get_ldap_secure();
  my $x_basedn = get_base_dn();
  my $x_certdir = get_ldap_certdir();

  my $ldap;
  my $msg;
  return 0 if (! ($ldap = &PKI::TPS::Common::make_connection($x_hostport, $x_secureconn, \$msg, $certdir)));

  $msg = $ldap->bind ( version => 3 );
  return 0 if ($msg->is_error);

  $msg = $ldap->search ( base => "ou=people,$x_basedn",
                         scope   => "sub",
                         filter  => "uid=$uid",
                         attrs   =>  []
                       );
  if ($msg->is_error) {
    $ldap->unbind();
    return 0;
  }

  if ($msg->count() > 0) {
    return 1;
  }
  return 0;
}
