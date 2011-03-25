#! /usr/bin/perl -w
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

use CGI;
use Net::LDAP;
use Net::LDAP::Constant;
use PKI::TPS::Common;
no warnings qw(redefine);

require "[SERVER_ROOT]/cgi-bin/sow/cfg.pl";

sub main()
{

  my $q = new CGI;

  my $hostport = get_ldap_hostport();
  my $secureconn = get_ldap_secure();
  my $basedn = get_base_dn();
  my $certdir = get_ldap_certdir();

  my $letters = $q->param('letters');
  if ($letters eq "") {
    # HACK: ajax.js posts parameters into POST URL
    $letters = $ENV{'QUERY_STRING'};
    $letters =~ s/.*letters=//g;
    $letters =~ s/\+/ /g;
  }

  my $ldap;
  my $msg;
  my $result = "";

  print "Content-Type: text/html\n\n";
  
  if (! ($ldap = &PKI::TPS::Common::make_connection($hostport, $secureconn, \$msg, $certdir))) {
    return;
  };

  $msg = $ldap->bind ( version => 3 );
  if ($msg->is_error) {
    return;
  }

  $msg = $ldap->search ( base => $basedn,
                         scope   => "sub",
                         filter  => "cn=$letters*",
                         attrs   =>  ["cn", "uid"]
                       );
  if ($msg->is_error) {
    $ldap->unbind();
    return;
  }

  my @entries = $msg->sorted("cn");
  foreach my $entry (@entries) {
    my $cn = $entry->get_value("cn") || ""; 
    my $uid = $entry->get_value("uid") || "";
    $result .= $uid . "###" . $cn . "|";
  }

  $ldap->unbind();

  print $result;
}

&main();
