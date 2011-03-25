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

sub authorize
{
  my $client_dn = $ENV{'SSL_CLIENT_S_DN'};
  $client_dn =~ tr/A-Z/a-z/; # all lower cases
  $client_dn =~ s/\s+//g;    # remove all spacing

  if (&is_agent($client_dn)) {
    return 1;
  }
  return 0;
}

sub DoPage
{
  my $q = new CGI;
  my $hostport = get_ldap_hostport();
  my $secureconn = get_ldap_secure();
  my $basedn = get_base_dn();
  my $certdir = get_ldap_certdir();

  if (!&authorize()) {
    print $q->redirect("/cgi-bin/sow/noaccess.cgi");
    return;
  }

  my $name = $q->param('name');
  my $uid = $q->param('name_ID');
  $name = "" if !defined $name;

  if ($name eq "") {
    print $q->redirect("/cgi-bin/sow/search.cgi?error=Name cannot be empty");
    return;
  }

  my $ldap;
  my $msg;
  if (! ($ldap = &PKI::TPS::Common::make_connection($hostport, $secureconn, \$msg, $certdir))) {
    print $q->redirect("/cgi-bin/sow/search.cgi?error=Failed to connect to the database. $msg");
    return;
  };

  $msg = $ldap->bind ( version => 3 );
  if ($msg->is_error) {
    print $q->redirect("/cgi-bin/sow/search.cgi?error=Failed to bind to the database. " . $msg->error_text);
    return;
  }

  $msg = $ldap->search ( base => $basedn,
                         scope   => "sub",
                         filter  => "cn=$name",
                         attrs   =>  []
                       );

  if ($msg->is_error) {
    $ldap->unbind();
    print $q->redirect("/cgi-bin/sow/search.cgi?error=Search failed: " . $msg->error_text);
    return;
  }

  if ($msg->count() < 1) {
    $ldap->unbind();
    print $q->redirect("/cgi-bin/sow/search.cgi?error=User $name not found");
    return;
  }

  my $entry = $msg->entry(0);
  
  my $givenName = $entry->get_value("givenName") ||  "-";
  my $cn = $entry->get_value("cn") || "-";
  my $sn = $entry->get_value("sn") ||"-";
  $uid = $entry->get_value("uid") || "-";
  my $mail = $entry->get_value("mail") || "-";
  my $phone = $entry->get_value("telephoneNumber") || "-";
  my $photoLarge = $entry->get_value("photoLarge") || ""; # photo (full size)
  my $photoSmall = $entry->get_value("photoSmall") || ""; # photo (thumb)
  my $height = $entry->get_value("height") || "";
  my $weight = $entry->get_value("weight") || "";
  my $eyecolor = $entry->get_value("eyeColor") || "";

  $ldap->unbind();

  if ($uid eq "-") {
    print $q->redirect("/cgi-bin/sow/search.cgi?error=User $name not found");
    return;
  }

  open(FILE, "< [SERVER_ROOT]/cgi-bin/sow/read_temp.html");

  print $q->header();

  while ($l = <FILE>)
  {
      $l =~ s/\$mail/$mail/g;
      $l =~ s/\$uid/$uid/g;
      $l =~ s/\$givenName/$givenName/g;
      $l =~ s/\$sn/$sn/g;
      $l =~ s/\$cn/$cn/g;
      $l =~ s/\$phone/$phone/g;
      $l =~ s/\$photoLarge/$photoLarge/g;
      $l =~ s/\$photoSmall/$photoSmall/g;
      $l =~ s/\$height/$height/g;
      $l =~ s/\$weight/$weight/g;
      $l =~ s/\$eyecolor/$eyecolor/g;
      print $l;
  }

  close(FILE);
}

&DoPage(); 
