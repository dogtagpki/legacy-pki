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

package PKI::TPS::Common;

use strict;
use warnings;
use Exporter;
use Net::LDAP;
use Net::LDAP::LDIF;

use vars qw(@ISA @EXPORT @EXPORT_OK);
@ISA = qw(Exporter Autoloader);
@EXPORT = qw(r yes no import_ldif test_and_make_connection make_connection);

$PKI::TPS::Common::VERSION = '1.00';

sub yes { 
  return sub {1}; 
}

sub no { 
  return sub {0}; 
}

sub r { 
  my $a = shift; 
  return sub { $a; } 
}

sub import_ldif
{
  my ($ldap, $ldif_file, $msg_ref) = @_;
  my $ldif = Net::LDAP::LDIF->new( $ldif_file, "r", onerror => 'undef' );
  while( not $ldif->eof () ) {
    my $entry = $ldif->read_entry ( );
    if ( $ldif->error () ) {
      $$msg_ref = "Error parsing LDIF:" . $ldif->error() . "\n" . $ldif->error_lines();
      return 0;
    } else {
      $entry->update($ldap);
    }
  }
  $ldif->done();
  return 1;
}

sub test_and_make_connection 
{
  my ($hostport, $secureconn, $msg_ref, $certdir) = @_; 
  my $ldap;
  if ( $ldap = Net::LDAP->new ( "ldaps://$hostport", timeout => 30, capath => $certdir , verify => "require", inet6 => 1 )) { #ldaps succeeds
    if ($secureconn eq "false") {
      $$msg_ref = "SSL not selected, but this looks like an SSL port.";
      return undef;
    }
  } else { #ldaps failed
    if ($secureconn eq "true") {
      $$msg_ref = "Failed to connect to LDAPS port: $@";
      return undef;
    }
    if (! ($ldap = Net::LDAP->new ( "ldap://$hostport", timeout => 30, inet6 =>1 ))) { 
      $$msg_ref = "Failed to connect to LDAP port: $@";
      return undef;
    }
  }
  return $ldap;
}

sub make_connection
{
  my ($hostport, $secureconn, $msg_ref, $certdir) =@_;
  my $ldap;
  if ($secureconn eq "false") {
    $ldap = Net::LDAP->new ( "ldap://$hostport", timeout => 30, inet6 => 1 );
  } else {
    $ldap = Net::LDAP->new ( "ldaps://$hostport", timeout => 30, capath => $certdir, verify => "require", inet6 => 1 );
  }
  if (!$ldap) {
    $$msg_ref="$@";
    return undef;
  }
  return $ldap;
}


1;
