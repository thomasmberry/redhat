#!/usr/bin/perl
$|++; # disable stdout queue

use strict;
use Data::Dumper;
use Sys::Hostname;
use Carp qw(carp confess croak);
use feature 'say';
use lib qw (/home/icam/JPL/lib);
use IDM::RBAC::Common;
use IDM::RBAC::Owner;
use IDM::RBAC::Admin;
use IDM::RBAC::Hostenroll;
use Getopt::Long qw(GetOptions);

GetOptions(
   'n|ns|namespace=s' => \my $namespace,
   't|troubleshoot'   => \my $TROUBLESHOOT,
   'h|help'           => \my $HELP,
);

usage() if $HELP;

my %settings;
$settings{namespace}    = $namespace    if defined $namespace;

MAIN:
{
   my $rbac = IDM::RBAC::Common->new(\%settings);
   $rbac->init();
   $rbac->set_troubleshoot($TROUBLESHOOT);

   my @namespaces = defined $namespace ? ($namespace) : $rbac->get_namespaces();

   foreach my $namespace (@namespaces) {
      confess "namespace not defined" unless defined $namespace and length $namespace > 0;

      say("$namespace") if $rbac->is_troubleshoot();

      $rbac->set_namespace($namespace);

      # ADMIN not directly associated with OWNER
      my $admin = IDM::RBAC::Admin->new($rbac->get_settings());
      $admin->init();
      $admin->check();

      # OWNER dependency on ADMIN, must follow ADMIN setup
      my $owner = IDM::RBAC::Owner->new($rbac->get_settings());
      $owner->init();
      $owner->check();
   
      # HOSTENROLL 
      my $hostenroll = IDM::RBAC::Hostenroll->new($rbac->get_settings());
      $hostenroll->init();
      $hostenroll->check();

      $rbac->get_existing_rbac();
      $rbac->discard_invalid_rbac(
         admin      => $admin,
         owner      => $owner,
	 hostenroll => $hostenroll,
      );
   }
}

sub usage
{
   say "usage:
     validate all namespace; display only ipa commands
      : $0 

     validate all namespace; verbose output
      : $0 --troubleshoot

     validate specific namespace; display only ipa commands
      : $0 --namespace=acme

     validate specific namespace; verbose output
      : $0 --namespace=acme --troubleshoot
   ";

   exit;
}

