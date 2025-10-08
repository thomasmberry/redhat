package IDM::RBAC::Admin;

use strict;
use Data::Dumper;
use Sys::Hostname;
use Carp qw(carp confess);
use YAML::Tiny;
use feature 'say';
use constant {
   true  => 1,
   false => 0,
};
use lib qw(/home/icam/lib);
use parent 'IDM::RBAC::Common';

our @EXPORT = qw(
new
);

our @EXPORT_OK = qw(
init
check
add_group_admin
set_group_admin
check_group_admin
check_privilege_admin
add_role_admin
check_role_admin
);

sub new
{
   my $class = shift or confess "failed object";
   my ($self) = @_; # common settings
   bless $self, $class;
   return $self;
}

sub init
{
   my $self = shift or confess "failed object";

   say("IDM::RBAC::Admin") if $self->is_troubleshoot();

   $self->set_domainname();
   $self->set_short_domainname();

   $self->set_namespace();
   $self->set_ucnamespace();

   $self->set_group_owner();
   $self->set_group_admin();

   $self->set_permission_dir("/home/icam/JPL/config/admin");
   $self->set_privilege_name(sprintf('%s %s', $self->get_ucnamespace(), "Administration"));
   $self->set_role_name(sprintf('%s %s', $self->get_ucnamespace(), "Administrator"));
 
   $self->gather_permissions();
   $self->permissions_format($self->get_admin_permission_settings());
}

sub get_admin_permission_settings
{
   my $self = shift or confess "failed object";
   my $replace = {
      namespace       => $self->get_namespace(),
      ucnamespace     => $self->get_ucnamespace(),
      shortdomainname => $self->get_short_domainname(),
      group_admin     => $self->get_group_admin(),
   };
   return $replace;
}

sub check
{
   my $self = shift or confess "failed object";

   $self->check_group_admin();
   $self->check_role_admin();
   $self->check_privilege_admin();
   $self->check_permissions();
   $self->check_group_nonperson();
}

sub add_group_admin
{
   my $self = shift or confess "failed object";
   my $type = "admin";
   $self->add_group_role($type);
}

sub set_group_admin
{
   my $self = shift or confess "failed object";

   my $namespace = $self->get_namespace();
   my $type = "admin";
   my $group = "${namespace}.${type}";
   my $attr = "group_${type}";
   $self->{$attr} = $group;
}

sub check_group_admin
{
   my $self = shift or confess "failed object";
   $self->check_group_role("admin");
}

sub check_privilege_admin
{
   my $self = shift or confess "failed object";
   $self->check_privilege("admin");
}

sub add_role_admin
{
   my $self = shift or confess "failed object";
   $self->add_role("admin");
}

sub check_role_admin
{
   my $self = shift or confess "failed object";
   $self->check_role("admin");
}

1;
