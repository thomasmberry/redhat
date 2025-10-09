package IDM::RBAC::Owner;

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
add_group_owner
check_group_owner
check_privilege_owner
check_owner_role
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

   my %settings = @_;

   $self->set_troubleshoot($settings{troubleshoot});

   say("IDM::RBAC::Owner") if $self->is_troubleshoot();

   $self->set_namespace($settings{namespace});
   $self->set_namespace();
   $self->set_ucnamespace();
   $self->set_domainname();
   $self->set_short_domainname();
   $self->set_group_owner();
   $self->set_group_admin();
   $self->set_permission_dir("/home/icam/JPL/config/owner");
   $self->set_role_name(sprintf('%s %s', $self->get_ucnamespace(), "Owner Administrator"));
   $self->set_privilege_name(sprintf('%s %s', $self->get_ucnamespace(), "Owner Administration"));
 
   $self->gather_permissions();
   $self->permissions_format($self->get_owner_permission_settings());
}

sub get_owner_permission_settings
{
   my $self = shift or confess "failed object";
   my $replace = {
      namespace       => $self->get_namespace(),
      ucnamespace     => $self->get_ucnamespace(),
      shortdomainname => $self->get_short_domainname(),
      group_admin     => $self->get_group_admin(),
      group_owner     => $self->get_group_owner(),
   };
   return $replace;
}

sub check
{
   my $self = shift or confess "failed object";

   $self->check_group_owner();
   $self->check_owner_role();
   $self->check_privilege_owner();
   $self->check_permissions();
}

sub add_group_owner
{
   my $self = shift or confess "failed object";
   my $type = "owner";
   $self->add_group_role($type);
}

sub check_group_owner
{
    my $self = shift or confess "failed object";
    $self->check_group_role("owner");
}

sub check_privilege_owner
{
   my $self = shift or confess "failed object";
   $self->check_privilege("owner");
}

sub check_owner_role 
{
   my $self = shift or confess "failed object";
   $self->check_role("owner");
}

1;
