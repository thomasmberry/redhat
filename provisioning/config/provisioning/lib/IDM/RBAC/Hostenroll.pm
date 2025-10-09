package IDM::RBAC::Hostenroll;

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

use lib qw(/home/icam/lib/);
use parent 'IDM::RBAC::Common';

our @EXPORT = qw(
new
);

our @EXPORT_OK = qw(
init
check
add_hostenroll_user
check_hostenroll_user
set_hostenroll_user
get_hostenroll_user
hostenroll_settings
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

   carp "IDM::RBAC::Hostenroll" if $self->is_troubleshoot();

   $self->set_namespace(); 
   $self->set_ucnamespace();

   $self->set_domainname();
   $self->set_short_domainname();

   $self->set_hostenroll_user();

   $self->set_nonperson_group();

   $self->set_permission_dir("/home/icam/JPL/config/hostenroll");
   $self->set_privilege_name(sprintf('%s %s', uc($self->get_hostenroll_user()), "Administration"));
   $self->set_role_name(sprintf('%s %s', uc($self->get_hostenroll_user()), "Administrator"));
   $self->gather_permissions();
   $self->permissions_format($self->get_hostenroll_permission_settings());
}

sub get_hostenroll_permission_settings
{
   my $self = shift or confess "failed object";
   my $replace = {
      hostenroll      => $self->get_hostenroll_user(),
      uchostenroll    => $self->get_uchostenroll_user(),
      namespace       => $self->get_namespace(),
      ucnamespace     => $self->get_ucnamespace(),
      shortdomainname => $self->get_short_domainname(),
   };
   return $replace;
}

sub check
{
   my $self = shift or confess "failed object";
   $self->check_hostenroll_user();
   $self->check_role("hostenroll");
   $self->check_privilege("hostenroll");
   $self->check_permissions();
}

sub add_hostenroll_user
{
   my $self = shift or confess "failed object";

   my %settings = $self->hostenroll_settings();

   $self->add_user( %settings );
   $self->detach_group($settings{uid});

   my @groups = (
      "enrollment_administrators",
      "automation_account_password_policy",
      $self->get_nonperson_group(),
   );

   foreach my $group (@groups) {
      $self->add_group_member($group, $settings{uid});
   }
}

sub check_hostenroll_user
{
   my $self = shift or confess "failed object";

   my $user = $self->get_hostenroll_user();

   FIND_USER:
   {
      my $result = $self->find_user($user);
      if ( $result ) {
         say "# GOOD: user $user" if $self->is_troubleshoot();
      }
      else {
         carp "# ERROR: user $user missing" if $self->is_troubleshoot();
         $self->add_hostenroll_user();
      }
   }

   GROUP_MEMBER:
   {
      my $nonperson_group = $self->get_nonperson_group();

      my @groups = (
         "enrollment_administrators",
	 "hostenroll_selfservice",
         "automation_account_password_policy",
         $nonperson_group,
      );

      foreach my $group (@groups) {
         my $result = $self->find_group_member( $group, $user );
         if ( $result ) {
            say "# GOOD: $group group member $user" if $self->is_troubleshoot();
         }
         else {
            carp "# ERROR: $group group member $user missing" if $self->is_troubleshoot();
            $self->add_group_member($group, $user);
         }
      }
   }
}

sub set_hostenroll_user
{
   my $self = shift or confess "failed object";

   my $namespace = $self->get_namespace() or confess "namespace not defined";
   my $hostenroll = sprintf("%s-hostenroll", $namespace);
   $self->{hostenroll_user} = lc($hostenroll);
   $self->{uchostenroll_user} = uc($hostenroll);
}

sub get_hostenroll_user
{
   my $self = shift or confess "failed object";

   if ( not defined $self->{hostenroll_user} ) {
      confess "hostenroll user not defined";
   }
   return $self->{hostenroll_user};
}

sub get_uchostenroll_user
{
   my $self = shift or confess "failed object";

   if ( not defined $self->{uchostenroll_user} ) {
      confess "uchostenroll user not defined";
   }
   return $self->{uchostenroll_user};
}

sub hostenroll_settings
{
   my $self = shift or confess "failed object";

   my $user = $self->get_hostenroll_user();

   my ($last) = $user =~ /\A(.+?)-/;
   my $first = "hostenroll";
   my $fullname = "$first $last";

   return (
      uid              => $user,
      last             => $last,
      first            => $first,
      cn               => $fullname,
      displayname      => $fullname,
      class            => "nonperson",
      "user-auth-type" => "password",
   );
}

1;
