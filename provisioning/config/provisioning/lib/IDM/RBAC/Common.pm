package IDM::RBAC::Common;

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

our @EXPORT = qw(
new
);

our @EXPORT_OK = qw(
init
get_settings
set_troubleshoot
get_troubleshoot
is_troubleshoot
set_namespace
get_namespace
get_namespaces
set_ucnamespace
get_ucnamespace
set_domainname
get_domainname
set_short_domainname
get_short_domainname
add_group_role
get_group_role
check_group_role
get_group_admin
set_group_owner
get_group_owner
set_group_nonperson
get_group_nonperson
check_group_nonperson
get_existing_rbac
discard_invalid_rbac
get_permission
get_permission_name
get_permissions
set_permission_dir
get_permission_dir
set_permission_files
gather_permissions
check_permissions
set_current_permissions
permissions_format
add_privilege
del_privilege
check_privilege
show_privilege
privilege_content
role_content
apply_role_add_privilege
apply_role_add_member
add_role
provision_role
assign_privilege_permission
get_permission_settings
add_permission
del_permission
get_permission_aci
construct_aci
check_role
report
get_nonperson_group
set_nonperson_group
get_privilege_name
set_privilege_name
get_role_name
set_role_name
set_group_admin
add_user
detach_group
modify_user
add_group_member
find_user
find_group_member
);

sub new
{
   my $class = shift or confess "failed object";
   my ($self) = @_;
   bless $self, $class;
   return $self;
}

sub init
{
   my $self = shift or confess "failed object";

   carp "IDM::RBAC::Common" if $self->is_troubleshoot();

   $self->set_domainname();
   $self->set_short_domainname();
   $self->set_namespace();
   $self->set_ucnamespace();
}

sub get_settings
{
   my $self = shift or confess "failed object";

   my $settings = {
      troubleshoot         => $self->get_troubleshoot(),
      domainname           => $self->get_domainname(),
      set_short_domainname => $self->get_short_domainname(),
      namespace            => $self->get_namespace(),
      ucnamespace          => $self->get_ucnamespace(),
   };

   return $settings;
}

sub set_troubleshoot
{
   my $self = shift or confess "failed object";
   my $setting = shift;
   if ( defined $setting and length $setting > 0 ) {
      $self->{troubleshoot} = $setting;
   }
   else {
      $self->{troubleshoot} = false;
   }
}

sub get_troubleshoot
{
   my $self = shift or confess "failed object";
   $self->set_troubleshoot(false) if not defined $self->{troubleshoot};
   return $self->{troubleshoot};
}

sub is_troubleshoot
{
   my $self = shift or confess "failed object";
   my $troubleshoot = $self->get_troubleshoot();
   return $troubleshoot;
}

sub set_namespace
{
   my $self = shift or confess "failed object";
   my $namespace = shift or return;
   $self->{namespace} = lc($namespace);
}

sub get_namespace
{
   my $self = shift or confess "failed object";
   return $self->{namespace};
}

sub get_namespaces
{
   my $self = shift or confess "failed object";

   my $namespace = $self->get_namespace();

   if ( defined $namespace ) {
      return ($namespace);
   }

   my @namespaces;

   my $command = "ipa group-show namespaces --all --raw | grep \"^  member:\" | grep \"\\.admin\" 2>/dev/null";

   foreach my $dn (`$command`) {
      chomp $dn;
      my ($namespace) = $dn =~ /cn=(.+?)\.admin/;
      push @namespaces, $namespace;
   }

   $self->{namespaces} = \@namespaces;

   return @namespaces;
}

sub set_ucnamespace
{
   my $self = shift or confess "failed object";
   my $namespace = $self->get_namespace();
   my $ucnamespace = uc($namespace);
   $self->{ucnamespace} = $ucnamespace;
}

sub get_ucnamespace
{
   my $self = shift or confess "failed object";

   if ( not defined $self->{namespace} ) {
      confess "upper-case namespace missing";
   }
   return $self->{ucnamespace};
}

sub set_domainname
{
   my $self = shift or confess "failed object";

   my $domainname = `domainname`;
   chomp $domainname;
   if ( not defined $domainname or length $domainname == 0 ) {
      confess "unable to obtain domainname";
   }

   $self->{domainname} = $domainname;
}

sub get_domainname
{
   my $self = shift or confess "failed object";

   if ( not defined $self->{domainname} ) {
      confess "domainname not defined";
   }
   return $self->{domainname};
}

sub set_short_domainname
{
   my $self = shift or confess "failed object";
   my $domainname = $self->get_domainname();
   my ($shortdomainname) = $domainname =~ /\A(.+?)\./;
   if ( not defined $shortdomainname or length $shortdomainname == 0 ) {
      confess "short domainname cannot be defined";
   }
   $self->{shortdomainname} = $shortdomainname;
}

sub get_short_domainname
{
   my $self = shift or confess "failed object";

   if ( not defined $self->{shortdomainname} and length $self->{shortdomainname} == 0 ) {
      confess("short domainname not defined");
   }
   return $self->{shortdomainname};
}

sub add_group
{
   my $self = shift or confess "failed object";
   my %settings = @_ or confess "settings missing";

   confess "settings:group missing" if not defined $settings{group};

   my $group = $settings{group};
   delete $settings{group};

   my $command = sprintf('ipa group-add %s', $group);

   foreach my $setting ( keys %settings ) {
      my $value = defined $settings{$setting} ? $settings{$setting} : "";
      if ( length $value ) {
         $command .= sprintf(' --%s="%s"', $setting, $value);
      }
      else {
         $command .= sprintf(' --%s', $setting);
      }
   }
   say $command;
}

sub add_group_member
{
   my $self = shift or confess "failed object";
   my $group = shift or confess "group missing";
   my @members = @_ or confess "members missing";

   my $command = sprintf('ipa group-add-member %s', $group);

   if ( @members > 1 ) {
      my $members = join ",", @members;
      $command .= sprintf(' --users={%s}', $members);
   }
   else {
      my ($members) = @members;
      $command .= sprintf(' --users=%s', $members);
   }
   say $command;
}

sub add_group_nested
{
   my $self = shift or confess "failed object";
   my $group = shift or confess "group missing";
   my @groups = @_ or confess "members missing";

   my $command = sprintf('ipa group-add-member %s', $group);

   if ( @groups > 1 ) {
      my $groups = join ",", @groups;
      $command .= sprintf(' --groups={%s}', $groups);
   }
   else {
      my ($groups) = @groups;
      $command .= sprintf(' --groups=%s', $groups);
   }
   say $command;
}

sub add_group_role
{
   my $self = shift or confess "failed object";
   my $type = shift or confess "group role missing (admin,owner,hostenroll)";

   return if $type eq "hostenroll";

   my $function = "get_group_${type}";
   my $group = $self->$function(); # get_group_admin get_group_owner

   ADD_ADMIN_GROUP:
   {
      $self->add_group(
         group    => $group,
         nonposix => '',
      )
   }

   APPLY_TO_NAMESPACES:
   {
      $self->add_group_nested('namespaces', $group);
   }
}

sub get_group_role
{
   my $self = shift or confess "failed object";
   my $type = shift or confess "role type missing";
   return if $type eq "hostenroll";
   my $group_type = "get_group_${type}";
   return $self->$group_type();
}

sub check_group_role
{
   my $self = shift or confess "failed object";
   my $type = shift or confess "group role missing";

   my $group_role = "get_group_${type}";
   my $group = $self->$group_role();

   my $result = $self->check_group($group);
   if ( $result ) {
      say "# GOOD: group $group" if $self->is_troubleshoot();
   }
   else {
      carp "# ERROR: group $group missing" if $self->is_troubleshoot();
      $self->add_group_role($type);
   }
}

sub check_group
{
   my $self = shift or confess "failed object";
   my $group = shift or confess "group missing";
   my $command = sprintf('ipa group-show %s >/dev/null 2>&1', $group);
   my $result = system($command);
   if ( $result == 0 ) {
      return true;
   }
   else {
      return false;
   }
}

sub get_group_admin
{
   my $self = shift or confess "failed object";
   return $self->{group_admin};
}

sub set_group_owner
{
   my $self = shift or confess "failed object";

   my $namespace = $self->get_namespace();
   my $type = "owner";
   my $group = "${namespace}.${type}";
   my $attr = "group_${type}";
   $self->{$attr} = $group;
}

sub get_group_owner
{
   my $self = shift or confess "failed object";
   return $self->{group_owner};
}

sub set_group_nonperson
{
   my $self = shift or confess "failed object";
   my $namespace = $self->get_namespace();
   my $nonperson_group = sprintf('%s.nonperson', $namespace);
   $self->{nonperson_group} = $nonperson_group;
}

sub get_group_nonperson
{
   my $self = shift or confess "failed object";
   if ( not defined $self->{nonperson_group} ) {
      $self->set_group_nonperson();
   }
   return $self->{nonperson_group};
}

sub check_group_nonperson
{
   my $self = shift or confess "failed object";
   my $nonperson_group = $self->get_group_nonperson();
   my $result = $self->check_group("$nonperson_group");

   if ( $result ) {
      say "# GOOD: group $nonperson_group" if $self->is_troubleshoot();
   }
   else {
      carp "# ERROR: group $nonperson_group missing" if $self->is_troubleshoot();
      $self->add_group(
         group => $nonperson_group
      );
   }
}

sub get_existing_rbac
{
   my $self = shift or confess "failed object";

   my $ucnamespace = $self->get_ucnamespace();

   foreach my $type (qw(role privilege permission)) {
      my $command = sprintf('ipa %s-find "%s " --all --raw --sizelimit=0 --timelimit=0 | grep "^  cn: "',
         $type,
         $ucnamespace, 
      );
   
      my @entries;
      foreach my $entry (`$command`) {
         chomp $entry;
         $entry =~ s/  cn: //;
         $self->{rbac}->{bad}->{$type}->{$entry}++ if $entry =~ /^$ucnamespace /;
      }
   }
}

sub discard_invalid_rbac
{
   my $self = shift or confess "failed object";
   my %settings = @_;

   my $admin = $settings{admin} or confess "admin missing";
   my $owner = $settings{owner} or confess "owner missing";

   PERMISSIONS:
   {
      my %good_permissions;

      ADMIN:
      {
         foreach my $permlabel ( keys %{$admin->{permission}}) {
            $good_permissions{$admin->{permission}->{$permlabel}->{name}}++;
         }
      
         foreach my $permission ( keys %{$admin->{rbac}->{bad}->{permission}} ) {
            if ( defined $good_permissions{$permission} ) {
               delete $admin->{rbac}->{bad}->{permission}->{$permission};
            }
         }
      }
   
      OWNER:
      {
         foreach my $permlabel ( keys %{$owner->{permission}}) {
            $good_permissions{$owner->{permission}->{$permlabel}->{name}}++;
         }
         foreach my $permission ( keys %{$owner->{rbac}->{bad}->{permission}} ) {
            if ( defined $good_permissions{$permission} ) {
               delete $owner->{rbac}->{bad}->{permission}->{$permission};
            }
         }
      }

      my @permissions = (
         keys %{$owner->{rbac}->{bad}->{permission}},
         keys %{$admin->{rbac}->{bad}->{permission}},
      );
      foreach my $permission ( @permissions ) {
         $self->del_permission($permission);
      }
   }

   PRIVILEGE:
   {
      my $owner_privilege = $owner->{privilege};
      if ( defined $owner->{rbac}->{bad}->{privilege}->{$owner_privilege} ) {
         delete $owner->{rbac}->{bad}->{privilege}->{$owner_privilege};
      }

      my $admin_privilege = $admin->{privilege};
      if ( defined $admin->{rbac}->{bad}->{privilege}->{$admin_privilege} ) {
         delete $admin->{rbac}->{bad}->{privilege}->{$admin_privilege};
      }

      my @privileges = (
         keys %{$owner->{rbac}->{bad}->{privilege}},
         keys %{$admin->{rbac}->{bad}->{privilege}},
      );
      foreach my $privilege ( @privileges ) {
         $self->del_privilege($privilege);
      }
   }
       
   ROLE:
   {
      my $owner_role = $owner->{role};
      if ( defined $owner->{rbac}->{bad}->{role}->{$owner_role} ) {
         delete $owner->{rbac}->{bad}->{role}->{$owner_role};
      }

      my $admin_role = $admin->{role};
      if ( defined $admin->{rbac}->{bad}->{role}->{$admin_role} ) {
         delete $admin->{rbac}->{bad}->{role}->{$admin_role};
      }

      my @roles = (
         keys %{$owner->{rbac}->{bad}->{role}},
         keys %{$admin->{rbac}->{bad}->{role}},
      );
      foreach my $role ( @roles ) {
         $self->del_role($role);
      }
   }
}

sub del_privilege
{
   my $self = shift or confess "failed object";
   my $privilege = shift or confess "privilege missing";
   my $command = sprintf('ipa privilege-del "%s"', $privilege);
   say $command;
}

sub del_role
{
   my $self = shift or confess "failed object";
   my $role = shift or confess "role missing";

   my $command = sprintf('ipa role-del "%s"', $role);
   say $command;
}

sub get_permission
{
   my $self = shift or return;
   my $permission = shift or confess "permission missing";

   if ( not defined $self->{permission} ) {
      confess "permissions not collected";
   }
   if ( not defined $self->{permission}->{$permission} ) {
      confess "permission not defined: $permission";
   }

   return $self->{permission}->{$permission};
}

sub get_permission_name
{
   my $self = shift or return;
   my $permission = shift or confess "permission missing";

   my $settings = $self->get_permission($permission);

   if ( not defined $settings->{name} ) {
      confess "permission name not defined";
   }
   return $settings->{name};
}

sub get_permissions
{
   my $self = shift or return;

   if ( not defined $self->{permission_files} ) {
      confess "permissions not collected";
   }

   if ( not @{$self->{permission_files}} ) {
      confess "permissions not defined";
   }

   return @{$self->{permission_files}};
}

sub set_permission_dir
{
   my $self = shift or return;

   my $dir = shift or confess "permission directory missing";

   if ( not defined $dir or length $dir == 0 or not -d $dir ) {
      confess "unable to set permission directory";
   }
   $self->{permission_dir} = $dir;
}

sub get_permission_dir
{
   my $self = shift or return;

   if ( not defined $self->{permission_dir} ) {
      confess "permission directory missing";
   }
   return $self->{permission_dir};
}

sub set_permission_files
{
   my $self = shift or confess "failed object";
   my @permissions = @_ or confess "permission files missing";
   @{$self->{permission_files}} = @permissions;
}

sub gather_permissions
{
   my $self = shift or return;

   my $directory = $self->get_permission_dir();

   opendir(my $dh, $directory)
      or confess "Unable to read directory $directory";

   my $ucnamespace = $self->get_ucnamespace();

   my @entries = readdir($dh);
   my @permissions;

   ENTRY:
   foreach my $file ( sort @entries ) {
      next ENTRY if $file =~ /\A\./;
      next ENTRY if $file =~ /\AREADME/;
      push @permissions, $file;
   }

   $self->set_permission_files(@permissions);

   closedir $dh;
}

sub check_permissions
{
   my $self  = shift or confess "failed object";

   my @permissions = $self->get_permissions();

   CHECK_PERMISSIONS:
   foreach my $permission ( @permissions ) {
      $self->report($permission);
   }
}

sub set_current_permissions
{
   my $self = shift or confess "failed object";

   my $ucnamespace = $self->get_ucnamespace();
   my $privilege_name = $self->get_privilege_name();

   my $command = sprintf('ipa privilege-show "%s" --all --raw', $privilege_name);
   my $result = `$command >/dev/null 2>$1 && echo $?`;
   if ( $result > 0 ) {
      carp "privilege not found: $privilege_name";
      return;
   }

   $command = sprintf('$command 2>/dev/null | grep "^  memberof:" | grep "cn=permissions" | sed -e \'s/^  memberof: cn=//\' | sed -e \'s/,cn=.*$//\'', $privilege_name);

   foreach my $permission (`$command`) {
      chomp $permission;
      if ( $permission =~ /\A$ucnamespace / ) {
         $self->{current_permissions}->{$permission}++;
      }
   }
}

sub get_permission_files
{
   my $self = shift or confess "failed object";
   return @{$self->{permission_files}};
}

sub permissions_format
{
   my $self  = shift or confess "failed object";
   my $replace = shift or confess "replacement settings missing";

   foreach my $permission ( $self->get_permission_files() ) {
      my $fullpathfile = sprintf("%s/%s", $self->{permission_dir}, $permission);

      my $yaml = YAML::Tiny->read( $fullpathfile );
      my $settings = $yaml->[0]->{permission};

      foreach my $attribute (keys %{$settings}) {
         if ( ref($settings->{$attribute}) ne "ARRAY" ) {
            foreach my $label ( keys %{$replace} ) {
               my $replace = $replace->{$label};
               $settings->{$attribute} =~ s/[%]$label[%]/$replace/g;
            }
         }
      }

      $self->{permission}->{$permission} = $settings;
   }
}

sub add_privilege
{
   my $self = shift or confess "failed object";
   my $name = $self->get_privilege_name();

   if ( $self->is_privilege($name) ) {
      $self->del_privilege($name);
   }

   my $command = sprintf('ipa privilege-add "%s"', $name);
   say( $command );
}

sub check_privilege
{
   my $self = shift or confess "failed object";

   my $privilege_name = $self->get_privilege_name();
   my $result = $self->show_privilege();

   #$self->handle_good_rbac("privilege", $privilege_name);

   if ( $result == 0 ) {
      carp "# GOOD: privilege $privilege_name" if $self->is_troubleshoot();
   }
   else {
      carp "# ERROR: privilege $privilege_name missing" if $self->is_troubleshoot();
      $self->add_privilege();
   }
}

sub show_privilege
{
   my $self = shift or confess "failed object";

   my $privilege_name = $self->get_privilege_name();

   my $command = sprintf('ipa privilege-show "%s" --all --raw 2>/dev/null', $privilege_name);
   my $result = `$command`;

   return $result;
}

sub privilege_content
{
   my $self = shift or confess "failed object";

   my $role_name = $self->get_role_name();

   my $command = sprintf('ipa privilege-show "%s" --all --raw', $role_name);
   my $privilege_show = `$command >/dev/null 2>&1 && echo -n $?`;

   if ( $privilege_show == 0 ) {
      my $content = $self->show_privilege();
      $content =~ s/\n/ :: /g;
      return $content;
   }
   else {
      say("$role_name privilege not found") if $self->is_troubleshoot();
      return;
   }
}

sub role_content
{
   my $self = shift or confess "failed object";

   my $role_name = $self->get_role_name();

   my $command = sprintf('ipa role-show "%s" --all --raw 2>/dev/null', $role_name);

   my $role_show = `$command >/dev/null 2>&1 && echo -n $?`;

   if ( $role_show == 0 ) {
      my $result = `$command`;
      $result =~ s/\n/ :: /g;
      return $result;
   }
   else {
      say("$role_name role not found") if $self->is_troubleshoot();
      return;
   }
}

sub apply_role_add_privilege
{
   my $self = shift or confess "failed object";

   my $role_name = $self->get_role_name();
   my $privilege_name = $self->get_privilege_name();

   my $command = sprintf('ipa role-add-privilege "%s" --privileges="%s"',
      $role_name,
      $privilege_name
   );
   say( $command );
}

sub apply_role_add_member
{
   my $self = shift or confess "failed object";
   my $type = shift or confess "role type missing (admin,owner,hostenroll)";
   return if $type eq "hostenroll";

   my $role_name = $self->get_role_name();
   my $group_name = $self->get_group_role($type);

   my $command = sprintf('ipa role-add-member "%s" --groups=%s',
      $role_name,
      $group_name
   );
   say( $command );
}

sub add_role
{
   my $self = shift or confess "failed object";

   my $role = $self->get_role_name();

   if ( $self->is_role($role) ) {
      $self->del_role($role);
   }

   my $command = sprintf('ipa role-add "%s"', $role);
   say( $command );
}

sub provision_role
{
   my $self = shift or confess "failed object";
   my $type = shift or confess "role type missing (admin,owner,hostenroll)";

   $self->add_role();
   $self->apply_role_add_member($type);
   $self->apply_role_add_privilege();
}

sub assign_privilege_permission
{
   my $self = shift or confess "failed object";
   my $privilege  = shift or confess "privilege missing";
   my $permission = shift or confess "permission missing";

   my $permission_name = $self->get_permission_name($permission);

   my $command = sprintf ("ipa privilege-add-permission \"%s\" --permissions=\"%s\"",
      $privilege,
      $permission_name,
   ); 
   say( $command );
}

sub get_permission_settings
{
   my $self = shift or confess "failed object";
   my $permission = shift or confess "permission missing";

   if ( not defined $self->{permission}->{$permission} ) {
      confess "$permission not found";
   }

   return %{$self->{permission}->{$permission}};
}

sub add_permission
{
   my $self       = shift or confess "failed object";
   my $permission = shift or confess "permission missing";

   my %settings = $self->get_permission_settings($permission);

   my $name = $self->get_permission_name($permission);
   delete $settings{name};

   $self->del_permission($permission);

   my $command = "ipa permission-add \"$name\"";

   foreach my $attribute ( keys %settings ) {
      if ( ref $settings{$attribute} eq "ARRAY" ) {
         if ( @{$settings{$attribute}} > 1 ) {
            $command .= " --${attribute}={".(join ",", @{$settings{$attribute}})."}";
         }
         else {
            $command .= " --${attribute}=\"".$settings{$attribute}->[0]."\"";
         }
      }
      else {
         my $enc = $attribute eq "filter" ? "'" : '"';
         $command .= sprintf(" --%s=%s%s%s", $attribute, $enc, $settings{$attribute}, $enc);
      }
   }

   say("$command");
}

sub del_permission
{
    my $self = shift or confess "failed object";
    my $permission = shift or confess "permission file missing";

    my $name = $self->get_permission_name($permission);

    # avoid deleting System: permissions
    if ( $name =~ /\ASystem: / ) {
       say("# ATTENTION: Attempting to delete $name") if $self->is_troubleshoot();
       return;
    }

    # remove existing permission, if found
    if ( $self->is_permission($name) ) {
       my $command = sprintf("ipa permission-del \"%s\" >/dev/null 2>&1", $name);
       say("$command");
    }
}

sub get_permission_aci
{
   my $self = shift or confess "faied object";
   my $permission = shift or confess "permission file missing";

   my $name = $self->get_permission_name($permission);

   if ( $self->is_permission($name) ) {
      my $perm_aci = `ipa permission-show "$name" --all --raw 2>/dev/null | grep "^  aci:"`;
      chomp $perm_aci;
      $perm_aci =~ s/  aci: //;
      $perm_aci =~ s/((?:;write_keys|;read_keys))/\\$1/g;
   
      return $perm_aci;
   }

   say("Permission not found: $name") if $self->is_troubleshoot();
   return;
}

sub is_role
{
   my $self = shift or confess "failed object";
   my $name = shift or confess "permission name missing";

   my $command = sprintf('ipa role-show "%s" > /dev/null 2>&1', $name);
   my $show = system($command);

   return false if $show; # exit code, then role not found
   return true;
}

sub is_privilege
{
   my $self = shift or confess "failed object";
   my $name = shift or confess "permission name missing";

   my $command = sprintf('ipa privilege-show "%s" > /dev/null 2>&1', $name);
   my $show = system($command);

   return false if $show; # exit code, then privilege not found
   return true;
}

sub is_permission
{
   my $self = shift or confess "failed object";
   my $name = shift or confess "permission name missing";
   
   my $command = sprintf('ipa permission-show "%s" > /dev/null 2>&1', $name);
   my $show = system($command);

   return false if $show; # exit code, then permission not found
   return true;
}

sub construct_aci
{
   my $self = shift or confess "failed object";
   my $permission = shift or confess "permission not provided";

   my %settings = $self->get_permission_settings($permission);
   my $attrs = join " || ", (sort @{$settings{attrs}});

   my $permission_name = $self->get_permission_name($permission);

   # attributes
   my $aci;

   # ACI ATTRIBUTES
   $aci .= "(targetattr = \"${attrs}\")";

   # ACI DN
   my $target = $settings{target};
   $aci .= sprintf(
      "(target = \"ldap:///%s\")", $target
   );

   # ACI TARGETFILTER
   if ( defined $settings{filter} and length $settings{filter} ) {
      my $targetfilter = $settings{filter};
      $aci .= "(targetfilter = \"$targetfilter\")";
   }

   # ACI VERSION AND PERMISSION
   $aci .= sprintf("(version 3.0;acl \"permission:%s\";", $permission_name);

   # ACI RIGHTS
   my $rights = join ",", (sort @{$settings{right}});
   $aci .= "allow (${rights})";

   # ACI GROUPDN
   my $groupdn = sprintf(
      "ldap:///cn=%s,cn=permissions,cn=pbac,dc=%s,dc=jpl,dc=nasa,dc=gov",
      $permission_name,
      $self->get_short_domainname(),
   );
   $aci .= " groupdn = \"${groupdn}\";)";

   return $aci;
}

sub check_role
{
   my $self = shift or confess "failed object";
   my $type = shift or confess "role type missing (admin,owner,hostenroll)";

   my $role_name = $self->get_role_name();

   my $group     = $self->get_group_role($type) unless $type eq "hostenroll";
   my $privilege_name = $self->get_privilege_name();

   my $ucnamespace = $self->get_ucnamespace();

   my $role_content = $self->role_content();

   CHECK_ROLE:
   {
      #$self->handle_good_rbac("role", $role_name);

      if ( $role_content =~ /cn: $role_name/ ) {
         carp "# GOOD: role $role_name" if $self->is_troubleshoot();
      }
      else {
         carp "# ERROR: role $role_name missing" if $self->is_troubleshoot();
         $self->add_role();
      }
   }

   CHECK_MEMBER:
   {
      if ( $role_content =~ /member: cn=${group},/ ) {
         carp "# GOOD: role assigned member $group" if $self->is_troubleshoot();
      }
      else {
         carp "# ERROR: role member $group not assigned" if $self->is_troubleshoot();
         $self->add_group_role($type);
	 $self->apply_role_add_member($type);
      }
   }

   CHECK_PRIVILEGE:
   {
      #$self->handle_good_rbac("privilege", $privilege_name);

      if ( $role_content =~ /memberof: cn=${privilege_name},cn=privileges/ ) {
         carp "# GOOD: role assigned privilege $privilege_name" if $self->is_troubleshoot();
      }
      else {
         carp "# ERROR: role privilege $privilege_name not assigned" if $self->is_troubleshoot();

         $self->add_privilege();
         $self->apply_role_add_privilege();
      }
   }

   CHECK_PERMISSIONS:
   {
      my @permissions = $self->get_permissions();

      foreach my $permission ( @permissions ) {
         my $permission_name = $self->get_permission_name($permission);

         #$self->handle_good_rbac("permission", $permission_name);

         if ( $role_content =~ /memberof: cn=$permission_name,cn=permissions/ ) {
            carp "# GOOD: role assigned permission $permission_name" if $self->is_troubleshoot();
         }
         else {
            carp "# ERROR: role permission $permission_name not assigned" if $self->is_troubleshoot();
            if ( $self->is_permission($permission) ) {
	       $self->assign_privilege_permission($privilege_name, $permission);
            }

         }
      }
   }
}

sub report
{
   my $self = shift or confess "failed object";
   my $permission = shift or confess "permission file missing";

   my $privilege_name = $self->get_privilege_name();

   my $valid_aci = $self->construct_aci($permission);
   my $perm_aci  = $self->get_permission_aci($permission);

   my $permission_name = $self->get_permission_name($permission);

   if ( not defined $perm_aci or ( $valid_aci ne $perm_aci ) ) {
      if ( $self->is_troubleshoot() ) {
         carp "# bad: $permission_name";
         carp "#    CHECK: $valid_aci";
         carp "#    FOUND: $perm_aci";
      }

      $self->add_permission($permission);
      $self->assign_privilege_permission($privilege_name, $permission);
   }
   else {
      if ( $self->is_troubleshoot() ) {
         carp "# good: $permission_name";
         carp "#    CHECK: $valid_aci";
         carp "#    FOUND: $perm_aci";
      }
   }
}

sub get_nonperson_group
{
   my $self = shift or confess "failed object";
   if ( not defined $self->{nonperson_group} ) {
      confess "nonperson group not defined";
   }
   return $self->{nonperson_group};
}

sub set_nonperson_group
{
   my $self = shift or confess "failed object";
   my $namespace = $self->get_namespace();
   my $group = sprintf("%s.nonperson", $namespace);
   $self->{nonperson_group} = $group;
}

sub get_privilege_name
{
   my $self = shift or confess "failed object";

   confess "privilege not defined" if ( not defined $self->{privilege} );

   return $self->{privilege};
}

sub set_privilege_name
{
   my $self = shift or confess "failed object";
   my $title = shift or confess "privilege title missing";
   $self->{privilege} = $title;
}

sub get_role_name
{
   my $self = shift or confess "failed object";

   if ( not defined $self->{role} ) {
      confess "role name not defined";
   }

   return $self->{role};
}

sub set_role_name
{
   my $self = shift or confess "failed object";
   my $title = shift or confess "role title missing";
   $self->{role} = $title;
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

sub add_user
{
   my $self = shift or confess "failed object";
   my %settings = @_ or confess "settings missing";
   my $uid = $settings{uid};
   delete $settings{uid};

   my $command = sprintf('ipa user-add %s', $uid);

   foreach my $setting ( keys %settings ) {
      my $value = $settings{$setting};
      $command .= sprintf(' --%s="%s"', $setting, $value);
   }
   say $command;
}

sub detach_group
{
   my $self = shift or confess "failed object";
   my $user = shift or confess "user missing";

   my $command = sprintf('ipa group-detach %s', $user);
   say( $command );
}

sub modify_user
{
   my $self = shift or confess "failed object";
   my %settings = @_ or confess "settings missing";

   my $command = sprintf('ipa user-mod %s', $settings{uid});
   delete $settings{uid};

   foreach my $setting (keys %settings) {
      my $value = $settings{$setting};
      $command .= sprintf(' --%s="%s"', $setting, $value);
   }

   say( $command );
}

sub find_user
{
   my $self = shift or confess "failed object";
   my $user = shift or confess "user missing";
   my $command = sprintf('ipa user-show %s >/dev/null 2>&1', $user);
   my $result = system($command);
   if ( $result == 0 ) {
      carp "# GOOD: user $user" if $self->is_troubleshoot();
      return true;
   }
   else {
      carp "# ERROR: user $user missing" if $self->is_troubleshoot();
      return false;
   }
}

sub find_group_member
{
   my $self = shift or confess "failed object";
   my $group = shift or confess "group missing";
   my $user  = shift or confess "user missing";

   my $command = sprintf('ipa group-show %s --all --raw | grep "member: uid=%s,"',
      $group,
      $user
   );
   my $result = `$command`;

   if ( $result =~ /uid=$user,/ ) {
      return true;
   }
   else {
      return false;
   }
}

1;
