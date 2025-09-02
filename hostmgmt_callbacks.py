import logging
import re

from ldap import SCOPE_SUBTREE, SCOPE_ONELEVEL, SCOPE_BASE
from ipapython.dn import DN

from ipalib.errors import InternalError

from ipaserver.plugins.baseldap import entry_to_dict
from ipaserver.plugins.hostgroup import hostgroup_add_member
from ipaserver.plugins.hbacrule import (hbacrule_add_host)
from ipaserver.plugins.sudorule import (sudorule_add_host)

class DenyIneligibleMembers(object):
    """
    Implements the functionality of the function deny_if_any_non_namespace_members().

    The deny_if_any_non_namespace_members() function is a pre-callback
    registered to run before a member is added to a hostgroup, HBAC rule, or Sudo
    rule. Its purpose is to filter out any candidate members (hosts or
    hostgroups) that do not conform to predefined namespace rules. The core logic
    for this filtering is encapsulated within this class (DenyIneligibleMembers).

    Essentially, the code ensures that if a target group or rule belongs to a
    specific namespace (e.g., 'namespace.hostgroup'), only members from that same
    namespace are permitted. 
    """

    log_prefix = "namespace.DenyIneligibleMembers -"

    def __init__(self, ldap, tgt_dn, cands, rejects):
        assert isinstance(tgt_dn, DN)
        self.lprefix = DenyIneligibleMembers.log_prefix
        self.ldap = ldap
        self.tgt_dn = tgt_dn
        self.tgt_ns = self.target_namespace()
        self.cand_hosts, self.cand_hostgroups = self.candidate_lists(cands)
        self.reject_hosts, self.reject_hostgroups = self.reject_lists(rejects)

    def execute(self):
        if isinstance(self.tgt_ns, str): # hostgroup/hbacrule/sudorule have no namespace
            denied_dns = []
            for cand_dn in self.cand_hosts + self.cand_hostgroups:
                assert isinstance(cand_dn, DN)
                cand_name, attr = self.parse_dn(cand_dn)
                if not (self.exempt_from_namespace_policies(cand_name) \
                   or (self.exclude_by_hostgroup_name(cand_dn) and self.exclude_by_attr(cand_dn))):
                    denied_dns.append(cand_dn)
            self.enforce_exclusions(denied_dns)
        else:
            logging.info(f"{self.lprefix} {self.tgt_dn} has no namespace")

    def exempt_from_namespace_policies(self, cand_name):
        """
        Hosts with names starting with this or that are exempt from namespace
        policies.

        return True if re.search(r"^(this|that)", cand_name) else False
        """
        return False

    def is_hostgroup_candidate(self, cand_dn):
        return True if cand_dn in self.cand_hostgroups else False

    def exclude_by_hostgroup_name(self, cand_dn):
        """
        Denies hostgroup members unless their name matches the target namespace
        or is prefixed by it (e.g., namespace.hostgroup).
        """
        if self.is_hostgroup_candidate(cand_dn):
            cand_name, attr = self.parse_dn(cand_dn)
            if re.search(rf"^{self.tgt_ns}\.", cand_name, re.I) \
                    or re.search(rf"^{self.tgt_ns}$", cand_name, re.I):
                return False # hostgroup not excluded by hostgroup name
            return True # hostgroup excluded because not in target namespace
        return False # not excluded here because not a hostgroup

    def exclude_by_attr(self, cand_dn):
        """
        Denies members unless they are eligible, as determined by their LDAP
        attributes.
        """
        entry = self.get_candidate_entry(cand_dn)
        if entry is not None:
            eligible = self.is_eligible_based_on_attrs(entry)
            return not eligible
        else:
            logging.info(f"{self.lprefix} {cand_dn} excluded because entry not found")
            return True

    def is_eligible_based_on_attrs(self, entry):
        """
        An host or hostgroup entry is eligible for membership if it either has
        no userclass attribute or its userclass matches the target group's
        namespace.
        """
        attrs = entry_to_dict(entry, raw=True)
        userclasses = attrs.get("userclass", [])
        eligible = False
        if not userclasses:
            eligible = True
        else:
            for userclass in userclasses:
                if userclass == self.tgt_ns:
                    eligible = True
                    break
        return eligible

    def enforce_exclusions(self, denied_dns):
        """
        If a single member is denied, the entire operation to add all members
        will fail.
        """
        tgt_is_sudorule = self.target_is_sudorule()
        if len(denied_dns): # there is at least one denied member candidate
            for dn in self.cand_hosts: # clear candidate hosts
                self.cand_hosts.remove(dn)
            for dn in self.cand_hostgroups: # clear candidate hostgroups
                self.cand_hostgroups.remove(dn)
            for denied_dn in denied_dns: # provide caller with ineligible candidates
                if denied_dn in self.cand_hosts:
                    if not tgt_is_sudorule: # this is here to avoid an error downstream in ipaserver.plugins.baseldap.add_external_post_callback()
                        self.reject_hosts.append(denied_dn)
                if denied_dn in self.cand_hostgroups:
                    self.reject_hostgroups.append(denied_dn)

    def target_namespace(self):
        tgt_name = self.target_name()
        if tgt_name is not None:
            m = re.search(r"^(\w+)\.\w+", tgt_name)
            return m.group(1) if m else None
        return None

    def get_target_entry(self):
        id_name, id_attr = self.parse_dn(self.tgt_dn)
        if id_attr is not None:
            filter_ = self.ldap.make_filter_from_attr(id_attr, id_name, self.ldap.MATCH_ALL)
            try:
                results = self.ldap.get_entries(
                              self.tgt_dn,
                              scope=SCOPE_BASE,
                              filter=filter_,
                              attrs_list=['cn'],
                              size_limit=-1, # paged search will get everything anyway
                              paged_search=True)
            except Exception as err:
                logging.warning(f"{self.lprefix} target {self.tgt_dn} not found - {err}")
                results = []
            if len(results):
                return results[0]
        return None

    def target_is_sudorule(self):
        if re.search(r"cn=sudorules,cn=sudo,dc=", str(self.tgt_dn), re.I):
            return True
        return False

    def get_candidate_entry(self, dn):
        assert isinstance(dn, DN)
        cand_name, attr = self.parse_dn(dn)
        if attr is not None:
            filter_ = self.ldap.make_filter_from_attr(attr, cand_name,
                                                      self.ldap.MATCH_ALL)
            try:
                results = self.ldap.get_entries(
                              dn,
                              scope=SCOPE_BASE,
                              filter=filter_,
                              attrs_list=['userclass'],
                              size_limit=-1, # paged search will get everything anyway
                              paged_search=True)
            except Exception as err:
                if err:
                    logging.warning(f"{self.lprefix} SEARCH EXCEPTION: {err}")
                logging.warning(f"{self.lprefix} canidate {dn} not found")
                results = []
            if len(results):
                return results[0]
        return None

    def target_name(self):
        tgt_name, id_attr = self.parse_dn(self.tgt_dn)
        if re.search(r"ipaUniqueID", id_attr, re.I):
            tgt_entry = self.get_target_entry() # get hbacrule/sudorule
            attrs = entry_to_dict(tgt_entry, raw=True)
            tgt_names = attrs.get("cn", [])
            if len(tgt_names):
                return tgt_names[0]
        return tgt_name

    def candidate_lists(self, cands):
        dict_ = cands.get('member', cands.get('memberhost', None))
        return (dict_.get('host', []), dict_.get('hostgroup', []))

    def reject_lists(self, rejects):
        dict_ = rejects.get('member', rejects.get('memberhost', None))
        return (dict_.get('host', []), dict_.get('hostgroup', []))

    def parse_dn(self, dn):
        attr, name = (None, None)
        # This regex supports host, hostgroup, hbacrule and sudorule DNs
        m = re.search(r"^(cn|fqdn|ipaUniqueID)=([^,]+),.+", str(dn), re.I) 
        if m:
            attr, name = (m.group(1), m.group(2))
        return name, attr

def deny_if_any_non_namespace_members(caller, ldap, dn, candidates, rejects,
                                      *keys, **options):
    """
    This function is a pre-callback for OpenIPA's LDAPAddMember operations. It
    filters members for hostgroups, Sudo rules, and HBAC rules to enforce
    namespace policies.
    """
    DenyIneligibleMembers(ldap, dn, candidates, rejects).execute()
    return dn

hostgroup_add_member.register_pre_callback(deny_if_any_non_namespace_members)
hbacrule_add_host.register_pre_callback(deny_if_any_non_namespace_members)
sudorule_add_host.register_pre_callback(deny_if_any_non_namespace_members)
