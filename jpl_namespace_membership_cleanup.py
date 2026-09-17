__version__ = "1.0.0"

import logging
import uuid

from ipalib import errors
from ipalib.request import context
from ipapython.dn import DN

from ipaserver.plugins.automember import REBUILD_TASK_CONTAINER
from ipaserver.plugins.host import host_mod

"""
Automatically removes a host from its OLD namespace hostgroup when its
userclass attribute changes to a different namespace, or is removed
entirely -- a gap FreeIPA's own automember-rebuild command and the
underlying 389-ds automember plugin both leave open.

Background: FreeIPA/D4L's namespace convention gives each namespace a
hostgroup of the same name, populated via an automember rule matching
hosts whose userclass equals the namespace or starts with
"<namespace>.". The 389-ds automember plugin's real-time modify hook
(automember_mod_post_op(), in ldap/servers/plugins/automember/
automember.c) is ADD-ONLY for this case: it only performs cross-group
membership cleanup as a side effect of the SAME modify ALSO causing an
ADD to a DIFFERENT target group. A plain userclass change or removal,
with no simultaneous add elsewhere, never triggers that cleanup path --
so a host silently remains a member of its old namespace hostgroup
forever, until someone notices and fixes it by hand.

Confirmed empirically (sbx-idm, 2026-09-11) that no automember RULE
configuration can work around this -- not an exclusive condition on
the old rule, not a dedicated default/fallback hostgroup for
"no namespace matched" hosts. Both were built and tested live; neither
causes real cross-rule removal, because the 389-ds cleanup logic that
an ADD triggers only ever diffs the SAME rule's own before/after
target list, never a different rule's separately-tracked membership.

The only mechanism that performs genuine cross-rule membership cleanup
is a `cn=automember rebuild membership,cn=tasks,cn=config` task entry
with `cleanup: yes` set -- the exact task type `ipa automember-rebuild`
already creates (see ipaserver/plugins/automember.py's
automember_rebuild.execute(), which calls ldap.make_entry()/
ldap.add_entry() against this same REBUILD_TASK_CONTAINER) -- but that
command never exposes the `cleanup` attribute, so this has to be
submitted directly rather than via the ipa CLI/API's own rebuild
command.

This plugin closes that gap for the one case D4L actually needs it
for: a host's own userclass changing on host-mod. It uses the same
register_post_callback mechanism as jpl_namespace_membership_policy.py
(FreeIPA's own documented plugin-extension API, doc/guide/guide.org's
"Extending existing method" section) rather than modifying any vendor
file -- host_mod's real behavior is untouched; this callback only ever
runs AFTER a host-mod has already committed successfully.

Deliberately scoped to exactly ONE host per submitted task
(scope: base, basedn = that host's own DN) -- this plugin NEVER
submits a subtree-wide sweep. A domain-wide resync is a separate,
deliberate, operator-initiated action (a manual `ipa automember-rebuild`
run, or a hand-built cleanup task per debug/
automember-cleanup-rebuild-procedure.md), not something a single
host-mod should ever trigger as a side effect.
"""

log_prefix = "jpl.NamespaceMembershipCleanup -"


def detect_userclass_change_pre(self, ldap, dn, entry_attrs, attrs_list,
                                 *keys, **options):
    """
    PRE callback on host_mod: if this modify is actually changing
    userclass (to a different value, or removing it entirely -- LDAP
    has no "blank" attribute value, so a removal means the key is
    simply absent afterward), stash the host's DN on the request
    context so the POST callback below knows to submit a cleanup task
    once the modify has actually committed.

    Runs BEFORE the write, so it can read the entry's CURRENT (old)
    userclass value for comparison -- entry_attrs at this point holds
    only what's CHANGING in this operation, not the full current state.
    """
    if 'userclass' in entry_attrs:
        try:
            entry_attrs_old = ldap.get_entry(dn, ['userclass'])
            old_userclass = set(entry_attrs_old.get('userclass') or [])
        except errors.NotFound:
            old_userclass = set()
        new_userclass = set(entry_attrs.get('userclass') or [])
        if old_userclass != new_userclass:
            setattr(context, 'jpl_automember_cleanup_host_dn', dn)
    return dn


def submit_cleanup_task_post(self, ldap, dn, entry_attrs, *keys, **options):
    """
    POST callback on host_mod: if the PRE callback above flagged a real
    userclass change, submit a scoped (this host only) automember
    rebuild task with cleanup set. Runs AFTER the modify has committed,
    so the sweep sees the host's real, current userclass state.

    Never raises -- a failed cleanup-task submission should not fail
    the host-mod operation that triggered it. Logged instead; the next
    userclass change (or a manual automember-rebuild) gets another
    chance.
    """
    host_dn = getattr(context, 'jpl_automember_cleanup_host_dn', None)
    if host_dn is None:
        return dn
    delattr(context, 'jpl_automember_cleanup_host_dn')

    task_cn = str(uuid.uuid4())
    task_dn = DN(('cn', task_cn), REBUILD_TASK_CONTAINER)
    task_entry = ldap.make_entry(
        task_dn,
        objectclass=['top', 'extensibleObject'],
        cn=[task_cn],
        basedn=[str(host_dn)],
        filter=['(objectclass=*)'],
        scope=['base'],
        cleanup=['yes'])
    try:
        ldap.add_entry(task_entry)
    except errors.PublicError as e:
        logging.error(
            "%s failed to submit automember cleanup task for %s: %s",
            log_prefix, host_dn, e)
    return dn


host_mod.register_pre_callback(detect_userclass_change_pre)
host_mod.register_post_callback(submit_cleanup_task_post)
