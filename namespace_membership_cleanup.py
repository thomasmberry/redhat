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
"""

log_prefix = "log.NamespaceMembershipCleanup -"


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
            setattr(context, 'automember_cleanup_host_dn', dn)
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
    host_dn = getattr(context, 'automember_cleanup_host_dn', None)
    if host_dn is None:
        return dn
    delattr(context, 'automember_cleanup_host_dn')

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
