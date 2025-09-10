#! /usr/bin/env python3

__version__ = "1.0.0"

import logging
import re
import subprocess
import sys
import unittest

# NOTE: ran tests logged in to VM (icam-test-jw1-idm01) as 'admin' user with 'admin' user token

DEBUG = False
VERBOSE = False # display test commands
TEST_HOSTGROUP_ADDS = True
TEST_HBACRULE_ADDS = True
TEST_SUDORULE_ADDS = True

# set up logging to stdout
log_level = logging.DEBUG if DEBUG else logging.INFO
log_format = "[%(levelname)s]: %(message)s" if DEBUG else "%(message)s"
stdout_h = logging.StreamHandler(sys.stdout)
stdout_h.setFormatter(logging.Formatter(log_format))
l = logging.getLogger()
l.setLevel(log_level)
l.addHandler(stdout_h)

domain = None
cmd = ["domainname"]
result = subprocess.run(cmd, stdout=subprocess.PIPE)
result = result.stdout.decode('utf-8').rstrip()
m = re.search(r"^(\w+)-\w+", result)
if m:
    domain = m.group(1)
if not domain:
    raise Exception(f"Failed to discover domain from command '{cmd}'")

tgt_ns = "foo" # target namespace
alt_ns = "bar" # alternative (not target) namespace
base_dn = f"dc={domain}-idm,dc=jpl,dc=nasa,dc=gov"
users_branch = f"cn=users,cn=accounts,{base_dn}"

# Target objects
tgt_hostgroup = f"{tgt_ns}.hgroup"
tgt_hbacrule = f"{tgt_ns}.hbacrule"
tgt_sudorule = f"{tgt_ns}.sudorule"

# Candidate member object
cand_ips_host = f"ips.candhost.jpl.nasa.gov"
cand_host = f"candhost.jpl.nasa.gov"
cand_hostgroup = f"cand_hostgroup"
cand_tgt_hg = f"{tgt_ns}.cand_hostgroup"
cand_alt_hg = f"{alt_ns}.cand_hostgroup"

# DN values for setting enrolledby attribute

class Test1HostgroupAdds(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        if TEST_HOSTGROUP_ADDS and True:
            logging.debug(f"setUpClass() - begin")
            self.util = IPATestUtil()
            self.test_h_cmd = f"ipa hostgroup-add-member {tgt_hostgroup} --hosts={cand_host}"
            self.test_h_exempt_cmd = f"ipa hostgroup-add-member {tgt_hostgroup} --hosts={cand_ips_host}"
            self.test_hg1_cmd = f"ipa hostgroup-add-member {tgt_hostgroup} --hostgroups={cand_tgt_hg}"
            self.test_hg2_cmd = f"ipa hostgroup-add-member {tgt_hostgroup} --hostgroups={cand_alt_hg}"
            self.util.del_hostgroup(tgt_hostgroup, silent_fail=True)
            self.util.del_host(cand_host, silent_fail=True)
            self.util.add_hostgroup(tgt_hostgroup)
            logging.debug(f"setUpClass() - done")

    @classmethod
    def tearDownClass(self):
        if TEST_HOSTGROUP_ADDS and True:
            logging.debug(f"tearDownClass() - begin")
            self.util.del_hostgroup(tgt_hostgroup, silent_fail=True)
            self.util.del_host(cand_host, silent_fail=True)
            logging.debug(f"tearDownClass() - done")

    def test_0h_exempt_success_hostgroup(self):
        """Add host exempt of namespace policy to hostgroup"""
        if TEST_HOSTGROUP_ADDS and True:
            logging.info(f"\n=== {sys._getframe(0).f_code.co_name}()")
            self.util.add_host(cand_ips_host)
            success, content = self.util.execute(self.test_h_exempt_cmd, verbose=VERBOSE)
            self.util.del_host(cand_ips_host, silent_fail=True)
            self.assertTrue(success and "Number of members added 1" in content)

    def test_1h_orphaned_of_ns_success_hostgroup(self):
        """Add host orphaned of namespace to hostgroup"""
        if TEST_HOSTGROUP_ADDS and True:
            logging.info(f"\n=== {sys._getframe(0).f_code.co_name}()")
            self.util.add_host(cand_host)
            success, content = self.util.execute(self.test_h_cmd, verbose=VERBOSE)
            self.util.del_host(cand_host, silent_fail=True)
            self.assertTrue(success and "Number of members added 1" in content)

    def test_2h_tgt_ns_userclass_success_hostgroup(self):
        """Add host in target namespace by userclass attr to hostgroup"""
        if TEST_HOSTGROUP_ADDS and True:
            logging.info(f"\n=== {sys._getframe(0).f_code.co_name}()")
            self.util.add_host(cand_host, ns=tgt_ns)
            success, content = self.util.execute(self.test_h_cmd, verbose=VERBOSE)
            self.util.del_host(cand_host, silent_fail=True)
            self.assertTrue(success and "Number of members added 1" in content)

    def test_3h_alt_ns_userclass_failure_hostgroup(self):
        """Fail to add host in alternative namespace by userclass attr to hostgroup"""
        if TEST_HOSTGROUP_ADDS and True:
            logging.info(f"\n=== {sys._getframe(0).f_code.co_name}()")
            self.util.add_host(cand_host, ns=alt_ns)
            success, content = self.util.execute(self.test_h_cmd, verbose=VERBOSE)
            self.assertTrue(success and "Number of members added 0" in content)
            self.util.del_host(cand_host, silent_fail=True)

    def test_4hg_tgt_ns_name_success_hostgroup(self):
        """Add hostgroup in target namespace by name to another hostgroup"""
        if TEST_HOSTGROUP_ADDS and True:
            logging.info(f"\n=== {sys._getframe(0).f_code.co_name}()")
            self.util.add_hostgroup(cand_tgt_hg)
            success, content = self.util.execute(self.test_hg1_cmd, verbose=VERBOSE)
            self.assertTrue(success and "Number of members added 1" in content)
            self.util.del_hostgroup(cand_tgt_hg, silent_fail=True)

    def test_5hg_alt_ns_name_failure_hostgroup(self):
        """Fail to add hostgroup in alternative namespace by name attr to another hostgroup"""
        if TEST_HOSTGROUP_ADDS and True:
            logging.info(f"\n=== {sys._getframe(0).f_code.co_name}()")
            self.util.add_hostgroup(cand_alt_hg)
            success, content = self.util.execute(self.test_hg2_cmd, verbose=VERBOSE)
            self.util.del_hostgroup(cand_alt_hg, silent_fail=True)
            self.assertTrue(success and "Number of members added 0" in content)

class Test2HBACRuleAdds(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        if TEST_HBACRULE_ADDS and True:
            self.util = IPATestUtil()
            self.test_h_cmd = f"ipa hbacrule-add-host {tgt_hbacrule} --hosts={cand_host}"
            self.test_h_exempt_cmd = f"ipa hbacrule-add-host {tgt_hbacrule} --hosts={cand_ips_host}"
            self.test_hg1_cmd = f"ipa hbacrule-add-host {tgt_hbacrule} --hostgroups={cand_tgt_hg}"
            self.test_hg2_cmd = f"ipa hbacrule-add-host {tgt_hbacrule} --hostgroups={cand_alt_hg}"
            self.util.del_hbacrule(tgt_hbacrule, silent_fail=True)
            self.util.del_host(cand_host, silent_fail=True)
            self.util.add_hbacrule(tgt_hbacrule)

    @classmethod
    def tearDownClass(self):
        if TEST_HBACRULE_ADDS and True:
            self.util.del_hbacrule(tgt_hbacrule, silent_fail=True)
            self.util.del_host(cand_host, silent_fail=True)

    def test_0h_exempt_success_hbacrule(self):
        """Add host exempt of namespace to hbacrule"""
        if TEST_HBACRULE_ADDS and True:
            logging.info(f"\n=== {sys._getframe(0).f_code.co_name}()")
            self.util.add_host(cand_ips_host)
            success, content = self.util.execute(self.test_h_exempt_cmd, verbose=VERBOSE)
            self.assertTrue(success and "Number of members added 1" in content)
            self.util.del_host(cand_ips_host, silent_fail=True)

    def test_1h_orphaned_of_ns_success_hbacrule(self):
        """Add host orphaned of namespace to hbacrule"""
        if TEST_HBACRULE_ADDS and True:
            logging.info(f"\n=== {sys._getframe(0).f_code.co_name}()")
            self.util.add_host(cand_host)
            success, content = self.util.execute(self.test_h_cmd, verbose=VERBOSE)
            self.assertTrue(success and "Number of members added 1" in content)
            self.util.del_host(cand_host, silent_fail=True)

    def test_2h_tgt_ns_userclass_success_hbacrule(self):
        """Add host in target namespace to hbacrule"""
        if TEST_HBACRULE_ADDS and True:
            logging.info(f"\n=== {sys._getframe(0).f_code.co_name}()")
            self.util.add_host(cand_host, ns=tgt_ns)
            success, content = self.util.execute(self.test_h_cmd, verbose=VERBOSE)
            self.assertTrue(success and "Number of members added 1" in content)
            self.util.del_host(cand_host, silent_fail=True)

    def test_3h_alt_ns_userclass_failure_hbacrule(self):
        """Fail to add host in alternative namespace by userclass attr to hbacrule"""
        if TEST_HBACRULE_ADDS and True:
            logging.info(f"\n=== {sys._getframe(0).f_code.co_name}()")
            self.util.add_host(cand_host, ns=alt_ns)
            success, content = self.util.execute(self.test_h_cmd, verbose=VERBOSE)
            self.assertTrue(success and "Number of members added 0" in content)
            self.util.del_host(cand_host, silent_fail=True)

    def test_4hg_tgt_ns_name_success_hbacrule(self):
        """Add hostgroup in target namespace by name to another hostgroup"""
        if TEST_HBACRULE_ADDS and True:
            logging.info(f"\n=== {sys._getframe(0).f_code.co_name}()")
            self.util.add_hostgroup(cand_tgt_hg)
            success, content = self.util.execute(self.test_hg1_cmd, verbose=VERBOSE)
            self.assertTrue(success and "Number of members added 1" in content)
            self.util.del_hostgroup(cand_tgt_hg, silent_fail=True)

    def test_5hg_tgt_ns_name_failure_hbacrule(self):
        """Fail to add hostgroup in alternative namespace by name to another hostgroup"""
        if TEST_HBACRULE_ADDS and True:
            logging.info(f"\n=== {sys._getframe(0).f_code.co_name}()")
            self.util.add_hostgroup(cand_alt_hg)
            success, content = self.util.execute(self.test_hg2_cmd, verbose=VERBOSE)
            self.assertTrue(success and "Number of members added 0" in content)
            self.util.del_hostgroup(cand_alt_hg, silent_fail=True)

class Test3SudoRuleAdds(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        if TEST_SUDORULE_ADDS and True:
            self.test_h_cmd = f"ipa sudorule-add-host {tgt_sudorule} --hosts={cand_host}"
            self.test_h_exempt_cmd = f"ipa sudorule-add-host {tgt_sudorule} --hosts={cand_ips_host}"
            self.test_hg1_cmd = f"ipa sudorule-add-host {tgt_sudorule} --hostgroups={cand_tgt_hg}"
            self.test_hg2_cmd = f"ipa sudorule-add-host {tgt_sudorule} --hostgroups={cand_alt_hg}"
            self.util = IPATestUtil()
            self.util.del_sudorule(tgt_sudorule, silent_fail=True)
            self.util.del_host(cand_host, silent_fail=True)
            self.util.add_sudorule(tgt_sudorule)

    @classmethod
    def tearDownClass(self):
        if TEST_SUDORULE_ADDS and True:
            self.util.del_sudorule(tgt_sudorule, silent_fail=True)
            self.util.del_host(cand_host, silent_fail=True)

    def test_0h_exempt_success_sudorule(self):
        """Add host exemptmespace to sudorule"""
        if TEST_SUDORULE_ADDS and True:
            logging.info(f"\n=== {sys._getframe(0).f_code.co_name}()")
            self.util.add_host(cand_ips_host)
            success, content = self.util.execute(self.test_h_exempt_cmd, verbose=VERBOSE)
            self.assertTrue(success and "Number of members added 1" in content)
            self.util.del_host(cand_ips_host, silent_fail=True)

    def test_1h_orphaned_of_ns_success_sudorule(self):
        """Add host orphaned of namespace to sudorule"""
        if TEST_SUDORULE_ADDS and True:
            logging.info(f"\n=== {sys._getframe(0).f_code.co_name}()")
            self.util.add_host(cand_host)
            success, content = self.util.execute(self.test_h_cmd, verbose=VERBOSE)
            self.assertTrue(success and "Number of members added 1" in content)
            self.util.del_host(cand_host, silent_fail=True)

    def test_2h_tgt_ns_userclass_success_sudorule(self):
        """Add host in target namespace to sudorule"""
        if TEST_SUDORULE_ADDS and True:
            logging.info(f"\n=== {sys._getframe(0).f_code.co_name}()")
            self.util.add_host(cand_host, ns=tgt_ns)
            success, content = self.util.execute(self.test_h_cmd, verbose=VERBOSE)
            self.assertTrue(success and "Number of members added 1" in content)
            self.util.del_host(cand_host, silent_fail=True)

    def test_3h_alt_ns_userclass_failure_sudorule(self):
        """Fail to add host in alternative namespace by userclass attr to sudorule"""
        if TEST_SUDORULE_ADDS and True:
            logging.info(f"\n=== {sys._getframe(0).f_code.co_name}()")
            self.util.add_host(cand_host, ns=alt_ns)
            success, content = self.util.execute(self.test_h_cmd, verbose=VERBOSE)
            self.util.del_host(cand_host, silent_fail=True)
            self.assertTrue(success and "Number of members added 0" in content)

    def test_4hg_tgt_ns_name_success_sudorule(self):
        """Add hostgroup in target namespace by name to another hostgroup"""
        if TEST_SUDORULE_ADDS and True:
            logging.info(f"\n=== {sys._getframe(0).f_code.co_name}()")
            self.util.add_hostgroup(cand_tgt_hg)
            success, content = self.util.execute(self.test_hg1_cmd, verbose=VERBOSE)
            self.assertTrue(success and "Number of members added 1" in content)
            self.util.del_hostgroup(cand_tgt_hg, silent_fail=True)

    def test_5hg_tgt_ns_name_failure_sudorule(self):
        """Fail to add hostgroup in alternative namespace by name to another hostgroup"""
        if TEST_SUDORULE_ADDS and True:
            logging.info(f"\n=== {sys._getframe(0).f_code.co_name}()")
            self.util.add_hostgroup(cand_alt_hg)
            success, content = self.util.execute(self.test_hg2_cmd, verbose=VERBOSE)
            self.assertTrue(success and "Number of members added 0" in content)
            self.util.del_hostgroup(cand_alt_hg, silent_fail=True)

class IPATestUtil(object):

    def add_host(self, host, ns="", silent_fail=False):
        if ns:
            cmd =f"ipa host-add {host} --class {ns} --force"
        else:
            cmd =f"ipa host-add {host} --force"
        return self.execute(cmd, silent_fail=silent_fail)

    def del_host(self, host, silent_fail=False):
        return self.execute(f"ipa host-del {host}", silent_fail=silent_fail)

    def add_hostgroup(self, hgroup, silent_fail=False):
        return self.execute(f"ipa hostgroup-add {hgroup}", silent_fail=silent_fail)

    def del_hostgroup(self, hgroup, silent_fail=False):
        return self.execute(f"ipa hostgroup-del {hgroup}", silent_fail=silent_fail)

    def add_hbacrule(self, hbacrule, silent_fail=False):
        return self.execute(f"ipa hbacrule-add {hbacrule}", silent_fail=silent_fail)

    def del_hbacrule(self, hbacrule, silent_fail=False):
        return self.execute(f"ipa hbacrule-del {hbacrule}", silent_fail=silent_fail)

    def add_sudorule(self, sudorule, silent_fail=False):
        return self.execute(f"ipa sudorule-add {sudorule}", silent_fail=silent_fail)

    def del_sudorule(self, sudorule, silent_fail=False):
        return self.execute(f"ipa sudorule-del {sudorule}", silent_fail=silent_fail)

    def execute(self, command, silent_fail=False, verbose=False):
        if verbose:
            logging.info(f"execute> {command}")
        response = subprocess.run(command.split(),
                              stdout=subprocess.PIPE, #subprocess.DEVNULL,
                              stderr=subprocess.PIPE, #subprocess.DEVNULL,
                              universal_newlines=True)
        code = response.returncode
        content = response.stdout + response.stderr
        success = True if code == 0 or code == 1 else False
        logging.debug(f"code: {code} ({command})")
        if not success and not silent_fail:
            logging.warning(f"{command} - {content}")
        return (success, content)

if __name__ == "__main__":
    unittest.main()
