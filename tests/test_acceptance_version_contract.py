"""2.5.0 centralized installer-contract regressions."""
import re
import subprocess
import unittest
from common import payload


CHECKER = payload('VK_PAYLOAD_VK_WRITE_ACCEPTANCE')


def shell_function(name):
    match = re.search(r'(?ms)^' + re.escape(name) + r'\(\) \{\n.*?^\}', CHECKER)
    if not match:
        raise AssertionError('missing function ' + name)
    return match.group(0)


class AcceptanceVersionContractTests(unittest.TestCase):
    def classify(self, version):
        code = shell_function('installed_contract_class') + '\ninstalled_contract_class "$1"\n'
        return subprocess.run(['bash', '-c', code, '_', version], capture_output=True, text=True, timeout=3)

    def test_reviewed_matrix_and_future_fail_closed(self):
        modern = ('2.3.0', '2.4.0', '2.4.1', '2.4.2', '2.4.3', '2.5.0', '2.5.1', '2.5.2', '2.5.3', '2.5.4', '2.5.5')
        legacy = ('1.3.0', '1.3.99', '2.0.3', '2.1.0', '2.1.3', '2.2.0')
        future = ('2.5.6', '2.6.0', '3.0.0', 'broken')
        for version in modern:
            with self.subTest(version=version):
                self.assertEqual(self.classify(version).stdout.strip(), 'modern')
        for version in legacy:
            with self.subTest(version=version):
                self.assertEqual(self.classify(version).stdout.strip(), 'legacy')
        for version in future:
            with self.subTest(version=version):
                self.assertEqual(self.classify(version).stdout.strip(), 'unreviewed')

    def test_241_242_243_execute_modern_ssh_and_selfsteal_actions(self):
        classifier = shell_function('installed_contract_class')
        ssh = shell_function('vk_check_ssh_contract')
        target = shell_function('vk_check_selfsteal_target_contract')
        # Execute the actual generated branch functions; replace only absolute host binaries
        # by recording stubs so tests stay offline/unprivileged.
        ssh = ssh.replace('python3 -I -B -S /usr/local/lib/vkarmani-node/ssh_guard.py check', 'record ssh_guard.py check')
        ssh = ssh.replace('/usr/sbin/sshd -T 2>/dev/null', 'record historical_sshd')
        ssh = ssh.replace('$(sysctl -n net.ipv4.tcp_mtu_probing 2>/dev/null)', '1')
        target = target.replace('timeout 20 /usr/local/sbin/vkarmani-selfsteal-check --target-only', 'record selfsteal --target-only')
        script = classifier + '\n' + ssh + '\n' + target + r'''
record(){ printf 'ACTION=%s\n' "$*"; }
pass(){ :; }
fail(){ printf 'FAIL=%s\n' "$1"; }
_contains(){ cat >/dev/null; return 0; }
INSTALL_VERSION=$1
INSTALLED_CONTRACT_CLASS=$(installed_contract_class "$1")
vk_check_ssh_contract
vk_check_selfsteal_target_contract
'''
        for version in ('2.4.1', '2.4.2', '2.4.3'):
            with self.subTest(version=version):
                result = subprocess.run(['bash', '-c', script, '_', version], capture_output=True, text=True, timeout=3)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('ACTION=ssh_guard.py check', result.stdout)
                self.assertIn('ACTION=selfsteal --target-only', result.stdout)
                self.assertNotIn('historical_sshd', result.stdout)

    def test_no_obsolete_regex_feature_gate_remains(self):
        self.assertNotIn(r'^2\.(3\.0|4\.0)$', CHECKER)
        self.assertEqual(CHECKER.count('2.3.0|2.4.0|2.4.1|2.4.2|2.4.3|2.5.0|2.5.1|2.5.2|2.5.3'), 1)


if __name__ == '__main__':
    unittest.main()
