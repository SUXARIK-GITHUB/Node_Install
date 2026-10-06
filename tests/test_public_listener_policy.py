"""Read-only public TCP listener policy; never emits peer/client addresses."""
import unittest
from common import module


M = module('VK_NODE_PLUGINS_PY')


def line(addr, process, pid):
    return f'LISTEN 0 4096 {addr} 0.0.0.0:* users:(("{process}",pid={pid},fd=7))'


class PublicListenerPolicyTests(unittest.TestCase):
    def good(self):
        return '\n'.join([
            line('0.0.0.0:22', 'sshd', 10),
            line('8.8.4.4:80', 'nginx', 20),
            line('8.8.4.4:443', 'rw-core', 30),
            line('0.0.0.0:2222', 'rw-node', 40),
            line('127.0.0.1:9999', 'debug-local', 50),
        ]) + '\n'

    def test_expected_policy_passes_and_loopback_is_ignored(self):
        self.assertEqual(M.public_listener_policy(self.good(), [22], 2222, {30}, {40}, True, '8.8.4.4'),
                         (True, 'EXPECTED_ONLY'))

    def test_unexpected_public_port_fails_without_peer_addresses(self):
        raw = self.good() + line('0.0.0.0:9999', 'debug', 51) + '\n'
        ok, reason = M.public_listener_policy(raw, [22], 2222, {30}, {40}, True, '8.8.4.4')
        self.assertFalse(ok); self.assertEqual(reason, 'UNEXPECTED_PUBLIC_PORTS=9999')
        self.assertNotIn('0.0.0.0', reason)

    def test_ambiguous_owner_is_not_silent_pass(self):
        raw = self.good().replace(' users:(("nginx",pid=20,fd=7))', '')
        ok, reason = M.public_listener_policy(raw, [22], 2222, {30}, {40}, True, '8.8.4.4')
        self.assertFalse(ok); self.assertIn('OWNER_NOT_VERIFIED', reason)

    def test_missing_443_allowed_until_strict_require_xray(self):
        raw = '\n'.join(x for x in self.good().splitlines() if ':443 ' not in x) + '\n'
        self.assertTrue(M.public_listener_policy(raw, [22], 2222, set(), {40}, False, '8.8.4.4')[0])
        self.assertFalse(M.public_listener_policy(raw, [22], 2222, set(), {40}, True, '8.8.4.4')[0])


    def test_scoped_ipv4_loopback_from_real_iproute2_is_ignored(self):
        raw = self.good() + line('127.0.0.53%lo:53', 'systemd-resolve', 60) + '\n'
        self.assertEqual(
            M.public_listener_policy(raw, [22], 2222, {30}, {40}, True, '8.8.4.4'),
            (True, 'EXPECTED_ONLY'),
        )

    def test_scoped_non_loopback_address_is_still_audited(self):
        raw = self.good() + line('8.8.4.4%eth0:9999', 'debug', 61) + '\n'
        ok, reason = M.public_listener_policy(raw, [22], 2222, {30}, {40}, True, '8.8.4.4')
        self.assertFalse(ok)
        self.assertEqual(reason, 'UNEXPECTED_PUBLIC_PORTS=9999')

    def test_http_and_xray_must_bind_expected_public_ipv4(self):
        raw = self.good().replace('8.8.4.4:80', '0.0.0.0:80')
        ok, reason = M.public_listener_policy(raw, [22], 2222, {30}, {40}, True, '8.8.4.4')
        self.assertFalse(ok); self.assertIn('BIND_ADDRESS_MISMATCH', reason)
        raw = self.good().replace('8.8.4.4:443', '1.1.1.1:443')
        ok, reason = M.public_listener_policy(raw, [22], 2222, {30}, {40}, True, '8.8.4.4')
        self.assertFalse(ok); self.assertIn('BIND_ADDRESS_MISMATCH', reason)


if __name__ == '__main__':
    unittest.main()
