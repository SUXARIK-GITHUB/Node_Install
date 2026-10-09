"""Read-only public TCP listener policy; never emits peer/client addresses."""
import json
from pathlib import Path
import subprocess
import tempfile
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

    def test_http_requires_public_ipv4_but_xray_allows_reviewed_ipv4_wildcard(self):
        raw = self.good().replace('8.8.4.4:80', '0.0.0.0:80')
        ok, reason = M.public_listener_policy(raw, [22], 2222, {30}, {40}, True, '8.8.4.4')
        self.assertFalse(ok); self.assertIn('BIND_ADDRESS_MISMATCH', reason)

        wildcard = self.good().replace('8.8.4.4:443', '0.0.0.0:443')
        self.assertEqual(
            M.public_listener_policy(wildcard, [22], 2222, {30}, {40}, True, '8.8.4.4'),
            (True, 'EXPECTED_ONLY'),
        )

        wrong = self.good().replace('8.8.4.4:443', '1.1.1.1:443')
        ok, reason = M.public_listener_policy(wrong, [22], 2222, {30}, {40}, True, '8.8.4.4')
        self.assertFalse(ok); self.assertIn('BIND_ADDRESS_MISMATCH', reason)

    def test_preboot_dual_stack_node_port_requires_owner_bindv6only_and_real_ipv4_connect(self):
        with tempfile.TemporaryDirectory(prefix='vk-listener-252-') as tmp:
            root = Path(tmp)
            config = root / 'config.json'
            ports = root / 'ssh-ports'
            config.write_text(json.dumps({'node_port': 2222, 'public_ipv4': '8.8.4.4'}))
            ports.write_text('22\n')

            raw4 = '\n'.join([
                line('0.0.0.0:22', 'sshd', 10),
                line('8.8.4.4:80', 'nginx', 20),
            ]) + '\n'
            raw6 = 'LISTEN 0 511 *:2222 *:* users:(("rw-node",pid=40,fd=21))\n'
            docker_top = 'PID COMMAND\n30 rw-core\n40 rw-node\n'

            def runner(args, **kwargs):
                if args[:5] == ['ss', '-H', '-4', '-lntp']:
                    return subprocess.CompletedProcess(args, 0, raw4, '')
                if args[:5] == ['ss', '-H', '-6', '-lntp']:
                    return subprocess.CompletedProcess(args, 0, raw6, '')
                if args[:4] == ['sysctl', '-n', 'net.ipv6.bindv6only']:
                    return subprocess.CompletedProcess(args, 0, '0\n', '')
                if 'top' in args:
                    return subprocess.CompletedProcess(args, 0, docker_top, '')
                raise AssertionError(args)

            connects = []
            def connect(host, port):
                connects.append((host, port))
                return True

            self.assertEqual(
                M.listener_runtime_status(str(config), str(ports), False, runner, connect),
                (True, 'EXPECTED_ONLY DUAL_STACK_NODE_PORT=2222 IPV4_CONNECT=PASS'),
            )
            self.assertEqual(connects, [('127.0.0.1', 2222), ('8.8.4.4', 2222)])

            self.assertEqual(
                M.listener_runtime_status(str(config), str(ports), False, runner,
                                          lambda host, port: host == '127.0.0.1'),
                (False, 'NODE_PORT_DUAL_STACK_IPV4_CONNECT_FAILED'),
            )

    def test_dual_stack_exception_does_not_hide_other_missing_ports(self):
        with tempfile.TemporaryDirectory(prefix='vk-listener-252-strict-') as tmp:
            root = Path(tmp)
            config = root / 'config.json'
            ports = root / 'ssh-ports'
            config.write_text(json.dumps({'node_port': 2222, 'public_ipv4': '8.8.4.4'}))
            ports.write_text('22\n')
            raw4 = line('0.0.0.0:22', 'sshd', 10) + '\n'
            docker_top = 'PID COMMAND\n40 rw-node\n'

            def runner(args, **kwargs):
                if args[:5] == ['ss', '-H', '-4', '-lntp']:
                    return subprocess.CompletedProcess(args, 0, raw4, '')
                if 'top' in args:
                    return subprocess.CompletedProcess(args, 0, docker_top, '')
                raise AssertionError(args)

            ok, reason = M.listener_runtime_status(
                str(config), str(ports), False, runner, lambda *_: True
            )
            self.assertFalse(ok)
            self.assertEqual(reason, 'MISSING_EXPECTED_PORTS=80,2222')


if __name__ == '__main__':
    unittest.main()
