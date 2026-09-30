import base64
import contextlib
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from common import module, certificate_bundle, payload


class ValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.h = module('PY_HELPER')
        cls.tls = module('VK_PAYLOAD_VK_WRITE_TLS_CHECK')
        cls.bundle, cls.secret = certificate_bundle()

    def test_valid_secret_and_prefix_quotes(self):
        for value in (self.secret, 'SECRET_KEY=' + self.secret, "'" + self.secret + "'", '"' + self.secret + '"'):
            self.assertEqual(self.h.normalize_secret(value, check_dates=True), self.secret)

    def test_invalid_secrets_never_appear_in_errors(self):
        for secret in ('bad-private-value', 'a' * 100, '{}', '$(touch /tmp/NOPE)', 'x\ny', '', None):
            with self.subTest(value_type=type(secret).__name__):
                with self.assertRaises(self.h.Failure) as caught:
                    self.h.normalize_secret(secret)
                if secret and isinstance(secret, str):
                    self.assertNotIn(secret, str(caught.exception))

    def test_secret_key_pair_mismatch_rejected(self):
        other, _ = certificate_bundle()
        bundle = dict(self.bundle, nodeKeyPem=other['nodeKeyPem'])
        secret = base64.b64encode(json.dumps(bundle).encode()).decode()
        with self.assertRaises(self.h.Failure):
            self.h.normalize_secret(secret)

    def test_wrong_ca_signature_rejected(self):
        other, _ = certificate_bundle()
        bundle = dict(self.bundle, caCertPem=other['caCertPem'])
        secret = base64.b64encode(json.dumps(bundle).encode()).decode()
        with self.assertRaises(self.h.Failure):
            self.h.normalize_secret(secret)

    def test_expired_secret_rejected_after_time_sync(self):
        _, secret = certificate_bundle(expired=True)
        self.assertEqual(self.h.normalize_secret(secret, check_dates=False), secret)
        with self.assertRaises(self.h.Failure):
            self.h.normalize_secret(secret, check_dates=True)

    def test_domain_validation(self):
        self.assertEqual(self.h.domain('  NODE.Example.Com.  '), 'node.example.com')
        for value in ('https://node.example.com', 'node.example.com:443', 'foo..com', '-a.com',
                      'a-.com', '127.0.0.1', 'localhost', 'x\n.com', 'a' * 64 + '.com', None):
            with self.subTest(value=value), self.assertRaises(self.h.Failure):
                self.h.domain(value)

    def test_public_ipv4_rejects_local_reserved_ipv6_cidr(self):
        self.assertEqual(self.h.public_ipv4('8.8.8.8'), '8.8.8.8')
        for value in ('127.0.0.1', '0.0.0.0', '10.0.0.1', '172.16.1.1', '192.168.1.1',
                      '100.64.0.1', '169.254.169.254', '198.18.0.1', '192.0.2.1',
                      '224.0.0.1', '240.1.1.1', '255.255.255.255', '8.8.8.8/32',
                      '008.8.8.8', '2001:db8::1', 123, None):
            with self.subTest(value=value), self.assertRaises(self.h.Failure):
                self.h.public_ipv4(value)

    def config(self):
        return {'installation_mode': 'secret-key-only', 'domain': 'node.example.test',
                'public_ipv4': '8.8.8.8', 'panel_ipv4': ['1.1.1.1'], 'node_port': 2222}

    def test_config_rejects_unknown_fields_wrong_types_and_foreign_image(self):
        base = self.config()
        for change in ({'node_port': True}, {'node_port': 80}, {'panel_ipv4': []}, {'unknown': 1},
                       {'auto_reboot': 'true'}, {'allow_net_admin': 'false'}, {'image': 'attacker/node:latest'},
                       {'selfsteal_host_socket': '/var/run/docker.sock'}):
            with self.subTest(change=change), self.assertRaises(self.h.Failure):
                self.h.normalize_config(dict(base, **change))

    def test_config_schema_defaults_keep_legacy_auto_reboot_false(self):
        config = self.h.normalize_config(self.config())
        for flag in ('auto_reboot', 'weekly_reboot', 'allow_net_admin'):
            self.assertIs(config[flag], False)
        self.assertIs(config['certbot_dry_run'], True)

    def test_official_image_validation(self):
        for image in ('remnawave/node:latest', 'ghcr.io/remnawave/node:2',
                      'remnawave/node@sha256:' + 'a' * 64):
            self.assertEqual(self.h.normalize_config(dict(self.config(), image=image))['image'], image)

    def test_atomic_secret_permissions(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'private'
            self.h.atomic_text(path, 'TEST-ONLY')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.read_text(), 'TEST-ONLY')
            self.assertEqual(len(list(Path(folder).iterdir())), 1)

    def test_reality_keys_persist_and_private_routes_are_blocked(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(self.h, 'ETC', Path(folder)), \
             patch.object(self.h, 'detect_local_public_ipv4s', return_value={'8.8.8.8': 'eth0', '9.9.9.9': 'eth1'}):
            first = self.h.make_keys_profile(self.config())
            original = (Path(folder) / 'reality.json').read_bytes()
            second = self.h.make_keys_profile(self.config())
            self.assertEqual(original, (Path(folder) / 'reality.json').read_bytes())
            self.assertEqual(first, second)
            profile = first[2]
            self.assertEqual(profile['inbounds'][0]['settings']['clients'], [])
            reality = profile['inbounds'][0]['streamSettings']['realitySettings']
            self.assertEqual((reality['target'], reality['xver'], reality['minClientVer']), ('/dev/shm/nginx.sock', 1, '1.0.0'))
            blocked = profile['routing']['rules'][0]['ip']
            for target in ('127.0.0.0/8', '169.254.0.0/16', '1.1.1.1/32', '9.9.9.9/32', '::/0'):
                self.assertIn(target, blocked)

    def test_corrupted_reality_keys_are_not_regenerated(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(self.h, 'ETC', Path(folder)), \
             patch.object(self.h, 'detect_local_public_ipv4s', return_value={'8.8.8.8': 'eth0'}):
            self.h.make_keys_profile(self.config())
            path = Path(folder) / 'reality.json'
            keys = json.loads(path.read_text())
            keys['public_key'] = 'a' * 43
            path.write_text(json.dumps(keys))
            previous = path.read_bytes()
            with self.assertRaises(self.h.Failure):
                self.h.make_keys_profile(self.config())
            self.assertEqual(path.read_bytes(), previous)

    def test_sni_matches_independent_hkdf_implementation(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        def canon(value):
            return ''.join(line for line in value.splitlines() if not line.startswith('-----')).encode()
        b = self.bundle
        output = HKDF(algorithm=hashes.SHA256(), length=22, salt=b'', info=b'rw-v1').derive(
            canon(b['jwtPublicKey']) + canon(b['caCertPem']))
        expected = output[:16].hex() + '.' + output[16:21].hex() + '.' + ('com', 'net', 'org', 'io', 'dev', 'app')[output[21] % 6]
        self.assertEqual(self.tls.derive_sni(b['caCertPem'], b['jwtPublicKey']), expected)

    def test_sni_pem_whitespace_canonicalization(self):
        b = self.bundle
        expected = self.tls.derive_sni(b['caCertPem'], b['jwtPublicKey'])
        self.assertEqual(self.tls.derive_sni(b['caCertPem'].replace('\n', '\r\n'), b['jwtPublicKey'].replace('\n', '\\n')), expected)

    def test_material_file_permissions_and_pin(self):
        import ssl
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            (path / 'config.json').write_text(json.dumps(self.config()))
            env = path / 'remnanode.env'
            env.write_text('NODE_PORT=2222\nSECRET_KEY=' + self.secret + '\nTZ=Europe/Moscow\n')
            env.chmod(0o600)
            cfg, ca, fp = self.tls.load_material(path)
            self.assertEqual(fp, hashlib.sha256(ssl.PEM_cert_to_DER_cert(self.bundle['nodeCertPem'])).digest())
            self.assertNotEqual(cfg['_probe_servername'], cfg['domain'])
            env.chmod(0o644)
            with self.assertRaises(ValueError):
                self.tls.load_material(path)


class DnsTests(unittest.TestCase):
    def setUp(self):
        self.h = module('PY_HELPER')
        self.local = {'8.8.8.8': 'eth0', '9.9.9.9': 'eth1'}

    def snapshot(self, ipv4='9.9.9.9'):
        return {'system': ({ipv4}, set()), '1.1.1.1': ({ipv4}, set()), '8.8.8.8': ({ipv4}, set())}

    def select(self, snap, local=None):
        with patch.object(self.h, '_dns_snapshot', return_value=snap), \
             patch.object(self.h, 'detect_local_public_ipv4s', return_value=self.local if local is None else local), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return self.h.select_public_ipv4_for_domain('node.example.test', wait_seconds=0)

    def test_multi_ip_selects_dns_address_not_default_source(self):
        self.assertEqual(self.select(self.snapshot()), '9.9.9.9')

    def test_single_unavailable_public_resolver_allowed(self):
        snap = self.snapshot()
        snap['1.1.1.1'] = None
        self.assertEqual(self.select(snap), '9.9.9.9')

    def test_stale_system_dns_warns_but_public_consensus_wins(self):
        snap = self.snapshot()
        snap['system'] = ({'8.8.8.8'}, set())
        self.assertEqual(self.select(snap), '9.9.9.9')

    def test_conflicting_public_resolvers_refused(self):
        snap = self.snapshot()
        snap['1.1.1.1'] = ({'8.8.8.8'}, set())
        with self.assertRaises(self.h.Failure):
            self.select(snap)

    def test_aaaa_refused(self):
        snap = self.snapshot()
        snap['1.1.1.1'] = ({'9.9.9.9'}, {'2001:db8::1'})
        with self.assertRaises(self.h.Failure):
            self.select(snap)

    def test_multiple_a_records_refused(self):
        snap = {name: ({'8.8.8.8', '9.9.9.9'}, set()) for name in self.snapshot()}
        with self.assertRaises(self.h.Failure):
            self.select(snap)

    def test_cdn_or_nat_address_not_assigned_refused(self):
        with self.assertRaises(self.h.Failure):
            self.select(self.snapshot('1.0.0.1'))

    def test_only_system_dns_is_not_external_evidence(self):
        snap = self.snapshot()
        snap['1.1.1.1'] = snap['8.8.8.8'] = None
        with self.assertRaises(self.h.Failure):
            self.select(snap)


class SshTests(unittest.TestCase):
    def setUp(self):
        self.h = module('PY_SSH_CONFIG')

    def test_config_keeps_original_body_and_password_policy(self):
        old = 'Include /etc/ssh/sshd_config.d/*.conf\n# SSH settings\nPort 222\nPubkeyAuthentication yes\n'
        result = self.h.render_ssh(old, ['222'], {'222'})
        self.assertTrue(result.endswith(old))
        self.assertIn('PasswordAuthentication yes\n', result)
        self.assertIn('PermitRootLogin yes\n', result)
        self.assertIn('AuthenticationMethods any\n', result)
        self.assertIn('Port 222\n', result)
        self.assertLess(result.index('PasswordAuthentication yes'), result.index('Include '))

    def test_rerun_keeps_socket_only_ports_and_is_idempotent(self):
        old = '# Default port is implicit\nInclude /etc/ssh/sshd_config.d/*.conf\n'
        first = self.h.render_ssh(old, ['22', '2200'], {'22'})
        second = self.h.render_ssh(first, ['22', '2200'], {'22', '2200'})
        self.assertEqual(first, second)
        self.assertIn('Port 22\nPort 2200\n', second)
        self.assertEqual(second.count(self.h.START), 1)

    def test_bad_ports_and_damaged_marker_are_refused(self):
        for ports in ([], ['0'], ['65536'], ['not-a-port']):
            with self.subTest(ports=ports), self.assertRaises(ValueError):
                self.h.render_ssh('old\n', ports, set())
        with self.assertRaises(ValueError):
            self.h.render_ssh(self.h.START + '\nold\n', ['22'], {'22'})


if __name__ == '__main__':
    unittest.main()
