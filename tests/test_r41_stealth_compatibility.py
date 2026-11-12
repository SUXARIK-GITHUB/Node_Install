"""r41: real default-site contract, bounded TLS and XHTTP export integrity."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import unittest
from urllib.parse import quote
from unittest.mock import patch

from common import ROOT, module
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'integrations'))
import stealth_external_audit as tls_audit
import xhttp_subscription_audit as sub_audit
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class DefaultSiteContract(unittest.TestCase):
    def test_embedded_fallback_is_not_a_placeholder(self):
        embedded = module('VK_SITE_TOOL_PY')
        for i in range(20):
            data, _ = embedded.render('node.example.test', f'{i:064x}')
            body = data.decode('utf-8').lower()
            for unwanted in ('скоро открытие', 'сайт в разработке', 'демонстрационный',
                             'скоро откроемся', 'будущего сайта', 'remnawave', 'vless'):
                self.assertNotIn(unwanted, body)
            self.assertIn('редакционные заметки', body)

    def test_catalog_default_only_for_new_ordinary_verified_full_zip(self):
        source = (ROOT / 'install.sh').read_text()
        scope = source.index('# Fresh Ordinary only: install an audited multi-page theme')
        active = source.index("VK_INITIAL_SITE_THEME='111-atlas-docs'", scope)
        preflight = source.index('scripts/verify_release.py', scope)
        check_live = source.index('! -e "$STATE/INSTALL_COMPLETE"', scope)
        check_cascade = source.index('VK_CASCADE_ACTIVE -eq 0', scope)
        install_stage = source.index("VK_SITE_PARTIAL_FAILURE=0", scope)
        self.assertTrue(scope < check_cascade < check_live < preflight < active < install_stage)
        self.assertTrue((ROOT / 'site-catalog/111-atlas-docs/index.html').is_file())
        self.assertTrue((ROOT / 'site-catalog/111-atlas-docs/404.html').is_file())
        self.assertIn('SITE_DEFAULT=VERIFIED_CATALOG', source)
        self.assertIn('VK_INITIAL_SITE_THEME', source[install_stage:install_stage + 1700])


class ParallelTLS(unittest.TestCase):
    def sample(self, *, cipher='TLS_AES_128_GCM_SHA256', failures=0):
        calls = []
        def connect(address, domain, **kw):
            calls.append(kw)
            if failures and len(calls) <= failures:
                raise socket.timeout('private test timeout')
            return {'tls': 'TLSv1.3', 'alpn': 'h2', 'cipher': cipher, 'elapsed_ms': 17}
        return tls_audit.parallel_tls_sample('cover.example.test', '8.8.4.4', connect=connect), calls

    def test_sample_bounds_and_protocol(self):
        report, calls = self.sample()
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['attempts'], 4)
        self.assertEqual(report['elapsed_ms_median'], 17)
        self.assertTrue(all(kw['version'] == ssl.TLSVersion.TLSv1_3 and kw['offer_h2'] for kw in calls))
        self.assertNotIn('8.8.4.4', json.dumps(report))
        self.assertNotIn('cover.example.test', json.dumps(report))
        with self.assertRaises(tls_audit.AuditError):
            tls_audit.parallel_tls_sample('cover.example.test', '8.8.4.4', count=5)

    def test_failure_or_divergent_fingerprint_is_not_pass(self):
        from itertools import count
        from threading import Lock
        index, lock = count(), Lock()
        def diverge(_, __, **kwargs):
            with lock:
                cipher = 'CIPHER_' + str(next(index))
            return {'tls': 'TLSv1.3', 'alpn': 'h2',
                    'cipher': cipher, 'elapsed_ms': 100}
        result = tls_audit.parallel_tls_sample('cover.example.test', '8.8.4.4', connect=diverge)
        self.assertEqual(result['status'], 'REVIEW')
        def fail(_, __, **kwargs):
            raise socket.timeout('timeout')
        self.assertEqual(tls_audit.parallel_tls_sample('cover.example.test', '8.8.4.4',
                                                      connect=fail)['status'], 'FAIL')

    def test_optional_audit_keeps_default_behavior_unchanged(self):
        def connect(ip, domain, **kw):
            if kw.get('sni') != domain:
                raise ssl.SSLError('[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] handshake failure')
            return {'tls': 'TLSv1.2' if kw.get('version') == ssl.TLSVersion.TLSv1_2 else 'TLSv1.3',
                    'alpn': 'h2' if kw.get('offer_h2') else 'http/1.1', 'http_code':
                    421 if kw.get('host') else 404 if kw.get('path', '/') != '/' else 200,
                    'security_headers': True}
        plain = lambda a, b: {'http_code': 301, 'redirect_to_expected_https': True}
        resolve = lambda a,b: {'status': 'PASS'}
        def parallel(*args, **kwargs):
            return {'status': 'REVIEW', 'attempts': 4, 'reason': 'SYNTHETIC'}
        base = tls_audit.audit('node.example.test', '8.8.8.8', connect=connect,
                              plain=plain, resolve=resolve, parallel=parallel)
        active = tls_audit.audit('node.example.test', '8.8.8.8', connect=connect,
                                plain=plain, resolve=resolve, parallel_count=4,
                                parallel=parallel)
        self.assertNotIn('parallel_tls13', base['checks'])
        self.assertEqual(active['checks']['parallel_tls13']['status'], 'REVIEW')
        self.assertNotEqual(active['live_checks_status'], 'PASS')


class XHTTPClientExportContract(unittest.TestCase):
    def setUp(self):
        self.secret = bytes(range(1, 33))
        pk = X25519PrivateKey.from_private_bytes(self.secret).public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        self.enc = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
        self.public = self.enc(pk)
        self.server = {
            'inbounds': [{'protocol': 'vless', 'settings': {'flow': ''},
                          'streamSettings': {'network': 'xhttp', 'security': 'reality',
                                             'realitySettings': {'privateKey': self.enc(self.secret),
                                                                 'serverNames': ['node.example.test'],
                                                                 'shortIds': ['abcdef1234567890']},
                                             'xhttpSettings': {'mode': 'auto', 'host': 'node.example.test',
                                                               'path': '/abc123'}}}]}
        self.client = {'network': 'xhttp', 'security': 'reality', 'flow': '',
                       'sni': 'node.example.test', 'public_key': self.public,
                       'short_id': 'abcdef1234567890', 'fingerprint': 'chrome',
                       'host': 'node.example.test', 'path': '/abc123', 'mode': 'auto'}

    def test_correct_export_is_only_static_match(self):
        report = sub_audit.audit(self.server, self.client)
        self.assertEqual(report['status'], 'STATIC_MATCH', report)
        self.assertEqual(report['live_connectivity'], 'UNVERIFIED')
        data = json.dumps(report)
        for secret in (self.public, self.enc(self.secret), 'node.example.test', 'abcdef1234567890'):
            self.assertNotIn(secret, data)

    def test_path_key_shortid_flow_and_transport_mismatch(self):
        changes = [('path', '/wrong', 'CLIENT_XHTTP_PATH_MISMATCH_OR_MISSING'),
                   ('public_key', self.enc(b'X'*32), 'CLIENT_REALITY_PUBLIC_KEY_MISMATCH'),
                   ('short_id', 'bad', 'CLIENT_SHORT_ID_MISMATCH'),
                   ('flow', 'xtls-rprx-vision', 'CLIENT_MUST_NOT_USE_VISION'),
                   ('network', 'raw', 'CLIENT_NOT_XHTTP_REALITY'),
                   ('host', None, 'CLIENT_XHTTP_HOST_MISMATCH_OR_MISSING')]
        for field, value, expected in changes:
            with self.subTest(field=field):
                candidate = dict(self.client, **{field: value})
                result = sub_audit.audit(self.server, candidate)
                self.assertEqual(result['status'], 'FAIL')
                self.assertIn(expected, result['issues'])

    def test_fingerprint_and_forced_modes_require_live_review(self):
        self.assertIn('FINGERPRINT_REQUIRES_HYBRID_TLS_COMPATIBILITY_REVIEW',
                      sub_audit.audit(self.server, dict(self.client, fingerprint='edge'))['observations'])
        self.assertIn('CLIENT_FORCED_XHTTP_MODE_REQUIRES_LIVE_REVIEW',
                      sub_audit.audit(self.server, dict(self.client, mode='stream-one'))['observations'])
        self.assertEqual(sub_audit.audit(self.server, dict(self.client, mode='unknown'))['status'], 'FAIL')

    def test_private_uri_and_json_without_leaks_or_symlink_follow(self):
        with tempfile.TemporaryDirectory() as dirname:
            base = Path(dirname)
            uri = ('vless://00000000-0000-4000-8000-000000000000@node.example.test:443?'
                   'type=xhttp&security=reality&flow=&sni=node.example.test&pbk='+self.public+
                   '&sid=abcdef1234567890&fp=chrome&host=node.example.test&path=%2Fabc123&mode=auto')
            path = base / 'client.txt'
            path.write_text(uri)
            path.chmod(0o600)
            self.assertEqual(sub_audit.read_client(path), self.client)
            result = sub_audit.audit(self.server, sub_audit.read_client(path))
            self.assertEqual(result['status'], 'STATIC_MATCH')
            path.write_text(uri+'&sni=extra.example.test')
            with self.assertRaises(sub_audit.Invalid):
                sub_audit.read_client(path)
            path.chmod(0o644)
            with self.assertRaises(sub_audit.Invalid):
                sub_audit.read_client(path)
            path.unlink()
            target = base / 'other.txt'
            target.write_text(uri)
            target.chmod(0o600)
            path.symlink_to(target)
            with self.assertRaises(OSError):
                sub_audit.read_client(path)
            path.unlink()
            c = self.client
            json_client = {'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{
                'address': 'node.example.test', 'port': 443, 'users': [{'id':'0000', 'flow': ''}]}]},
                'streamSettings': {'network': c['network'], 'security': c['security'],
                                   'realitySettings': {'serverName': c['sni'],
                                                       'publicKey': c['public_key'],
                                                       'shortId': c['short_id'],
                                                       'fingerprint': c['fingerprint']},
                                   'xhttpSettings': {'host': c['host'], 'path': c['path'],
                                                     'mode': c['mode']}}}]}
            path.write_text(json.dumps(json_client))
            path.chmod(0o600)
            self.assertEqual(sub_audit.read_client(path), dict(self.client, direct_route_review=False, direct_default_review=False))
            json_client['outbounds'].append({'protocol': 'freedom', 'tag': 'direct'})
            json_client['routing'] = {'rules': [{'outboundTag': 'direct', 'type': 'field', 'domain': ['geosite:private']}]}
            path.write_text(json.dumps(json_client))
            self.assertIn('EXPLICIT_DIRECT_ROUTING_PRESENT_REVIEW_CLIENT_PRIVACY_POLICY',
                          sub_audit.audit(self.server, sub_audit.read_client(path))['observations'])


if __name__ == '__main__':
    unittest.main()
