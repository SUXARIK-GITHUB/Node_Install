"""2026-10-14 RKN advisory regressions: cover TLS, HSTS, Vision, management isolation.

No VPS changes. A real Nginx test listens on a private Unix socket using temporary CA.
This does NOT verify Xray on the public 443 or an external firewall/provider.
"""
import copy
import hashlib
from pathlib import Path
import re
import ssl
import time
import unittest
from unittest.mock import patch

from common import SCRIPT, module, template
import test_220_selfsteal as cover_fixture
import test_tls_integration as fixture


class EdgeTemplate258(unittest.TestCase):
    def test_https_hsts_only_named_host(self):
        conf = template('/etc/nginx/conf.d/20-vkarmani-selfsteal.conf')
        self.assertEqual(conf.count('Strict-Transport-Security'), 1)
        self.assertIn('add_header Strict-Transport-Security "max-age=300" always;', conf)
        self.assertNotIn('includeSubDomains', conf)
        self.assertNotIn('preload', '\n'.join(x for x in conf.splitlines() if x.lstrip().startswith('add_header ')))
        default, named = conf.split('    server_name $DOMAIN;', 1)
        self.assertNotIn('Strict-Transport-Security', default)
        self.assertIn('    ssl_protocols TLSv1.2 TLSv1.3;', named)
        named_server = conf.rsplit('server {', 1)[1]
        self.assertIn('listen unix:$NGINX_SELFSTEAL_HTTPS_SOCKET ssl', named_server)
        self.assertIn('$NGINX_SELFSTEAL_HTTPS_PROXY;', named_server)
        self.assertIn('    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;', named)
        self.assertIn('    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;', named)
        self.assertIn('add_header X-Content-Type-Options nosniff always;', named)
        self.assertIn('add_header Content-Security-Policy ', named)

    def test_http80_exact_301_not_reflected_host(self):
        conf = template('/etc/nginx/conf.d/10-vkarmani-http.conf')
        self.assertIn('listen $PUBLIC_IP:80 default_server;', conf)
        self.assertIn('server_name _;', conf)
        self.assertIn('return 404;', conf)
        self.assertIn('location / { $NGINX_HTTP_ROOT_ACTION }', conf)
        self.assertIn("NGINX_HTTP_ROOT_ACTION='return 301 https://'", SCRIPT)
        self.assertNotIn("NGINX_HTTP_ROOT_ACTION='return 404;'", SCRIPT)
        self.assertIn('if (\\$host != $DOMAIN) { return 404; }', conf)
        self.assertIn('location ^~ /.well-known/acme-challenge/', conf)
        self.assertIn('HTTP80_301_FIXED_DOMAIN', SCRIPT)
        self.assertIn('Location:', SCRIPT)

    def test_public_tls12_and_tls13_probes_not_unverified_pass(self):
        self.assertIn('--tls-max "$TLS"', SCRIPT)
        self.assertIn('for TLS in 1.2 1.3;', SCRIPT)
        self.assertIn('REALITY_443_TLS${TLS//./}_HSTS', SCRIPT)
        self.assertIn('PUBLIC_TLS_OK=0', SCRIPT)
        self.assertIn('[[ "$PUBLIC_TLS_OK" -eq 1 && "$REMOTE_TLS_OK" -eq 1 ]] && XRAY_COVER_OK=1', SCRIPT)
        self.assertIn('fail "REALITY_443_TLS${TLS//./}_HSTS"', SCRIPT)
        self.assertNotIn('curl -k', SCRIPT)
        self.assertNotIn('--insecure', SCRIPT.split('PUBLIC_TLS_OK=1',1)[1].split('    done',1)[0])

    def test_node_management_port_restricted_to_panel_sources(self):
        # Static template plus mock-level existing firewall tests; external scanning is required.
        self.assertIn('ufw default deny incoming', SCRIPT)
        self.assertIn('ufw allow proto tcp from "$panel" to any port "$NODE_PORT"', SCRIPT)
        self.assertNotRegex(SCRIPT, r'(?m)^ufw allow (?:\d+|2222)/tcp\s*$')
        self.assertIn('then pass UFW_TCP_POLICY; else fail UFW_TCP_POLICY;', SCRIPT)
        self.assertIn('PUBLIC_TCP_LISTENERS_POLICY', SCRIPT)

    def test_raw_vision_not_replaced_and_xhttp_remains_alternative(self):
        h = module('PY_HELPER')
        with patch.object(h, 'detect_local_public_ipv4s', return_value={'192.0.2.10':'eth0'}):
            # Only structural assertion; cannot create and test live user credentials here.
            profile_text = SCRIPT.split("'streamSettings': {", 1)[1]
            self.assertIn("'network': 'raw'", profile_text)
            self.assertIn("'security': 'reality'", profile_text)
        self.assertIn("PROFILE_FLOW = 'xtls-rprx-vision'", SCRIPT)
        self.assertIn('XHTTP', (Path(__file__).resolve().parents[1] / 'README.md').read_text())

    def test_missing_hsts_malformed_duplicate_wide_policy_rejected(self):
        h = module('VK_PAYLOAD_VK_WRITE_SELFSTEAL_CHECK')
        good = {'x-content-type-options': 'nosniff',
                'referrer-policy': 'strict-origin-when-cross-origin',
                'content-security-policy': "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
                'strict-transport-security': 'max-age=300'}
        h.security_headers(good)
        for bad in (None, '', 'max-age=0', 'max-age=300; includeSubDomains',
                    'max-age=300; preload', 'max-age=31536000', 'max-age=300, max-age=300'):
            conf = copy.deepcopy(good)
            if bad is None: conf.pop('strict-transport-security')
            else: conf['strict-transport-security'] = bad
            with self.subTest(hsts=bad), self.assertRaisesRegex(ValueError, 'HSTS_NOT_EFFECTIVE'):
                h.security_headers(conf)

    def test_probe_uses_both_versions_with_bound_and_no_skip(self):
        h = module('VK_PAYLOAD_VK_WRITE_SELFSTEAL_CHECK')
        seen = []
        class Dummy:
            def __enter__(self): return self
            def __exit__(self, *args): pass
        def fake_connect(*args, **kwargs):
            seen.append((args[1], kwargs.get('tls_version')))
            return Dummy()
        with patch.object(h, 'connect', side_effect=fake_connect):
            h.target_tls('node.example.test', timeout=5)
        self.assertEqual(seen, [('http/1.1', ssl.TLSVersion.TLSv1_2),
                                ('http/1.1', ssl.TLSVersion.TLSv1_3),
                                ('h2', ssl.TLSVersion.TLSv1_3)])


@unittest.skipUnless(fixture.NGINX, 'real local Nginx unavailable; cannot verify TLS1.2/1.3')
class EdgeLiveNginx258(unittest.TestCase):
    configure = classmethod(cover_fixture.Selfsteal220Tests.configure.__func__)
    start = classmethod(cover_fixture.Selfsteal220Tests.start.__func__)
    stop = classmethod(cover_fixture.Selfsteal220Tests.stop.__func__)

    @classmethod
    def setUpClass(cls):
        cover_fixture.Selfsteal220Tests.setUpClass.__func__(cls)

    def test_verified_tls12_and_tls13_same_named_selfsteal(self):
        leaf = hashlib.sha256(ssl.PEM_cert_to_DER_cert(self.bundle['nodeCertPem'])).digest()
        for tls in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            with self.subTest(protocol=tls):
                status, headers, body = self.helper.http1_request(
                    'node.example.test', self.socket_path, self.root/'ca.pem',
                    time.monotonic()+6, leaf, tls_version=tls)
                self.assertEqual((status, body), (200, self.index))
                self.helper.security_headers(headers)
                self.assertEqual(headers['strict-transport-security'], 'max-age=300')

    def test_hsts_on_404_and_405_not_only_success(self):
        for kwargs, expected in (({'uri':'/not-existing'},404),({'method':'POST'},405)):
            with self.subTest(kwargs=kwargs):
                status, headers, _ = self.helper.http1_request(
                    'node.example.test', self.socket_path, self.root/'ca.pem',
                    time.monotonic()+5, None, **kwargs)
                self.assertEqual(status,expected)
                self.helper.security_headers(headers)

    def test_local_full_contract_rejects_hsts_removal(self):
        self.helper.check('node.example.test', self.socket_path, self.site/'index.html',
                          self.root/'ca.pem', timeout=8, extended=True,
                          reject_unknown_sni=self.reject_sni)


if __name__ == '__main__':
    unittest.main()
