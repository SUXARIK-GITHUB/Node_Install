"""Real, isolated Nginx contract plus negative probes. No production services/ports."""
import concurrent.futures
import hashlib
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import time
import unittest
from unittest.mock import patch
from common import module, payload, template
import test_tls_integration as fixture
import test_protocol_faults as peers


@unittest.skipUnless(fixture.NGINX, 'Nginx unavailable: real Selfsteal contract not verified')
class Selfsteal220Tests(unittest.TestCase):
    configure = classmethod(fixture.NginxSelfstealIntegrationTests.configure.__func__)
    start = classmethod(fixture.NginxSelfstealIntegrationTests.start.__func__)
    stop = classmethod(fixture.NginxSelfstealIntegrationTests.stop.__func__)

    @classmethod
    def setUpClass(cls):
        fixture.NginxSelfstealIntegrationTests.setUpClass.__func__(cls)
        cls.cover = module('VK_SITE_TOOL_PY')
        cls.index, cls.assets = cls.cover.render('node.example.test', 'a' * 64)
        (cls.site / 'index.html').write_bytes(cls.index)
        for name, data in cls.assets.items():
            p = cls.site / name
            p.parent.mkdir(exist_ok=True)
            p.write_bytes(data)
            p.chmod(0o644)
        cls.defaults = {'robots.txt': b'User-agent: *\nDisallow:\n',
                        'favicon.svg': b'<svg xmlns="http://www.w3.org/2000/svg"/>',
                        '404.html': b'<!doctype html><title>404</title><h1>Not found</h1>'}
        for name, data in cls.defaults.items():
            (cls.site / name).write_bytes(data)
            (cls.site / name).chmod(0o644)
        cls.stop()
        conf = cls.root / 'nginx.conf'
        conf.write_text(conf.read_text().replace('http { access_log off;',
            'http { types { text/css css; image/svg+xml svg; text/html html; text/plain txt; } access_log off;'))
        cls.start()

    def request(self, **kw):
        return self.helper.http1_request('node.example.test', self.socket_path,
            self.root / 'ca.pem', time.monotonic() + 5, None, **kw)

    def probe(self):
        return self.helper.check('node.example.test', self.socket_path,
            self.site / 'index.html', self.root / 'ca.pem', timeout=8,
            extended=True, reject_unknown_sni=self.reject_sni)

    def test_full_contract_including_assets_head_cache_and_negatives(self):
        self.probe()

    def test_unknown_sni_server_reject_or_explicit_legacy(self):
        if self.reject_sni:
            self.helper.negative_sni(self.socket_path, 'wrong.example.test', time.monotonic() + 4)
        else:
            with self.assertRaisesRegex(ValueError, 'UNEXPECTED_SNI_ACCEPTED'):
                self.helper.negative_sni(self.socket_path, 'wrong.example.test', time.monotonic() + 4)

    def test_no_sni_server_reject_or_explicit_legacy(self):
        if self.reject_sni:
            self.helper.negative_sni(self.socket_path, None, time.monotonic() + 4)
        else:
            with self.assertRaisesRegex(ValueError, 'UNEXPECTED_SNI_ACCEPTED'):
                self.helper.negative_sni(self.socket_path, None, time.monotonic() + 4)

    def test_wrong_host_and_write_method_rejected(self):
        self.assertEqual(self.request(host='unrelated.example.test')[0], 421)
        self.assertEqual(self.request(method='POST')[0], 405)

    def test_uppercase_host_and_port_compatible(self):
        self.assertEqual(self.request(host='NODE.EXAMPLE.TEST:443')[0], 200)

    def test_secret_files_in_site_not_served(self):
        for name in ('.env', 'config.json', 'private.pem', 'backup.sql'):
            p = self.site / name
            try:
                p.write_bytes(b'NEVER_PUBLIC_TEST_CANARY')
                p.chmod(0o644)
                status, headers, body = self.request(uri='/' + name)
                self.assertEqual(status, 404)
                self.assertNotIn(b'NEVER_PUBLIC_TEST_CANARY', body)
                self.helper.security_headers(headers)
            finally:
                p.unlink(missing_ok=True)

    def test_unversioned_asset_is_not_served(self):
        p = self.site / 'assets' / 'unlisted.css'
        try:
            p.write_bytes(b'CANARY');p.chmod(0o644)
            self.assertEqual(self.request(uri='/assets/unlisted.css')[0], 404)
        finally:
            p.unlink(missing_ok=True)

    def test_allowed_asset_symlink_to_secret_is_not_served(self):
        secret = self.root / 'secret-canary'
        secret.write_bytes(b'SECRET_CANARY');secret.chmod(0o644)
        name = '/assets/style-' + 'a' * 20 + '.css'
        link = self.site / name[1:]
        try:
            link.symlink_to(secret)
            status, _, body = self.request(uri=name)
            self.assertEqual(status, 404)
            self.assertNotIn(b'SECRET_CANARY', body)
        finally:
            link.unlink(missing_ok=True)

    def test_asset_header_inheritance_and_304_no_body(self):
        for name in self.assets:
            status, h, body = self.request(uri='/' + name)
            self.assertEqual(status, 200)
            self.helper.security_headers(h)
            self.assertIn('max-age=604800', h['cache-control'])
            status, h, body = self.request(uri='/' + name, etag=h['etag'])
            self.assertEqual((status, body), (304, b''))
            self.helper.security_headers(h)

    def test_head_no_payload_and_html_no_cache(self):
        status, h, body = self.request(method='HEAD')
        self.assertEqual((status, body), (200, b''))
        self.assertEqual(h['content-length'], str(len(self.index)))
        self.assertIn('no-cache', h['cache-control'])

    def test_custom_404_body_and_protection_headers(self):
        status, h, body = self.request(uri='/not-published')
        self.assertEqual(status, 404)
        self.assertEqual(body, self.defaults['404.html'])
        self.helper.security_headers(h)

    def test_damaged_asset_detected_even_if_root_still_200(self):
        name = next(iter(self.assets));p = self.site / name
        try:
            p.write_bytes(b'TAMPER')
            self.assertEqual(self.request()[0], 200)
            with self.assertRaisesRegex(ValueError, 'HASH_NAME_MISMATCH'):
                self.probe()
        finally:
            p.write_bytes(self.assets[name])

    def test_20_extended_checks_four_workers(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda _: self.probe(), range(20)))
        self.assertIsNone(self.proc.poll())

    def test_fallback_without_new_directive_is_parseable(self):
        # Simulate feature gating. This is NOT an actual Nginx 1.18 binary test.
        c = self.root / 'nginx.conf';text = c.read_text()
        fallback = self.root / 'legacy-feature.conf'
        fallback.write_text(text.replace('ssl_reject_handshake on;', ''))
        r = subprocess.run([fixture.NGINX, '-t', '-p', str(self.root) + '/', '-c', str(fallback)],
                           capture_output=True, timeout=5)
        self.assertEqual(r.returncode, 0, r.stderr)


class Probe220UnitTests(unittest.TestCase):
    def setUp(self):
        self.h = module('VK_PAYLOAD_VK_WRITE_SELFSTEAL_CHECK')

    def request_peer(self, data, **kw):
        with patch.object(self.h, 'connect', return_value=peers.BytesPeer(data)):
            return self.h.http1_request('node.example.test', 'unused', None,
                time.monotonic() + 2, None, **kw)

    def test_content_length_mismatch_is_not_success(self):
        with self.assertRaisesRegex(ValueError, 'CONTENT_LENGTH_MISMATCH'):
            self.request_peer(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc')

    def test_duplicate_header_is_not_accepted(self):
        with self.assertRaisesRegex(ValueError, 'DUPLICATE'):
            self.request_peer(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n')

    def test_head_body_not_accepted(self):
        with self.assertRaisesRegex(ValueError, 'HAS_BODY'):
            self.request_peer(b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx', method='HEAD')

    def test_http_injection_rejected_before_connection(self):
        for kw in ({'host': 'a\r\nX: y'}, {'uri':'/../bad?secret'}, {'etag':'"a"\r\nX: y'}):
            with self.subTest(kw=kw), patch.object(self.h, 'connect') as connect:
                with self.assertRaisesRegex(ValueError, 'UNSAFE'):
                    self.h.http1_request('node.example.test', 'unused', None, time.monotonic()+2, None, **kw)
                connect.assert_not_called()

    def test_asset_external_and_traversal_refused(self):
        for url in ('https://bad.invalid/style.css', '../secret.css', '/etc/passwd', 'assets/a.css'):
            with self.subTest(url=url), self.assertRaisesRegex(ValueError, 'NOT_LOCAL_VERSIONED'):
                parser = self.h.Assets();parser.feed('<link rel="stylesheet" href="'+url+'">')

    def test_nginx_version_capability_not_assumed(self):
        for ver, want in (('1.18.0',False),('1.19.4',True),('1.24.0',True),('1.26.3',True)):
            with patch.object(self.h.subprocess, 'run', return_value=subprocess.CompletedProcess([],0,b'',('nginx/'+ver).encode())):
                self.assertIs(self.h.nginx_sni_reject_supported(), want)
        with patch.object(self.h.subprocess, 'run', return_value=subprocess.CompletedProcess([],1,b'',b'bad')):
            with self.assertRaisesRegex(ValueError,'NOT_VERIFIED'):
                self.h.nginx_sni_reject_supported()

    def test_no_proxy_restart_firewall_command_in_probe(self):
        code = payload('VK_PAYLOAD_VK_WRITE_SELFSTEAL_CHECK')
        for command in ('systemctl', 'iptables', 'docker', 'apt-get', 'killall'):
            self.assertNotIn(command, code)
        self.assertIn('AUTHENTICATED_VLESS_CLIENT=NOT_TESTED', code)

    def test_generated_http_policy_keeps_acme_and_fixed_redirect(self):
        c = template('/etc/nginx/conf.d/10-vkarmani-http.conf')
        self.assertIn('/.well-known/acme-challenge/', c)
        self.assertIn('https://$DOMAIN', c)
        self.assertNotIn('https://\\$host', c)
        self.assertIn('default_server', c)


@unittest.skipUnless(fixture.NGINX, 'Nginx unavailable: fragmented TLS test not verified')
class FragmentedSelfsteal220Tests(unittest.TestCase):
    setUpClass = classmethod(Selfsteal220Tests.setUpClass.__func__)
    configure = classmethod(Selfsteal220Tests.configure.__func__)
    start = classmethod(Selfsteal220Tests.start.__func__)
    stop = classmethod(Selfsteal220Tests.stop.__func__)

    def test_large_fragmented_clienthello_and_proxy_header(self):
        # Nginx target only, not Xray or an external carrier. Every TLS byte is
        # actually exchanged with a private Nginx socket; no handshake mock.
        ctx=ssl.create_default_context(cafile=self.root/'ca.pem')
        ctx.minimum_version=ctx.maximum_version=ssl.TLSVersion.TLSv1_3
        ctx.set_alpn_protocols(['http/1.1']+['padding-'+str(i)+'x'*80 for i in range(20)])
        incoming,outgoing=ssl.MemoryBIO(),ssl.MemoryBIO()
        engine=ctx.wrap_bio(incoming,outgoing,server_side=False,server_hostname='node.example.test')
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.settimeout(2)
        deadline=time.monotonic()+5
        first=0
        try:
            sock.connect(self.socket_path)
            proxy=b'PROXY TCP4 127.0.0.1 127.0.0.1 54321 443\r\n'
            for offset in range(0,len(proxy),7):sock.sendall(proxy[offset:offset+7])
            for _ in range(100):
                self.assertLess(time.monotonic(),deadline)
                try:
                    engine.do_handshake();done=True
                except ssl.SSLWantReadError:done=False
                if outgoing.pending:
                    b=outgoing.read()
                    if not first:first=len(b)
                    for offset in range(0,len(b),37):sock.sendall(b[offset:offset+37])
                if done:break
                b=sock.recv(16384);self.assertTrue(b);incoming.write(b)
            else:self.fail('TLS handshake never completed')
            self.assertGreater(first,1500)
            self.assertEqual(engine.selected_alpn_protocol(),'http/1.1')
            engine.write(b'HEAD / HTTP/1.1\r\nHost: node.example.test\r\nConnection: close\r\n\r\n')
            sock.sendall(outgoing.read())
            response=bytearray()
            for _ in range(100):
                try:
                    b=engine.read(16384)
                    if not b:break
                    response.extend(b)
                    if b'\r\n\r\n' in response:break
                except ssl.SSLWantReadError:
                    incoming.write(sock.recv(16384))
                self.assertLess(time.monotonic(),deadline)
            self.assertTrue(response.startswith(b'HTTP/1.1 200 '),bytes(response[:40]))
        finally:sock.close()
