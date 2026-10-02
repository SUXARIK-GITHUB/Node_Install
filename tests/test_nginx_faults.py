"""Real isolated Nginx chaos/recovery; never touch host Nginx or public ports."""
import concurrent.futures
import hashlib
import os
from pathlib import Path
import socket
import ssl
import subprocess
import time
import unittest
from common import module
import test_tls_integration as tls_fixture
NGINX = tls_fixture.NGINX

@unittest.skipUnless(NGINX, 'isolated Nginx binary is unavailable')
class NginxFaultIntegrationTests(unittest.TestCase):
    setUpClass = classmethod(tls_fixture.NginxSelfstealIntegrationTests.setUpClass.__func__)
    configure = classmethod(tls_fixture.NginxSelfstealIntegrationTests.configure.__func__)
    start = classmethod(tls_fixture.NginxSelfstealIntegrationTests.start.__func__)
    stop = classmethod(tls_fixture.NginxSelfstealIntegrationTests.stop.__func__)

    def setUp(self):
        self.cover = self.site / 'index.html'
        self.original = self.cover.read_bytes()
        self.addCleanup(self.cover.write_bytes, self.original)

    def probe(self, **kwargs):
        return self.helper.check('node.example.test', path=self.socket_path,
                                 site=self.cover, cafile=self.root / 'ca.pem', **kwargs)

    def test_96_kib_page_does_not_stall_at_http2_flow_window(self):
        self.cover.write_bytes(b'x' * (96 * 1024))
        self.probe(timeout=3)

    def test_128_kib_boundary_succeeds(self):
        self.cover.write_bytes(b'x' * (128 * 1024))
        self.probe(timeout=3)

    def test_oversized_page_is_explicitly_rejected(self):
        self.cover.write_bytes(b'x' * (128 * 1024 + 1))
        with self.assertRaisesRegex(ValueError, '128_KIB_PROBE_LIMIT'):
            self.probe()

    def test_current_leaf_pin_succeeds(self):
        expected = hashlib.sha256(ssl.PEM_cert_to_DER_cert(self.bundle['nodeCertPem'])).digest()
        self.probe(expected_leaf=expected)

    def test_certificate_not_reloaded_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'CERTIFICATE_NOT_RELOADED'):
            self.probe(expected_leaf=b'!' * 32)

    def test_live_socket_is_not_removed_by_prepare(self):
        helper = module('VK_SOCKET_PREPARE')
        with self.assertRaisesRegex(helper.UnsafeSocket, 'LIVE_SOCKET_UNCHANGED'):
            helper.prepare(Path(self.socket_path))
        self.probe()

    def test_sigkill_stale_socket_recovery_three_times(self):
        helper = module('VK_SOCKET_PREPARE')
        for _ in range(3):
            self.proc.kill()
            self.proc.wait(timeout=3)
            self.assertTrue(Path(self.socket_path).is_socket())
            with self.assertRaises(ConnectionRefusedError):
                self.probe(timeout=.5)
            self.assertEqual(helper.prepare(Path(self.socket_path)), 'STALE_REMOVED')
            self.start()
            self.probe(timeout=3)

    def test_parallel_probes_128_requests_16_workers(self):
        # Each probe makes two TLS sessions. Not a VPN throughput benchmark.
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(lambda _: self.probe(timeout=5), range(128)))
        self.assertIsNone(self.proc.poll())
        self.probe()

    def test_plain_tls_without_proxy_header_is_rejected(self):
        ctx = ssl.create_default_context(cafile=self.root / 'ca.pem')
        raw = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        raw.settimeout(.5)
        try:
            raw.connect(self.socket_path)
            with self.assertRaises((ssl.SSLError, OSError)):
                with ctx.wrap_socket(raw, server_hostname='node.example.test'):
                    self.fail('Nginx accepted missing PROXY header')
        finally:
            raw.close()
        self.probe()

    def test_non_200_nginx_response_is_not_success(self):
        # The real Nginx must not be reported healthy when its location returns 404.
        self.stop()
        config = self.root / 'nginx.conf'
        original = config.read_text()
        altered = original.replace('try_files /index.html =404;', 'return 404;')
        self.assertNotEqual(altered, original)
        try:
            config.write_text(altered)
            self.start()
            with self.assertRaisesRegex(ValueError, 'HTTP/1.1'):
                self.probe()
        finally:
            self.stop()
            config.write_text(original)
            self.start()

if __name__ == '__main__':
    unittest.main()
