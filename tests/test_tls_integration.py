"""Real loopback TLS and a private nginx process; no host config/services changed."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

from common import certificate_bundle, module, template
from node_hkdf_oracle import NODE_SNI_PROGRAM


@contextlib.contextmanager
def api_server(bundle, expected_sni):
    """Require a client certificate; the installer must not claim panel authentication."""
    with tempfile.TemporaryDirectory(prefix='vk-api-') as directory:
        root = Path(directory)
        for key, name in [('nodeCertPem', 'cert.pem'), ('nodeKeyPem', 'key.pem'), ('caCertPem', 'ca.pem')]:
            (root / name).write_text(bundle[key])
            (root / name).chmod(0o600)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(root / 'cert.pem', root / 'key.pem')
        ctx.load_verify_locations(root / 'ca.pem')
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.set_alpn_protocols(['http/1.1'])
        seen = []
        def sni(_sock, name, _context):
            seen.append(name)
            return None if name == expected_sni else ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        ctx.set_servername_callback(sni)
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        listener.settimeout(0.1)
        stop, outcomes = threading.Event(), []
        def serve():
            while not stop.is_set():
                try:
                    raw, _ = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                raw.settimeout(2)
                try:
                    with ctx.wrap_socket(raw, server_side=True):
                        outcomes.append('AUTHENTICATED')
                except ssl.SSLError as exc:
                    outcomes.append(exc.reason)
                    raw.close()
                except OSError:
                    raw.close()
        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            yield listener.getsockname()[1], seen, outcomes
        finally:
            stop.set()
            listener.close()
            worker.join(timeout=3)
            if worker.is_alive():
                raise AssertionError('isolated TLS worker did not stop')


class ApiTLSIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = module('VK_PAYLOAD_VK_WRITE_TLS_CHECK')
        cls.bundle, _ = certificate_bundle()
        cls.sni = cls.helper.derive_sni(cls.bundle['caCertPem'], cls.bundle['jwtPublicKey'])
        cls.fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cls.bundle['nodeCertPem'])).digest()

    def test_real_tls_normal_and_fragmented_are_not_panel_authentication(self):
        with api_server(self.bundle, self.sni) as (port, seen, outcomes):
            for fragmented in (False, True):
                ok, reason, size = self.helper.probe('127.0.0.1', port, self.sni, self.bundle['caCertPem'],
                                                    self.fp, fragmented=fragmented, timeout=3)
                self.assertTrue(ok, reason)
                self.assertEqual(reason, 'TLS13_CA_AND_LEAF_OK')
                if fragmented:
                    self.assertGreater(size, 1500)
            time.sleep(0.05)
        self.assertEqual(seen, [self.sni, self.sni])
        self.assertNotIn('AUTHENTICATED', outcomes)
        self.assertTrue(any('CERTIFICATE' in str(x) for x in outcomes), outcomes)

    def test_wrong_ca_is_rejected(self):
        other, _ = certificate_bundle()
        with api_server(self.bundle, self.sni) as (port, _, __):
            result = self.helper.probe('127.0.0.1', port, self.sni, other['caCertPem'], self.fp, timeout=3)
        self.assertEqual(result[:2], (False, 'TLS_CERTIFICATE_VERIFY_FAILED'))

    def test_wrong_leaf_pin_is_rejected(self):
        with api_server(self.bundle, self.sni) as (port, _, __):
            result = self.helper.probe('127.0.0.1', port, self.sni, self.bundle['caCertPem'], b'x' * 32, timeout=3)
        self.assertEqual(result[:2], (False, 'TLS_LEAF_MISMATCH'))

    def test_wrong_sni_is_rejected(self):
        with api_server(self.bundle, self.sni) as (port, _, __):
            result = self.helper.probe('127.0.0.1', port, 'wrong.example.test', self.bundle['caCertPem'], self.fp, timeout=3)
        self.assertFalse(result[0])
        self.assertIn('UNRECOGNIZED_NAME', result[1])

    def test_closed_port_is_not_success(self):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        result = self.helper.probe('127.0.0.1', port, self.sni, self.bundle['caCertPem'], self.fp, timeout=0.5)
        self.assertFalse(result[0])
        self.assertTrue(result[1].startswith('TCP_'), result[1])

    @unittest.skipUnless(shutil.which('node'), 'Node.js absent: independent JavaScript HKDF comparison skipped')
    def test_sni_matches_nodejs_hkdf(self):
        # Jammy's distro Node 12 has createHmac but no hkdfSync. The test oracle
        # keeps native HKDF where available and uses RFC 5869 otherwise.
        public_bundle = {key: self.bundle[key] for key in ('caCertPem', 'jwtPublicKey')}
        result = subprocess.run(['node', '-e', NODE_SNI_PROGRAM],
                                input=json.dumps(public_bundle), text=True,
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, 'Node HKDF oracle failed: ' + result.stderr)
        self.assertEqual(result.stdout, self.sni)


NGINX = shutil.which('nginx') or ('/usr/sbin/nginx' if Path('/usr/sbin/nginx').is_file() else None)

@unittest.skipUnless(NGINX, 'nginx absent: isolated real Nginx tests skipped')
class NginxSelfstealIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = module('VK_PAYLOAD_VK_WRITE_SELFSTEAL_CHECK')
        cls.temp = tempfile.TemporaryDirectory(prefix='vk-ngx-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.root.chmod(0o755)
        cls.socket_path = str(cls.root / 'selfsteal.sock')
        cls.bundle, _ = certificate_bundle()
        for key, name in [('nodeCertPem', 'cert.pem'), ('nodeKeyPem', 'key.pem'), ('caCertPem', 'ca.pem')]:
            (cls.root / name).write_text(cls.bundle[key])
            (cls.root / name).chmod(0o600)
        cls.site = cls.root / 'site'
        cls.site.mkdir(mode=0o755)
        (cls.site / 'index.html').write_text('<!doctype html><title>Isolated test</title><p>Selfsteal integration</p>')
        (cls.site / 'index.html').chmod(0o644)
        cls.fragment = template('/etc/nginx/conf.d/20-vkarmani-selfsteal.conf')
        version = subprocess.run([NGINX, '-v'], text=True, capture_output=True, check=True).stderr
        import re
        version_tuple = tuple(int(x) for x in re.search(r'nginx/(\d+)\.(\d+)\.(\d+)', version).groups())
        cls.modern_h2 = version_tuple >= (1, 25, 1)
        cls.reject_sni = version_tuple >= (1, 19, 4)
        cls.configure(cls.modern_h2)
        cls.proc = None
        cls.start()
        cls.addClassCleanup(cls.stop)

    @classmethod
    def configure(cls, modern):
        fragment = (cls.fragment.replace('$NGINX_HTTP2_LISTEN', '' if modern else 'http2')
                    .replace('$NGINX_HTTP2_DIRECTIVE', 'http2 on;' if modern else '')
                    .replace('$NGINX_REJECT_HANDSHAKE_DIRECTIVE', 'ssl_reject_handshake on;' if cls.reject_sni else '')
                    .replace('$DOMAIN', 'node.example.test').replace('\\$', '$')
                    .replace('/run/vkarmani-selfsteal/nginx.sock', cls.socket_path)
                    .replace('/etc/letsencrypt/live/node.example.test/fullchain.pem', str(cls.root / 'cert.pem'))
                    .replace('/etc/letsencrypt/live/node.example.test/privkey.pem', str(cls.root / 'key.pem'))
                    .replace('/var/www/vkarmani-node/site', str(cls.site)))
        # Single-process mode keeps this process in the test sandbox/current UID.
        # Nginx package builds use absolute /var/lib/nginx/* defaults. A private
        # prefix alone does not redirect them. Keep ALL scratch files local,
        # also when CI runs under root in a disposable container.
        temporary_paths = ''.join(
            f'{directive}_temp_path {cls.root}/temp/{directory}; '
            for directive, directory in (
                ('client_body', 'body'), ('proxy', 'proxy'), ('fastcgi', 'fastcgi'),
                ('uwsgi', 'uwsgi'), ('scgi', 'scgi')))
        (cls.root / 'temp').mkdir(exist_ok=True)
        config = (f'daemon off; master_process off; pid {cls.root}/nginx.pid; '
                  f'error_log {cls.root}/error.log; events {{ worker_connections 64; }} '
                  f'http {{ access_log off; {temporary_paths}{fragment} }}\n')
        (cls.root / 'nginx.conf').write_text(config)
        subprocess.run([NGINX, '-t', '-p', str(cls.root) + '/', '-c', str(cls.root / 'nginx.conf')],
                       check=True, text=True, capture_output=True, timeout=5)

    @classmethod
    def start(cls):
        cls.proc = subprocess.Popen([NGINX, '-p', str(cls.root) + '/', '-c', str(cls.root / 'nginx.conf')],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            if cls.proc.poll() is not None:
                raise AssertionError('isolated Nginx failed: ' + (cls.root / 'error.log').read_text()[-1500:])
            if Path(cls.socket_path).is_socket():
                return
            time.sleep(0.02)
        cls.stop()
        raise AssertionError('isolated Nginx socket did not become ready')

    @classmethod
    def stop(cls):
        if cls.proc is not None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
                cls.proc.wait(timeout=5)
            cls.proc = None

    def test_real_proxy_tls13_http1_and_http2(self):
        self.helper.check('node.example.test', path=self.socket_path,
                          site=self.site / 'index.html', cafile=self.root / 'ca.pem')

    def test_wrong_hostname_rejected(self):
        with self.assertRaises(ssl.SSLError):
            self.helper.check('wrong.example.test', path=self.socket_path,
                              site=self.site / 'index.html', cafile=self.root / 'ca.pem')

    def test_wrong_body_rejected(self):
        wrong = self.root / 'wrong.html'
        wrong.write_text('not the cover page')
        with self.assertRaisesRegex(ValueError, 'expected cover page'):
            self.helper.check('node.example.test', path=self.socket_path, site=wrong, cafile=self.root / 'ca.pem')

    def test_socket_recreated_after_nginx_restart(self):
        self.stop()
        Path(self.socket_path).unlink(missing_ok=True)
        self.start()
        self.helper.check('node.example.test', path=self.socket_path,
                          site=self.site / 'index.html', cafile=self.root / 'ca.pem')

    def test_legacy_http2_directive_syntax(self):
        try:
            self.configure(False)
        finally:
            self.configure(self.modern_h2)


if __name__ == '__main__':
    unittest.main()
