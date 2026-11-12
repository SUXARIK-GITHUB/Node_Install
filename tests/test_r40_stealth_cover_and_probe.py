"""R40: offline regression checks for HTTPS cover, privacy, and owned endpoint audit."""
import contextlib
import io
import json
import socket
import shutil
import tempfile
import threading
from pathlib import Path
import ssl
import subprocess
import sys
import unittest
from unittest.mock import patch

from common import ROOT
sys.path.insert(0, str(ROOT / 'scripts'))
import cover_variants
import site_catalog
import cover_rich
import site_audit
import stealth_external_audit as probe
sys.path.insert(0, str(ROOT / 'integrations'))
import selfsteal_runtime_probe as local_cover


class CoverContent(unittest.TestCase):
    def test_all_120_sites_and_600_pages_have_no_public_placeholder_and_no_remote_assets(self):
        seen = set()
        for theme in cover_variants.NAMES + site_catalog.NAMES:
            with self.subTest(theme=theme):
                bundle = cover_rich.render_rich(theme, 'cover.example.test')
                self.assertEqual(site_audit.audit_bundle(bundle, 'cover.example.test', rich=True)['status'], 'PASS')
                for page, body in bundle.items():
                    if page.endswith('.html'):
                        content = body.decode('utf-8').lower()
                        for marker in ('демонстрационных и справочных целях',
                                       'ознакомительный характер',
                                       'small editorial demonstration',
                                       'fictional independent creative journal'):
                            self.assertNotIn(marker, content)
                self.assertNotIn(bundle['index.html'], seen)
                seen.add(bundle['index.html'])
        self.assertEqual(len(seen), 120)

    def test_public_placeholders_are_blocked_by_site_audit(self):
        data = cover_rich.render_rich('01-atelier', 'cover.example.test')
        broken = dict(data)
        broken['about.html'] += '<p>Содержимое носит ознакомительный характер.</p>'.encode()
        with self.assertRaisesRegex(ValueError, 'PUBLIC_PLACEHOLDER_COPY'):
            site_audit.audit_bundle(broken, 'cover.example.test', rich=True)


class LocalCoverContract(unittest.TestCase):
    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL fixture generation unavailable')
    def test_extended_checks_verified_on_owned_unix_tls_socket(self):
        with tempfile.TemporaryDirectory() as td:
            work = Path(td)
            cert, key, sock = (work / 'cert.pem', work / 'key.pem', work / 'cover.sock')
            p = subprocess.run(['openssl', 'req', '-x509', '-nodes', '-sha256',
                                '-newkey', 'rsa:2048', '-days', '2',
                                '-subj', '/CN=node.example.test',
                                '-addext', 'subjectAltName=DNS:node.example.test',
                                '-keyout', str(key), '-out', str(cert)],
                               text=True, capture_output=True, timeout=12)
            self.assertEqual(p.returncode, 0, p.stderr)
            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ctx.load_cert_chain(str(cert), str(key))
            errors = []
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(sock))
            listener.listen(4)
            listener.settimeout(5)
            def serve():
                try:
                    for _ in range(4):
                        raw, _ = listener.accept()
                        with raw:
                            raw.settimeout(5)
                            preface = b''
                            while not preface.endswith(b'\r\n') and len(preface) < 110:
                                preface += raw.recv(1)
                            assert preface.startswith(b'PROXY TCP4 ') and preface.endswith(b'\r\n')
                            with server_ctx.wrap_socket(raw, server_side=True) as tls:
                                request = b''
                                while b'\r\n\r\n' not in request and len(request) < 2048:
                                    request += tls.recv(256)
                                path = request.split(b' ', 2)[1]
                                host = next((line[5:].strip() for line in request.split(b'\r\n')
                                             if line.lower().startswith(b'host:')), b'')
                                status = 421 if host != b'node.example.test' else 404 if path != b'/' else 200
                                tls.sendall(f'HTTP/1.1 {status} OK\r\nContent-Length: 0\r\n\r\n'.encode())
                except Exception as exc:
                    errors.append(type(exc).__name__)
                finally:
                    listener.close()
            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            result = local_cover.probe('node.example.test', sock, proxy_v1=True,
                                       cafile=cert, extended=True)
            worker.join(timeout=6)
            self.assertFalse(errors, errors)
            self.assertFalse(worker.is_alive())
            self.assertEqual(result['status'], 'PASS', result)
            self.assertEqual(result['extended_checks'],
                             {'head': 'PASS', 'missing_page': 'PASS', 'host_mismatch': 'PASS'})
            self.assertNotIn('node.example.test', json.dumps(result))



class PublicEndpointProbe(unittest.TestCase):
    def test_target_rejects_internal_and_unvalidated_domains(self):
        for bad in ('127.0.0.1', '10.0.0.5', '172.16.0.1', '169.254.169.254',
                    '192.168.0.5', '0.0.0.0', '::1', '2001:db8::1', '198.51.100.7'):
            with self.subTest(address=bad), self.assertRaises(probe.AuditError):
                probe.validated_target('my.example.com', bad)
        for bad in ('localhost', 'a.b;evil', 'https://example.com', 'EXAMPLE.COM',
                    'foo.example.com\nHTTP/1.1 200 OK'):
            with self.subTest(domain=bad), self.assertRaises(probe.AuditError):
                probe.validated_target(bad, '8.8.8.8')
        self.assertEqual(probe.validated_target('my.example.com', '8.8.8.8'),
                         ('my.example.com', '8.8.8.8'))

    def test_cli_requires_explicit_ownership_and_does_not_connect(self):
        with patch.object(probe, 'audit', side_effect=AssertionError('NETWORK_CALL')):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as fail:
                    probe.main(['--domain', 'node.example.test', '--ip', '8.8.8.8'])
            self.assertEqual(fail.exception.code, 2)

    def test_fully_healthy_visible_checks_do_not_claim_post_handshake_proof(self):
        calls = []
        def connect(ip, domain, **opts):
            calls.append(opts)
            if not opts['sni'] or opts['sni'] != domain:
                raise ssl.SSLError('[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] handshake failure')
            code = 421 if opts.get('host') == 'unrelated.invalid' else 404 if opts.get('path', '/') != '/' else 200
            return {'tls': ('TLSv1.2' if opts.get('version') == ssl.TLSVersion.TLSv1_2 else 'TLSv1.3'),
                    'alpn': 'h2' if opts.get('offer_h2') else 'http/1.1',
                    'http_code': code, 'security_headers': True}
        def plain(ip, domain):
            return {'http_code': 301, 'redirect_to_expected_https': True}
        def dns(domain, ip):
            return {'status':'PASS', 'ipv4_includes_target': True,
                    'ipv6_records_present': False, 'reason': 'NONE'}
        result = probe.audit('node.example.test', '8.8.8.8', connect=connect,
                             plain=plain, resolve=dns)
        self.assertEqual(result['live_checks_status'], 'PASS', result)
        self.assertEqual(result['status'], 'UNVERIFIED')
        self.assertEqual(result['checks']['post_handshake_records']['status'], 'UNVERIFIED')
        self.assertEqual(len(calls), 8)
        self.assertNotIn('8.8.8.8', json.dumps(result))
        self.assertNotIn('node.example.test', json.dumps(result))
        self.assertEqual(result['client_or_dpi_stealth_proven'], 'NO')

    def test_unexpected_unknown_sni_is_not_a_pass(self):
        result = probe._result_check(lambda: {'tls': 'TLSv1.3', 'alpn': None}, reject=True)
        self.assertEqual(result['status'], 'REVIEW')
        self.assertEqual(result['reason'], 'UNKNOWN_SNI_ACCEPTED')
        result = probe._result_check(lambda: (_ for _ in ()).throw(socket_timeout()), reject=True)
        self.assertEqual(result['status'], 'UNVERIFIED')

    def test_certificate_failure_is_fail_not_success(self):
        def fail():
            raise ssl.SSLCertVerificationError('untrusted certificate')
        result = probe._result_check(fail)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['reason'], 'CERT_OR_SNI_MISMATCH')


def socket_timeout():
    import socket
    return socket.timeout('test timeout')


if __name__ == '__main__':
    unittest.main()
