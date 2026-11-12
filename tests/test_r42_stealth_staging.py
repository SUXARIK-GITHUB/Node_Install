"""r42 regression: stable default site, bounded owned-endpoint probes, no secret disclosure."""
import contextlib
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from common import ROOT
sys.path.insert(0, str(ROOT / 'scripts'))
import site_default
import stealth_external_audit as ext
import stealth_report_compare as comparison


class DefaultThemeSelection(unittest.TestCase):
    def test_domain_selection_stable_diverse_and_reviewed(self):
        themes = {site_default.choose(f'node{i}.example.test') for i in range(100)}
        self.assertGreater(len(themes), 45)
        self.assertEqual(len(site_default.THEMES), 120)
        self.assertEqual(len(set(site_default.THEMES)), 120)
        self.assertEqual(site_default.choose('node1.example.test'),
                         site_default.choose('node1.example.test'))
        self.assertIn(site_default.choose('node1.example.test'), site_default.THEMES)
        self.assertEqual(site_default.main(['--domain', 'INVALID_DOMAIN']), 2)
        for theme in themes:
            self.assertTrue((ROOT / ('site-catalog' if int(theme.split('-',1)[0]) >= 13 else
                                      'cover-variants') / theme / 'index.html').is_file())

    def test_selection_is_only_fresh_ordinary_and_after_core_commit(self):
        source = (ROOT / 'install.sh').read_text()
        self.assertIn("VK_INITIAL_SITE_THEME='111-atlas-docs'", source)  # r41 validated fallback
        block = source.index('# Fresh Ordinary only: install an audited multi-page theme')
        self.assertIn('VK_CASCADE_ACTIVE -eq 0', source[block:block+1100])
        self.assertIn('! -e "$STATE/INSTALL_COMPLETE"', source[block:block+1100])
        self.assertIn('scripts/verify_release.py', source[block:block+1800])
        commit = source.index('"$LIB/finalize_install.py" finish')
        selection = source.index('site_default.py" --domain "$DOMAIN"')
        deploy = source.index('"$VK_SITE_SOURCE_ROOT/scripts/staging_web_deploy.py" site-deploy', selection)
        self.assertLess(commit, selection)
        self.assertLess(selection, deploy)
        self.assertIn('VK_SITE_PARTIAL_FAILURE=1', source[selection:deploy])
        self.assertIn('--site-theme)', source[:block])


class CurlHTTPS2(unittest.TestCase):
    def test_actual_h2_get_is_pinned_no_redirect_no_proxy_config_and_no_body(self):
        calls = []
        def run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            return SimpleNamespace(returncode=0, stdout=b'VK_H2:2:200', stderr=b'private')
        result = ext.http2_request('node.example.test', '8.8.8.8', run=run)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['reality_transport_proven'], 'NO')
        args, kw = calls[0]
        self.assertEqual(args[:2], ['curl', '-q'])
        self.assertIn('--http2', args)
        self.assertIn('--resolve', args)
        self.assertIn('node.example.test:443:8.8.8.8', args)
        self.assertIn('--max-redirs', args)
        self.assertIn('--noproxy', args)
        self.assertEqual(args[args.index('--noproxy')+1], '*')
        self.assertNotIn('--location', args)
        self.assertEqual(args[args.index('--output')+1], '/dev/null')
        self.assertEqual(kw['stdin'], subprocess.DEVNULL)
        self.assertEqual(kw['env']['HOME'], '/nonexistent')
        self.assertNotIn('8.8.8.8', json.dumps(result))
        self.assertNotIn('node.example.test', json.dumps(result))

    def test_h2_was_actually_requested_not_only_alpn(self):
        for output, status in ((b'VK_H2:1.1:200', 'REVIEW'),
                               (b'VK_H2:2:404', 'REVIEW'),
                               (b'garbage', 'UNVERIFIED')):
            with self.subTest(output=output):
                run = lambda *a, **kw: SimpleNamespace(returncode=0, stdout=output)
                self.assertEqual(ext.http2_request('node.example.test', '8.8.8.8', run=run)['status'], status)
        failed = lambda *a, **kw: SimpleNamespace(returncode=60, stdout=b'', stderr=b'private')
        self.assertEqual(ext.http2_request('node.example.test', '8.8.8.8', run=failed)['status'], 'FAIL')
        unavailable = lambda *a, **kw: (_ for _ in ()).throw(FileNotFoundError())
        self.assertEqual(ext.http2_request('node.example.test', '8.8.8.8', run=unavailable)['status'], 'UNVERIFIED')
        with self.assertRaises(ext.AuditError):
            ext.http2_request('localhost', '8.8.8.8', run=failed)

    def test_socks_is_loopback_and_never_claims_reality(self):
        seen = []
        def run(args, **kwargs):
            seen.append(args)
            return SimpleNamespace(returncode=0, stdout=b'VK_H2:2:200', stderr=b'')
        result = ext.http2_request('node.example.test', '8.8.8.8', socks_port=10808, run=run)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['reality_transport_proven'], 'NO')
        self.assertIn('socks5://127.0.0.1:10808', seen[0])
        self.assertEqual(seen[0][seen[0].index('--noproxy')+1], '')
        with self.assertRaises(ext.AuditError):
            ext.http2_request('node.example.test', '8.8.8.8', socks_port=0, run=run)
        with self.assertRaises(ext.AuditError):
            ext.http2_request('node.example.test', '8.8.8.8', socks_port=65536, run=run)


class OneExplicitApiPort(unittest.TestCase):
    def test_only_one_requested_port_and_all_outcomes_qualified(self):
        calls = []
        class Connection:
            def __enter__(self): return self
            def __exit__(self, *args): pass
        def connect(target, timeout):
            calls.append((target, timeout))
            return Connection()
        opened = ext.node_api_external('8.8.8.8', 2222, connect=connect)
        self.assertEqual(opened['status'], 'REVIEW')
        self.assertEqual(calls, [(('8.8.8.8', 2222), 2)])
        def refused(*a, **kw): raise ConnectionRefusedError()
        self.assertEqual(ext.node_api_external('8.8.8.8', 2222, connect=refused)['status'], 'PASS')
        def timed_out(*a, **kw): raise socket.timeout()
        self.assertEqual(ext.node_api_external('8.8.8.8', 2222, connect=timed_out)['status'], 'UNVERIFIED')
        for invalid in (0, 80, 443, 65536, True, '2222'):
            with self.assertRaises(ext.AuditError):
                ext.node_api_external('8.8.8.8', invalid, connect=connect)

    def test_optional_checks_preserve_legacy_audit_and_comparison(self):
        def conn(ip, domain, **kwargs):
            if kwargs['sni'] != domain:
                import ssl
                raise ssl.SSLError('[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] handshake failure')
            return {'tls': 'TLSv1.2' if str(kwargs.get('version')).endswith('TLSv1_2') else 'TLSv1.3',
                    'alpn': 'h2' if kwargs.get('offer_h2') else 'http/1.1',
                    'http_code': 421 if kwargs.get('host') else 404 if kwargs.get('path','/') != '/' else 200,
                    'security_headers': True}
        # Test only the opt-ins; legacy observations may require real TLS version
        # fixtures and are separately covered by r40/r41 tests.
        opts = {'connect': conn, 'resolve': lambda *a: {'status': 'PASS'},
                'plain': lambda *a: {'http_code': 301, 'redirect_to_expected_https': True}}
        original = ext.audit('node.example.test', '8.8.8.8', **opts)
        extras = ext.audit('node.example.test', '8.8.8.8', **opts,
                           actual_http2=True, client_socks_port=10808, node_api_port=2222,
                           http2=lambda *a, **kw: {'status': 'PASS', 'http_version': '2', 'http_code': 200},
                           api_check=lambda *a: {'status': 'REVIEW', 'reason':'NODE_API_TCP_ACCEPTED_FROM_THIS_SOURCE'})
        self.assertNotIn('http2_request', original['checks'])
        self.assertEqual(extras['checks']['http2_request']['status'], 'PASS')
        self.assertEqual(extras['checks']['node_api_external']['status'], 'REVIEW')
        self.assertEqual(extras['checks']['client_socks_https']['status'], 'PASS')
        report = comparison.compare(original, extras)
        self.assertEqual(set(report['added_checks']),
                         {'client_socks_https', 'http2_request', 'node_api_external'})
        self.assertEqual(extras['client_or_dpi_stealth_proven'], 'NO')

    def test_cli_no_probe_before_ownership_confirmation(self):
        with patch.object(ext, 'audit', side_effect=AssertionError('NETWORK_REQUEST')):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    ext.main(['--domain','node.example.test','--ip','8.8.8.8',
                              '--http2-actual','--node-api-port','2222'])
            self.assertEqual(caught.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
