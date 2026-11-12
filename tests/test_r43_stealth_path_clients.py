"""r43: bounded OWN endpoint probes, offline censorship-evidence review and client safety."""
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from common import ROOT
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'integrations'))
import stealth_external_audit as ext
import stealth_report_compare as compare
import network_path_review as path_review
import client_route_audit as routes
import reality_client_matrix as matrix


class OneTCP443(unittest.TestCase):
    def test_only_one_dial_no_payload(self):
        calls = []
        class Conn:
            def __enter__(self): return self
            def __exit__(self, *args): pass
        def connect(address, timeout):
            calls.append((address, timeout))
            return Conn()
        self.assertEqual(ext.tcp443_external('8.8.8.8', connect=connect)['status'], 'PASS')
        self.assertEqual(calls, [(('8.8.8.8', 443), 3)])
        self.assertNotIn('8.8.8.8', json.dumps(ext.tcp443_external('8.8.8.8', connect=connect)))

    def test_refused_timeout_and_invalid(self):
        def refused(*a, **kw): raise ConnectionRefusedError()
        def timeout(*a, **kw): raise socket.timeout()
        self.assertEqual(ext.tcp443_external('8.8.4.4', connect=refused)['status'], 'REVIEW')
        self.assertEqual(ext.tcp443_external('8.8.4.4', connect=timeout)['status'], 'UNVERIFIED')
        for ip in ('127.0.0.1', '192.168.1.5', '0.0.0.0', '::1', 'bad'):
            with self.subTest(ip=ip), self.assertRaises(ext.AuditError):
                ext.tcp443_external(ip, connect=refused)


class LargeOwnedAsset(unittest.TestCase):
    def test_only_owned_bounded_http2_with_no_body_storage(self):
        calls = []
        def run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            return SimpleNamespace(returncode=0, stdout=b'VK_LARGE:2:200:65536', stderr=b'private')
        report = ext.large_http2_asset('node.example.test', '8.8.4.4', '/assets/canary.bin', run=run)
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['downloaded_bytes'], 65536)
        self.assertEqual(report['dpi_or_path_filtering_proven'], 'NO')
        cmd, kw = calls[0]
        self.assertEqual(cmd[:2], ['curl', '-q'])
        self.assertIn('--http2', cmd)
        self.assertEqual(cmd[cmd.index('--max-filesize')+1], '262144')
        self.assertEqual(cmd[cmd.index('--output')+1], os.devnull)
        self.assertEqual(cmd[cmd.index('--noproxy')+1], '*')
        self.assertNotIn('--location', cmd)
        self.assertEqual(kw['env']['HOME'], '/nonexistent')
        self.assertEqual(kw['stdin'], subprocess.DEVNULL)
        self.assertNotIn('node.example.test', json.dumps(report))
        self.assertNotIn('8.8.4.4', json.dumps(report))

    def test_small_incorrect_protocol_and_size_are_not_pass(self):
        for stdout in (b'VK_LARGE:2:200:16000', b'VK_LARGE:1.1:200:65536',
                       b'VK_LARGE:2:404:65536'):
            with self.subTest(stdout=stdout):
                result = ext.large_http2_asset('node.example.test', '8.8.4.4', '/canary.bin',
                                               run=lambda *args, **kw: SimpleNamespace(returncode=0, stdout=stdout))
                self.assertEqual(result['status'], 'REVIEW')
        for stdout in (b'garbage', b'VK_LARGE:2:200:262145', b'VK_LARGE:2:200:-1'):
            self.assertEqual(ext.large_http2_asset('node.example.test', '8.8.4.4', '/canary.bin',
                 run=lambda *args, **kw: SimpleNamespace(returncode=0, stdout=stdout))['status'], 'UNVERIFIED')

    def test_partial_body_bytes_survive_curl_failure_without_body_or_stderr(self):
        result = ext.large_http2_asset('node.example.test', '8.8.4.4', '/canary.bin',
            run=lambda *a, **kw: SimpleNamespace(returncode=56,
                stdout=b'VK_LARGE:2:200:16384', stderr=b'SECRET_REMOTE_DATA'))
        self.assertEqual(result['status'], 'REVIEW')
        self.assertEqual(result['downloaded_bytes'], 16384)
        self.assertEqual(result['reason'], 'PARTIAL_OR_FAILED_HTTP_TRANSFER')
        self.assertNotIn('SECRET_REMOTE_DATA', json.dumps(result))

    def test_fail_closed_cert_unavailable_and_redirect(self):
        self.assertEqual(ext.large_http2_asset('node.example.test', '8.8.4.4', '/canary.bin',
            run=lambda *a, **kw: SimpleNamespace(returncode=60, stdout=b'', stderr=b'SECRET'))['status'], 'FAIL')
        def gone(*a, **kw): raise FileNotFoundError()
        self.assertEqual(ext.large_http2_asset('node.example.test', '8.8.4.4', '/canary.bin',run=gone)['status'], 'UNVERIFIED')
        def timeout(*a, **kw): raise subprocess.TimeoutExpired('curl', 4)
        self.assertEqual(ext.large_http2_asset('node.example.test', '8.8.4.4', '/canary.bin',run=timeout)['status'], 'UNVERIFIED')

    def test_no_unsafe_path_ever_reaches_curl(self):
        def fake(*a, **kw): raise AssertionError('should not run')
        for path in ('/', '/.env', '/../../etc/passwd', '/api?secret=x',
                     '/node%2f..%2fetc', 'https://bad.com/file.bin', '/a.bin#x',
                     '/a\r\nX: 1.bin', '/a/a/a/a/a/a.bin', '/x.json'):
            with self.subTest(path=path), self.assertRaises(ext.AuditError):
                ext.large_http2_asset('node.example.test', '8.8.4.4', path,run=fake)

    def test_reject_bad_path_before_any_network(self):
        with self.assertRaises(ext.AuditError):
            ext.audit('node.example.test', '8.8.4.4', large_static_path='/../oops.bin',
                      resolve=lambda *a: (_ for _ in ()).throw(AssertionError('NETWORK')))

    def test_optional_checks_and_compare_backward_compatibility(self):
        def conn(address, domain, **kw):
            if kw.get('sni') != domain:
                import ssl
                raise ssl.SSLError('TLSV1_ALERT_UNRECOGNIZED_NAME')
            return {'tls':'TLSv1.3','alpn':'h2' if kw.get('offer_h2') else 'http/1.1',
                    'http_code':421 if kw.get('host') else 404 if kw.get('path','/') != '/' else 200,
                    'security_headers':True}
        kw={'connect':conn,'resolve':lambda *a: {'status':'PASS'},
            'plain':lambda *a:{'http_code':301,'redirect_to_expected_https':True}}
        before=ext.audit('node.example.test','8.8.4.4',**kw)
        after=ext.audit('node.example.test','8.8.4.4',**kw,tcp443=True,
                tcp_check=lambda *a:{'status':'PASS'},large_static_path='/canary.bin',
                large_check=lambda *a:{'status':'PASS','downloaded_bytes':65536})
        self.assertNotIn('tcp443',before['checks'])
        self.assertEqual(after['checks']['tcp443']['status'],'PASS')
        self.assertEqual(after['checks']['large_http2_asset']['status'],'PASS')
        self.assertEqual(set(compare.compare(before,after)['added_checks']),{'tcp443','large_http2_asset'})

    def test_ownership_confirmation_is_required(self):
        with patch.object(ext,'audit',side_effect=AssertionError('NETWORK')):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    ext.main(['--domain','node.example.test','--ip','8.8.4.4', '--tcp443'])
            self.assertEqual(caught.exception.code,2)


class ComparativeEvidence(unittest.TestCase):
    def report(self, **fields):
        checks={'dns':{'status':'PASS'},'tcp443':{'status':'PASS'},
                'tls13':{'status':'PASS'},'http2_request':{'status':'PASS'},
                'large_http2_asset':{'status':'PASS','downloaded_bytes':65536}}
        for k,v in fields.items():
            if isinstance(v,dict):checks[k]=v
            else:checks[k]={'status':v}
        return {'schema':1,'scope':'EXPLICIT_OWNED_ENDPOINT_ONLY',
                'client_or_dpi_stealth_proven':'NO','checks':checks}

    def test_same_network_reports_all_pass_no_claim(self):
        result=path_review.review(self.report(),self.report())
        self.assertEqual(result['status'],'NO_DIFFERENCE_OBSERVED')
        self.assertEqual(result['source_attribution'],'NOT_POSSIBLE')
        self.assertEqual(result['interpretation'],'NETWORK_PATH_DIFFERENCE_NOT_PROOF_OF_CENSORSHIP')

    def test_dns_diff(self):
        result=path_review.review(self.report(),self.report(dns='REVIEW'))
        self.assertEqual(result['status'],'REVIEW')
        self.assertIn('DNS_RESOLUTION_DIFFERS',[x['code'] for x in result['differential_signals']])

    def test_tcp_diff(self):
        result=path_review.review(self.report(),self.report(tcp443='UNVERIFIED'))
        self.assertIn('TCP443_REACHABILITY_DIFFERS',[x['code'] for x in result['differential_signals']])
        self.assertIn('CANNOT_ISOLATE_TLS_FROM_TCP_CONNECTIVITY',result['observations'])

    def test_tls_diff_with_tcp_pass(self):
        result=path_review.review(self.report(),self.report(tls13='FAIL'))
        self.assertIn('TLS13_HANDSHAKE_OR_HTTPS_DIFFERS',[x['code'] for x in result['differential_signals']])
        self.assertNotIn('CANNOT_ISOLATE_TLS_FROM_TCP_CONNECTIVITY',result['observations'])

    def test_h2_and_size_diff(self):
        affected=self.report(http2_request='REVIEW',large_http2_asset={'status':'PASS','downloaded_bytes':32768})
        result=path_review.review(self.report(),affected)
        codes=[x['code'] for x in result['differential_signals']]
        self.assertIn('HTTP2_APPLICATION_RESPONSE_DIFFERS',codes)
        self.assertIn('STATIC_ASSET_TRANSFER_SIZE_DIFFERS',codes)
        self.assertNotIn('65536',json.dumps(result))

    def test_unknown_or_missing_and_failed_control_do_not_claim_censor(self):
        report=self.report()
        del report['checks']['tcp443']
        affected=self.report(tcp443='FAIL')
        outcome=path_review.review(report,affected)
        self.assertEqual(outcome['status'],'INSUFFICIENT')
        self.assertIn('tcp443',outcome['missing_or_incomparable_checks'])
        self.assertEqual(path_review.review(self.report(tls13='FAIL'),self.report(tls13='FAIL'))['status'],'INSUFFICIENT')

    def test_invalid_counts_keys_and_scopes(self):
        for malformed in (self.report(large_http2_asset={'status':'PASS','downloaded_bytes':999999}),
                          self.report(tcp443={'status':'ABSENT'}),
                          self.report(evil={'status':'PASS'})):
            with self.subTest(malformed=malformed),self.assertRaises(path_review.ReviewError):
                path_review.review(malformed,self.report())
        bad=self.report();bad['scope']='ANY_TARGET'
        with self.assertRaises(path_review.ReviewError):path_review.review(bad,self.report())

    def test_cli_requires_operator_attestation(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                path_review.main(['--control','a.json','--affected','b.json'])
            self.assertEqual(caught.exception.code,2)


class ClientRouting(unittest.TestCase):
    def config(self):
        return {'outbounds':[{'tag':'proxy','protocol':'vless'},
                             {'tag':'direct','protocol':'freedom'}],
                'routing':{'rules':[]},
                'inbounds':[{'protocol':'socks','listen':'127.0.0.1'}],
                'dns':{}}

    def test_first_vless_no_explicit_direct_remains_only_static(self):
        out=routes.audit(self.config())
        self.assertEqual(out['status'],'STATIC_REVIEW')
        self.assertEqual(out['dns_ipv6_udp_proven_safe'],'NO')
        self.assertEqual(out['live_egress_privacy'],'UNVERIFIED')

    def test_default_direct_flagged(self):
        cfg=self.config();cfg['outbounds']=list(reversed(cfg['outbounds']))
        self.assertIn('DEFAULT_OUTBOUND_IS_DIRECT',routes.audit(cfg)['observations'])

    def test_explicit_direct_rule_flagged(self):
        cfg=self.config();cfg['routing']['rules']=[{'type':'field','domain':['secret.example'],
                                                    'outboundTag':'direct'}]
        out=routes.audit(cfg)
        self.assertEqual(out['status'],'REVIEW')
        self.assertEqual(out['direct_rules_count'],1)
        self.assertNotIn('secret.example',json.dumps(out))

    def test_proxy_listener_external_and_balancer(self):
        cfg=self.config();cfg['inbounds'][0]['listen']='0.0.0.0'
        cfg['routing']['rules']=[{'type':'field','balancerTag':'balance0'}]
        out=routes.audit(cfg)
        self.assertIn('LOCAL_PROXY_LISTENER_NOT_RESTRICTED_TO_LOOPBACK',out['observations'])
        self.assertIn('BALANCER_RULES_REQUIRE_RUNTIME_VERIFICATION',out['observations'])

    def test_unknown_routing_outbound_tag_requires_review(self):
        cfg=self.config();cfg['routing']['rules']=[{'outboundTag':'missing-secret-tag'}]
        report=routes.audit(cfg)
        self.assertEqual(report['status'],'REVIEW')
        self.assertIn('ROUTING_TARGET_NOT_DEFINED_IN_OUTBOUNDS',report['observations'])
        self.assertNotIn('missing-secret-tag',json.dumps(report))

    def test_reject_nonfinite_or_duplicate_secret_file(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'client.json'
            p.write_text('{"outbounds": [], "outbounds": [], "private": "secret"}')
            p.chmod(0o600)
            with self.assertRaises(routes.Invalid):routes.read_config(p)
            p.write_text('{"num": NaN}')
            with self.assertRaises(routes.Invalid):routes.read_config(p)
            p.chmod(0o644)
            with self.assertRaises(routes.Invalid):routes.read_config(p)
            p.chmod(0o600)
            sym=Path(d)/'link';sym.symlink_to(p)
            with self.assertRaises(OSError):routes.read_config(sym)

    def test_bad_rules_and_outbounds_fail_closed(self):
        cfg=self.config();cfg['routing']['rules']=['literal-secret']
        with self.assertRaises(routes.Invalid):routes.audit(cfg)
        cfg=self.config();cfg['outbounds'].append({'tag':'proxy','protocol':'freedom'})
        with self.assertRaises(routes.Invalid):routes.audit(cfg)

    def test_private_read_cli_no_contents_logged(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'client.json'
            cfg=self.config();cfg['routing']['rules']=[{'outboundTag':'direct','domain':['secret.example']}]
            p.write_text(json.dumps(cfg));p.chmod(0o600)
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                code=routes.main(['--client-config',str(p),'--strict'])
            self.assertEqual(code,2)
            self.assertNotIn('secret.example',stdout.getvalue())
            self.assertNotIn(str(p),stdout.getvalue())


class CompatibilityMatrix(unittest.TestCase):
    def trial(self,**overrides):
        value={'app':'xray','client_core':'26.10.31','fingerprint':'chrome',
               'transport':'xhttp','key_share':'PRESENT','attempts':5,
               'successes':5,'egress':'EXPECTED_VPN_IP'}
        value.update(overrides)
        return value

    def data(self,**overrides):
        value={'schema':1,'server_core':'26.10.31','trials':[self.trial()]}
        value.update(overrides)
        return value

    def test_full_attested_case_is_observed_only(self):
        out=matrix.review(self.data())
        self.assertEqual(out['status'],'OBSERVED_COMPATIBLE_IN_TEST_ONLY')
        self.assertEqual(out['trials'][0]['status'],'OBSERVED_COMPATIBLE_IN_THIS_TEST_ONLY')
        self.assertIn('NO_DPI_DETECTION_OR_PRIVACY_GUARANTEE',out['limitations'])

    def test_new_core_requires_hybrid_evidence(self):
        out=matrix.review(self.data(trials=[self.trial(fingerprint='edge',key_share='ABSENT')]))
        self.assertIn('SERVER_REQUIRES_VERIFIED_HYBRID_KEY_SHARE_COMPATIBILITY',out['trials'][0]['observations'])
        self.assertEqual(out['status'],'REVIEW')

    def test_old_core_does_not_infer_new_core_requirement(self):
        out=matrix.review(self.data(server_core='26.7.28',
                            trials=[self.trial(fingerprint='edge',key_share='ABSENT')]))
        self.assertEqual(out['status'],'OBSERVED_COMPATIBLE_IN_TEST_ONLY')

    def test_randomized_unreliable_and_direct_egress(self):
        out=matrix.review(self.data(trials=[self.trial(fingerprint='randomized',
                           egress='DIRECT_IP_OBSERVED')]))
        self.assertEqual(out['status'],'REVIEW')
        self.assertIn('DIRECT_EGRESS_REPORTED_BLOCK_RELEASE',out['trials'][0]['observations'])
        self.assertIn('RANDOMIZED_CLIENTHELLO_MUST_BE_RETESTED_ACROSS_RESTARTS',out['trials'][0]['observations'])

    def test_errors_in_small_sample_or_versions(self):
        out=matrix.review(self.data(trials=[self.trial(attempts=3,successes=2,client_core=None)]))
        self.assertEqual(out['status'],'REVIEW')
        self.assertIn('CONNECTION_FAILURES_OBSERVED',out['trials'][0]['observations'])
        self.assertIn('TOO_FEW_ATTEMPTS_FOR_EVEN_LOCAL_RELIABILITY',out['trials'][0]['observations'])

    def test_invalid_unsafe_metadata_denied(self):
        for invalid in (self.data(server_core='latest'),
                        self.data(trials=[self.trial(attempts=True)]),
                        self.data(trials=[self.trial(successes=6)]),
                        self.data(trials=[self.trial(fingerprint='not_real')]),
                        self.data(trials=[self.trial()]*33),
                        self.data(secret='token')):
            with self.subTest(value=invalid),self.assertRaises(matrix.Invalid):matrix.review(invalid)

    def test_private_file_permissions_and_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'data.json';p.write_text(json.dumps(self.data()));p.chmod(0o600)
            self.assertEqual(matrix.review(matrix._read(p))['status'],'OBSERVED_COMPATIBLE_IN_TEST_ONLY')
            p.chmod(0o644)
            with self.assertRaises(matrix.Invalid):matrix._read(p)
            p.chmod(0o600)
            link=Path(d)/'link';link.symlink_to(p)
            with self.assertRaises(OSError):matrix._read(link)
            p.write_text('{"schema":1,"schema":1}')
            with self.assertRaises(matrix.Invalid):matrix._read(p)

    def test_no_secrets_or_domain_in_output(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'metadata.json';p.write_text(json.dumps(self.data()));p.chmod(0o600)
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(matrix.main(['--evidence',str(p),'--strict']),0)
            self.assertNotIn(str(p),out.getvalue())
            self.assertNotIn('secret.example',out.getvalue().lower())


if __name__=='__main__':
    unittest.main()
