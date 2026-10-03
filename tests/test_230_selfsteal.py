"""Readiness is not site integrity. Real Nginx reload with temporary certificates."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
from common import SCRIPT, certificate_bundle, module, payload
import test_220_selfsteal as base_fixture
import test_tls_integration as fixture


@unittest.skipUnless(fixture.NGINX, 'real Nginx unavailable: target/reload tests not verified')
class Selfsteal230IntegrationTests(unittest.TestCase):
    setUpClass=classmethod(base_fixture.Selfsteal220Tests.setUpClass.__func__)
    @classmethod
    def configure(cls, modern):
        import pwd
        fixture.NginxSelfstealIntegrationTests.configure.__func__(cls, modern)
        path=cls.root/'nginx.conf'
        # Production-like master/worker reload, still restricted to our private prefix.
        user=pwd.getpwuid(os.getuid()).pw_name
        text=path.read_text().replace('master_process off;',
            'master_process on; worker_processes 1; user '+user+';')
        path.write_text(text)
        subprocess.run([fixture.NGINX,'-t','-p',str(cls.root)+'/', '-c',str(path)],
                       capture_output=True,check=True,timeout=5)

    start=classmethod(base_fixture.Selfsteal220Tests.start.__func__)
    stop=classmethod(base_fixture.Selfsteal220Tests.stop.__func__)
    request=base_fixture.Selfsteal220Tests.request
    probe=base_fixture.Selfsteal220Tests.probe

    def tls(self, bundle=None):
        fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert((bundle or self.bundle)['nodeCertPem'])).digest()
        return self.helper.target_tls('node.example.test', self.socket_path,
            self.root/'ca.pem', timeout=3, expected_leaf=fp)

    def test_target_tls_without_reading_html_or_css(self):
        with patch.object(self.helper, 'check', side_effect=AssertionError('must not read web data')):
            self.tls()

    def test_missing_index_not_a_tls_failure_but_site_failure(self):
        p=self.site/'index.html';original=p.read_bytes()
        try:
            p.unlink();self.tls()
            with self.assertRaises((FileNotFoundError,ValueError)):self.probe()
        finally:p.write_bytes(original);p.chmod(0o644)

    def test_corrupt_css_not_a_tls_failure_but_fails_full_acceptance(self):
        name=next(n for n in self.assets if n.endswith('.css'));p=self.site/name
        try:
            p.write_bytes(b'CORRUPTED_TEST_RESOURCE')
            self.tls()
            self.assertEqual(self.request()[0],200)
            with self.assertRaisesRegex(ValueError,'HASH_NAME_MISMATCH'):self.probe()
        finally:p.write_bytes(self.assets[name])
        self.probe()

    def test_wrong_fingerprint_still_rejected_by_target_mode(self):
        with self.assertRaisesRegex(ValueError,'CERTIFICATE_NOT_RELOADED'):
            self.helper.target_tls('node.example.test',self.socket_path,self.root/'ca.pem',expected_leaf=b'x'*32)

    def test_absent_target_is_not_a_pass(self):
        with self.assertRaises(FileNotFoundError):
            self.helper.target_tls('node.example.test',str(self.root/'missing.sock'),self.root/'ca.pem',timeout=0.2)

    def test_invalid_budget_or_domain_refused_before_connect(self):
        for timeout in (0,-1,21):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                self.helper.target_tls('node.example.test',timeout=timeout)
        with self.assertRaises(ValueError):self.helper.target_tls('bad\nname')

    def test_real_certificate_rotation_with_same_nginx_process(self):
        new,_=certificate_bundle()
        saved={name:(self.root/name).read_bytes() for name in ('cert.pem','key.pem','ca.pem')}
        pid=self.proc.pid
        try:
            # Certificates are ephemeral. Both temporary CAs are trusted by this probe only.
            for key,name in [('nodeCertPem','cert.pem'),('nodeKeyPem','key.pem')]:
                p=self.root/(name+'.new');p.write_text(new[key]);p.chmod(0o600);p.replace(self.root/name)
            (self.root/'ca.pem').write_text(self.bundle['caCertPem']+new['caCertPem'])
            # New file on disk does not imply it is already served.
            with self.assertRaisesRegex(ValueError,'CERTIFICATE_NOT_RELOADED'):self.tls(new)
            h=module('VK_CERT_DEPLOY_PY');saved_status=self.root/'activation-state';saved_status.mkdir(mode=0o700,exist_ok=True)
            h.STATUS=saved_status/'status.json'
            commands=[]
            def run(args, **kwargs):
                commands.append(args)
                if args==['/usr/sbin/nginx','-t']:
                    return subprocess.run([fixture.NGINX,'-t','-p',str(self.root)+'/', '-c',str(self.root/'nginx.conf')],capture_output=True,timeout=5)
                if args==['/usr/bin/systemctl','reload','nginx']:
                    return subprocess.run([fixture.NGINX,'-s','reload','-p',str(self.root)+'/', '-c',str(self.root/'nginx.conf')],capture_output=True,timeout=5)
                if args==['/usr/local/sbin/vkarmani-selfsteal-check','--target-only']:
                    try:self.tls(new);code=0
                    except (ssl.SSLError,ValueError,OSError):code=1
                    return subprocess.CompletedProcess(args,code,b'',b'')
                raise AssertionError('unexpected operation')
            fingerprint=hashlib.sha256(ssl.PEM_cert_to_DER_cert(new['nodeCertPem'])).hexdigest()
            with patch.object(h,'leaf_fingerprint',return_value=fingerprint),contextlib.redirect_stdout(io.StringIO()):
                h.deploy('node.example.test',runner=run,budget=8)
            self.assertEqual((self.proc.pid,self.proc.poll()),(pid,None));self.tls(new)
            status=json.loads(h.STATUS.read_text());self.assertEqual(status['result'],'PASS')
            self.assertEqual(status['certificate_sha256'],fingerprint)
            self.assertEqual(sum('reload' in a for a in commands),1)
        finally:
            for name,data in saved.items():(self.root/name).write_bytes(data)
            subprocess.run([fixture.NGINX,'-s','reload','-p',str(self.root)+'/', '-c',str(self.root/'nginx.conf')],capture_output=True,check=True,timeout=5)
            # A graceful reload can briefly expose old and new workers. Restore
            # test isolation only after the original certificate is observed
            # repeatedly; one lucky connection is not a convergence proof.
            deadline=time.monotonic()+4;stable=0
            while stable < 4:
                try:
                    self.tls();stable+=1
                    if stable < 4:time.sleep(0.05)
                except (ssl.SSLError,OSError,ValueError):
                    stable=0
                    if time.monotonic()>deadline:raise
                    time.sleep(0.05)

    def test_bad_key_precheck_preserves_current_certificate_and_service(self):
        new,_=certificate_bundle();p=self.root/'key.pem';old=p.read_bytes();pid=self.proc.pid
        try:
            p.write_text(new['nodeKeyPem'])
            r=subprocess.run([fixture.NGINX,'-t','-p',str(self.root)+'/', '-c',str(self.root/'nginx.conf')],capture_output=True,timeout=5)
            self.assertNotEqual(r.returncode,0)
            self.tls();self.assertEqual(self.request()[0],200)
            self.assertEqual((self.proc.pid,self.proc.poll()),(pid,None))
        finally:p.write_bytes(old)


class Selfsteal230PrivateStateTests(unittest.TestCase):
    def setUp(self):
        self.h=module('VK_PAYLOAD_VK_WRITE_SELFSTEAL_CHECK')
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.etc=self.root/'etc';self.etc.mkdir()
        self.certroot=self.root/'certs';self.certroot.mkdir();(self.certroot/'node.example.test').mkdir()
        self.cert=self.certroot/'node.example.test'/'fullchain.pem';self.bundle,_=certificate_bundle()
        self.cert.write_text(self.bundle['nodeCertPem'])
        self.cfg=self.etc/'config.json';self.cfg.write_text('{"domain":"node.example.test","selfsteal_host_socket":"/run/vkarmani-selfsteal/nginx.sock"}');self.cfg.chmod(0o600)

    def read(self):return self.h.load_target(self.etc,self.certroot)

    def test_bounded_metadata_and_expected_leaf(self):
        domain,path,fp=self.read()
        self.assertEqual(domain,'node.example.test');self.assertEqual(len(fp),32)
        self.assertEqual(path,'/run/vkarmani-selfsteal/nginx.sock')

    def test_certbot_symlink_allowed_but_config_symlink_refused(self):
        target=self.root/'certificate';self.cert.rename(target);self.cert.symlink_to(target)
        self.read()
        c=self.root/'config';self.cfg.rename(c);self.cfg.symlink_to(c)
        with self.assertRaises(OSError):self.read()

    def test_config_wrong_mode_and_fifo_refused(self):
        self.cfg.chmod(0o644)
        with self.assertRaisesRegex(ValueError,'UNSAFE'):self.read()
        self.cfg.unlink();os.mkfifo(self.cfg,0o600)
        with self.assertRaisesRegex(ValueError,'UNSAFE'):self.read()

    def test_duplicate_nonfinite_and_traversal_domain_refused(self):
        for cfg in ('{"domain":"node.example.test","domain":"other.test"}',
                    '{"domain":"node.example.test","v":NaN}',
                    '{"domain":"../../secret"}',
                    '{"domain":"node.example.test","selfsteal_host_socket":"/run/unknown.sock"}'):
            self.cfg.write_text(cfg)
            with self.subTest(kind=cfg[:10]),self.assertRaises(ValueError):self.read()

    def test_oversized_config_and_certificate_refused(self):
        old=self.cfg.read_bytes();self.cfg.write_bytes(b' '*65537)
        with self.assertRaisesRegex(ValueError,'TOO_LARGE'):self.read()
        self.cfg.write_bytes(old);self.cert.write_bytes(b' '*1048577)
        with self.assertRaisesRegex(ValueError,'TOO_LARGE'):self.read()

    def test_target_mode_and_full_mode_are_distinct_in_cli(self):
        for argv,target_called,web_called in ((['probe','--target-only'],True,False),(['probe'],False,True)):
            with self.subTest(argv=argv),patch.object(self.h,'load_target',return_value=('node.example.test','socket',b'a'*32)),\
                 patch.object(self.h,'target_tls') as target,patch.object(self.h,'check') as web,\
                 patch.object(self.h,'nginx_sni_reject_supported',return_value=True),\
                 patch.object(self.h.sys,'argv',argv),contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(self.h.main(),0)
                self.assertEqual(target.called,target_called);self.assertEqual(web.called,web_called)
                self.assertIn('AUTHENTICATED_VLESS_CLIENT=NOT_TESTED',output.getvalue())

    def test_dpkg_audit_and_ipv6_command_failures_cannot_be_success(self):
        self.assertIn('DPKG_AUDIT=$(dpkg --audit) ||',SCRIPT)
        self.assertIn("else fail NO_IPV6_LISTENERS 'NOT_VERIFIED: ss failed'",SCRIPT)
