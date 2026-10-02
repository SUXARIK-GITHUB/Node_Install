"""Bounded cert activation receipts; no Certbot/CA/systemd or user files touched."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from common import SCRIPT, certificate_bundle, module, payload


class CertDeploy230Tests(unittest.TestCase):
    def setUp(self):
        self.mask=os.umask(0o077);os.umask(self.mask);self.addCleanup(os.umask,self.mask)
        self.h = module('VK_CERT_DEPLOY_PY')
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.h.ETC = self.root / 'etc'; self.h.ETC.mkdir(mode=0o700)
        self.h.STATE = self.root / 'state'; self.h.STATE.mkdir(mode=0o700)
        self.h.CERT_ROOT = self.root / 'live'; self.h.CERT_ROOT.mkdir()
        self.h.STATUS = self.h.STATE / 'status.json'
        self.h.LOCK = self.root / 'lock'
        self.domain = 'node.example.test'
        c = self.h.ETC / 'config.json'
        c.write_text(json.dumps({'installation_mode':'secret-key-only', 'domain':self.domain})); c.chmod(0o600)
        self.bundle, _ = certificate_bundle()
        certdir = self.h.CERT_ROOT / self.domain; certdir.mkdir()
        (certdir / 'fullchain.pem').write_text(self.bundle['nodeCertPem'] + self.bundle['caCertPem'])
        self.calls = []

    def runner(self, argv, **kwargs):
        self.calls.append(argv)
        self.assertLessEqual(kwargs['timeout'], 20)
        return subprocess.CompletedProcess(argv, 0, b'', b'')

    def deploy(self, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()): self.h.deploy(self.domain, **kwargs)

    def status(self):
        return json.loads(self.h.STATUS.read_text())

    def test_successful_activation_receipt_and_commands(self):
        self.deploy(runner=self.runner)
        self.assertEqual(self.calls, [
            ['/usr/sbin/nginx','-t'], ['/usr/bin/systemctl','reload','nginx'],
            ['/usr/local/sbin/vkarmani-selfsteal-check','--target-only']])
        r=self.status();self.assertEqual((r['result'],r['phase']),('PASS','COMPLETE'))
        self.assertEqual(self.h.STATUS.stat().st_mode & 0o777,0o600)
        self.assertNotIn('PRIVATE KEY',self.h.STATUS.read_text())
        self.assertEqual(len(r['certificate_sha256']),64)
        self.assertFalse(list(self.h.STATE.glob('.cert-deploy-*')))

    def test_precheck_failure_never_reloads(self):
        def failed(args, **kwargs):
            self.calls.append(args); return subprocess.CompletedProcess(args,1,b'',b'SECRET_ERROR')
        with self.assertRaises(self.h.Failure): self.deploy(runner=failed)
        self.assertEqual(self.calls,[['/usr/sbin/nginx','-t']])
        self.assertEqual((self.status()['result'],self.status()['phase']),('FAIL','PRECHECK'))
        self.assertNotIn('SECRET_ERROR',self.h.STATUS.read_text())

    def test_reload_failure_never_claims_target_pass(self):
        def failed(args, **kwargs):
            self.calls.append(args); return subprocess.CompletedProcess(args,1 if 'reload' in args else 0,b'',b'')
        with self.assertRaises(self.h.Failure): self.deploy(runner=failed)
        self.assertEqual(self.status()['phase'],'RELOAD')
        self.assertFalse(any('--target-only' in a for a in self.calls))

    def test_target_failure_is_bounded_not_web_error(self):
        def failed(args, **kwargs):
            return subprocess.CompletedProcess(args,1 if '--target-only' in args else 0,b'',b'')
        with self.assertRaises(self.h.Failure): self.deploy(runner=failed,budget=1)
        self.assertEqual((self.status()['result'],self.status()['phase']),('FAIL','VERIFY_TARGET_TLS'))

    def test_target_transient_failure_retries_successfully(self):
        n=[0]
        def retry(args, **kwargs):
            self.calls.append(args)
            if '--target-only' in args:
                n[0]+=1
                return subprocess.CompletedProcess(args,int(n[0]==1),b'',b'')
            return subprocess.CompletedProcess(args,0,b'',b'')
        with patch.object(self.h.time,'sleep'): self.deploy(runner=retry)
        self.assertEqual(n[0],2);self.assertEqual(self.status()['result'],'PASS')
        self.assertEqual(sum('reload' in a for a in self.calls),1)

    def test_timeout_precheck_is_explicit(self):
        def timeout(args, **kwargs): raise subprocess.TimeoutExpired(args,1)
        with self.assertRaisesRegex(self.h.Failure,'TIMEOUT'): self.deploy(runner=timeout)
        self.assertEqual(self.status()['result'],'FAIL')

    def test_generation_absent_then_receipt(self):
        self.assertEqual(self.h.generation(),'absent');self.deploy(runner=self.runner)
        self.assertRegex(self.h.generation(),r'^[a-f0-9]{32}$')

    def test_dry_run_requires_new_success_not_stale_receipt(self):
        self.deploy(runner=self.runner)
        previous=self.h.generation()
        with self.assertRaisesRegex(self.h.Failure,'NOT_PROVEN'): self.h.verify_new(previous)
        self.deploy(runner=self.runner)
        with contextlib.redirect_stdout(io.StringIO()) as result: self.h.verify_new(previous)
        self.assertIn('CERTBOT_DEPLOY_HOOK=PASS',result.getvalue())

    def test_receipt_current_certificate_must_match(self):
        self.deploy(runner=self.runner)
        new, _ = certificate_bundle()
        (self.h.CERT_ROOT / self.domain / 'fullchain.pem').write_text(new['nodeCertPem'])
        with self.assertRaisesRegex(self.h.Failure,'NOT_PROVEN'): self.h.verify_new('absent')

    def test_changed_certificate_during_activation_not_pass(self):
        fingerprints=iter(['a'*64,'b'*64])
        with patch.object(self.h,'leaf_fingerprint',side_effect=lambda _:next(fingerprints)):
            with self.assertRaisesRegex(self.h.Failure,'CHANGED_DURING'): self.deploy(runner=self.runner)
        self.assertEqual(self.status()['result'],'FAIL')

    def test_unsafe_status_symlink_not_followed_or_replaced(self):
        dst=self.root/'victim';dst.write_text('PRESERVE')
        self.h.STATUS.symlink_to(dst)
        with self.assertRaises(OSError): self.deploy(runner=self.runner)
        self.assertEqual(dst.read_text(),'PRESERVE');self.assertTrue(self.h.STATUS.is_symlink())
        self.assertEqual(self.calls,[])

    def test_unsafe_state_directory_refused(self):
        self.h.STATE.chmod(0o755)
        with self.assertRaisesRegex(self.h.Failure,'UNSAFE_STATUS_DIRECTORY'): self.deploy(runner=self.runner)
        self.assertFalse(self.h.STATUS.exists())

    def test_status_fifo_not_read_blocking(self):
        os.mkfifo(self.h.STATUS,0o600)
        with self.assertRaisesRegex(self.h.Failure,'UNSAFE_PRIVATE_STATE'): self.deploy(runner=self.runner)
        self.assertEqual(self.calls,[])

    def test_config_domain_validation(self):
        p=self.h.ETC/'config.json'
        for domain in ('../node','node;systemctl','-bad.example','example..com'):
            p.write_text(json.dumps({'installation_mode':'secret-key-only','domain':domain}))
            with self.subTest(domain=domain),self.assertRaises(self.h.Failure): self.h.current_domain()

    def test_certbot_live_certificate_symlink_is_supported(self):
        live=self.h.CERT_ROOT/self.domain/'fullchain.pem'
        value=self.h.leaf_fingerprint(self.domain)
        target=self.root/'cert.pem';live.rename(target);live.symlink_to(target)
        self.assertEqual(value,self.h.leaf_fingerprint(self.domain))

    def test_interrupt_marks_incomplete_phase_fail(self):
        def interrupted(args, **kwargs): raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt): self.deploy(runner=interrupted)
        self.assertEqual((self.status()['result'],self.status()['phase']),('FAIL','PRECHECK'))

    def test_no_vpn_restart_firewall_or_certificate_rewrite(self):
        text=payload('VK_CERT_DEPLOY_PY')
        for token in ('iptables','nft ','docker','restart nginx','privkey.pem','unlink(fullchain'):
            self.assertNotIn(token,text)
        self.assertIn("'--target-only'",text)
        self.assertNotIn('reality.json',text)

    def test_certbot_dryrun_really_requires_deploy_hook_and_receipt(self):
        self.assertIn('--dry-run --run-deploy-hooks --non-interactive',SCRIPT)
        self.assertIn('verify-new "$DEPLOY_BEFORE"',SCRIPT)
        self.assertIn("'deploy_hook=pass'",SCRIPT)
        self.assertLess(SCRIPT.index('verify-new "$DEPLOY_BEFORE"'), SCRIPT.index("printf 'deploy_hook=pass"))

    def test_other_lineage_skips_without_status_or_command(self):
        with patch.object(self.h.os,'geteuid',return_value=0),\
             patch.object(self.h,'current_domain',return_value=self.domain),\
             patch.object(self.h.sys,'argv',['helper','deploy']),\
             patch.dict(os.environ,{'RENEWED_LINEAGE':'/other/cert','RENEWED_DOMAINS':'other.example'}),\
             patch.object(self.h,'deploy') as deploy, contextlib.redirect_stdout(io.StringIO()) as result:
            self.assertEqual(self.h.main(),0)
            deploy.assert_not_called();self.assertIn('SKIPPED_OTHER_LINEAGE',result.getvalue())
        self.assertFalse(self.h.STATUS.exists())

    def test_missing_renewal_context_refused(self):
        with patch.object(self.h.os,'geteuid',return_value=0),\
             patch.object(self.h,'current_domain',return_value=self.domain),\
             patch.object(self.h.sys,'argv',['helper','deploy']),patch.dict(os.environ,{},clear=True):
            with self.assertRaisesRegex(self.h.Failure,'LINEAGE_MISSING'): self.h.main()

    def test_termination_during_target_verification_is_not_retried(self):
        calls=[]
        def signaled(args, **kwargs):
            calls.append(args)
            if '--target-only' in args:
                self.h.interrupted(15,None)
            return subprocess.CompletedProcess(args,0,b'',b'')
        with patch.object(self.h.time,'sleep') as sleep:
            with self.assertRaisesRegex(self.h.Failure,'INTERRUPTED_15'):
                self.deploy(runner=signaled)
            sleep.assert_not_called()
        self.assertEqual((self.status()['result'],self.status()['phase']),('FAIL','VERIFY_TARGET_TLS'))
        self.assertEqual(sum('--target-only' in a for a in calls),1)

    def test_corrupt_or_failed_receipt_cannot_prove_activation(self):
        self.deploy(runner=self.runner)
        status=self.status()
        for update in ({'generation':'invalid'}, {'result':'FAIL'}, {'phase':'RELOAD'}, {'domain':'other.example'}):
            self.h.record(dict(status,**update))
            with self.subTest(update=update),self.assertRaises(self.h.Failure):self.h.verify_new('absent')
