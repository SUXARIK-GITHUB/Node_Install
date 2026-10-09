"""Execute the real finalizer against a private filesystem and explicit fake services.

No Docker, firewall, NTP, systemd or /etc mutation in these tests.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from common import SCRIPT, ROOT, module, payload


class Finalization256(unittest.TestCase):
    def setUp(self):
        self.m = module('VK_FINALIZER_PY')
        self.temp = tempfile.TemporaryDirectory(prefix='vk-finish-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.digest = 'remnawave/node@sha256:' + 'a'*64
        self.calls = []
        self.checks = 0
        self.fail_check = set()
        self.fail_activate = False
        self.fail_rollback = False
        self.fail_timer = False
        self.f = self.m.Finalizer(self.root, runner=self.runner, owner=os.getuid())
        for name in self.m.WATCHED:
            self.write(name, 'fixture\n')
        self.write('etc/vkarmani-node/config.json', json.dumps({'installation_mode':'secret-key-only',
                   'domain':'node.example.test','public_ipv4':'192.0.2.10','panel_ipv4':['192.0.2.20'],'node_port':2222}))
        self.write(self.m.STATE+'/install-version','2.5.6\n')
        self.write(self.m.STATE+'/image-digest', self.digest+'\n')
        self.write('etc/ufw/before.rules','*filter\n:ufw-before-input - [0:0]\nCOMMIT\n')
        self.write('proc/cmdline','quiet ipv6.disable=1\n')
        self.write(self.m.STATE+'/backups/original/config','old fixture\n')
        self.write(self.m.STATE+'/backups/original/MANIFEST.sha256',self.m.sha(b'old fixture\n')+'  ./config\n')
        self.write(self.m.STATE+'/latest-backup-path','/'+self.m.STATE+'/backups/original\n')
        self.source=self.write(self.m.STATE+'/installer-2.5.6.sh', SCRIPT)

    def write(self, path, value, mode=0o600):
        p=self.root/path
        # mkdir parents mode isn't applied to every ancestor by pathlib; tighten all.
        p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        for d in [p.parent,*p.parent.parents]:
            if self.root in d.parents or d==self.root: d.chmod(0o700)
        p.write_text(value);p.chmod(mode)
        return p

    def runner(self, argv, timeout=30, quiet=False):
        self.calls.append((argv,quiet))
        if argv[0]=='ip':
            return '[{"addr_info":[{"family":"inet","local":"192.0.2.10"}]}]'
        if argv[0]=='docker':
            return self.digest+'|true|false\n'
        if argv[0].endswith('/vkarmani-node-check'):
            self.checks+=1
            if self.checks in self.fail_check:
                raise self.m.Failure('MOCK_NTP_TIMEOUT')
            return ''
        if argv[0]=='python3' and argv[-1]=='reality-export':
            self.assertTrue(quiet, 'private key export must not go to stdout')
            self.write('root/reality-keys.txt','PRIVATE-TEST-CANARY\n')
            return ''
        if argv[0]=='bash':
            code=argv[4]
            if code.endswith('vk_rkn_activate'):
                self.write('etc/ufw/before.rules', self.m.RKN_MARKER+'\n')
                self.write(self.m.DROPIN,'[Unit]\nRequires=vkarmani-rkn-prepare.service\n')
                self.write(self.m.STATE+'/rkn/owned','version=2.5.3\n')
                if self.fail_activate: raise self.m.Failure('MOCK_ACTIVATION_FAIL')
            elif code.endswith('vk_rkn_abort_setup'):
                if self.fail_rollback: raise self.m.Failure('MOCK_ROLLBACK_FAIL')
                self.write('etc/ufw/before.rules',(self.f.tx/'ufw-before.rules').read_text())
                (self.root/self.m.DROPIN).unlink(missing_ok=True)
            else: self.fail('unexpected bash action '+code)
            return ''
        if argv[0].endswith('/vkarmani-rkn-guard') and argv[-1]=='status':
            return 'RKN_FIREWALL=PASS\n'
        if argv[0]=='systemctl' and argv[1] in ('is-enabled','is-active'):
            if self.fail_timer: raise self.m.Failure('MOCK_TIMER_FAIL')
            return ''
        self.fail('unexpected system command '+str(argv))

    def prepare(self):
        self.f.prepare(self.source)
        self.write(self.m.STATE+'/INSTALL_FAILED','rc=1 line=9999 at=2026-10-09T00:00:00+00:00\n')

    def test_helper_embedded_exactly_matches_source(self):
        self.assertEqual(payload('VK_FINALIZER_PY'),(ROOT/'integrations/finalize_install.py').read_text())

    def test_nominal_full_finish_is_idempotent_and_no_reinstall(self):
        self.prepare()
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.f.finish()
        self.assertIn('FINALIZATION=PASS',out.getvalue())
        self.assertNotIn('PRIVATE-TEST-CANARY',out.getvalue())
        complete=self.f.state/'INSTALL_COMPLETE'
        original=complete.read_bytes()
        self.assertEqual(complete.stat().st_mode&0o777,0o600)
        self.assertFalse((self.f.state/'INSTALL_FAILED').exists())
        first_calls=len([a for a,q in self.calls if a[0]=='bash'])
        self.f.finish()
        self.assertEqual(complete.read_bytes(),original)
        self.assertEqual(first_calls,len([a for a,q in self.calls if a[0]=='bash']))
        for argv,_ in self.calls:
            self.assertNotIn(argv[0],('apt','apt-get','ufw','nginx','reboot'))
            if argv[0]=='systemctl': self.assertIn(argv[1],('is-enabled','is-active'))
            if argv[0]=='docker': self.assertIn('inspect',argv)

    def test_ntp_failure_then_retry_never_replays_os(self):
        self.prepare();self.fail_check={1}
        with self.assertRaisesRegex(self.m.Failure,'NTP_TIMEOUT'):self.f.finish()
        self.assertFalse((self.f.state/'INSTALL_COMPLETE').exists())
        self.assertFalse((self.root/'root/reality-keys.txt').exists())
        self.assertEqual(self.f.checkpoint()['phase'],'ready')
        self.f.finish()
        self.assertEqual(self.f.checkpoint()['phase'],'complete')

    def test_backup_checksum_failure_blocks_checkpoint(self):
        self.write(self.m.STATE+'/backups/original/config','tampered\n')
        with self.assertRaisesRegex(self.m.Failure,'BACKUP_CHECKSUM'):self.f.prepare(self.source)
        self.assertFalse(self.f.tx.exists())

    def test_backup_path_traversal_rejected(self):
        self.write(self.m.STATE+'/backups/original/MANIFEST.sha256',self.m.sha(b'bad')+'  ../../secret\n')
        with self.assertRaisesRegex(self.m.Failure,'PATH_ESCAPE'):self.f.prepare(self.source)

    def test_unreviewed_legacy_install_not_automatically_finalized(self):
        self.write(self.m.STATE+'/install-version','2.5.5\n')
        with self.assertRaisesRegex(self.m.Failure,'2_5_6'):self.f.prepare(self.source)
        self.assertFalse(self.f.tx.exists())

    def test_missing_checkpoint_does_not_create_success(self):
        with self.assertRaises(OSError): self.f.finish()
        self.assertFalse((self.f.state/'INSTALL_COMPLETE').exists())

    def test_changed_keys_or_profile_are_refused(self):
        self.prepare()
        self.write('etc/vkarmani-node/reality.json','changed-key\n')
        with self.assertRaisesRegex(self.m.Failure,'DRIFT'):self.f.finish()
        self.assertEqual(self.checks,0)
        self.assertFalse((self.f.state/'INSTALL_COMPLETE').exists())

    def test_changed_installer_snapshot_refused(self):
        self.prepare();(self.f.tx/'installer.sh').write_text('malicious shell')
        with self.assertRaisesRegex(self.m.Failure,'INSTALLER_CHANGED'):self.f.finish()

    def test_snapshot_checksum_tamper_refused(self):
        self.prepare();(self.f.tx/'snapshot/etc/vkarmani-node/reality.json').write_text('corruption')
        with self.assertRaisesRegex(self.m.Failure,'DRIFT'):self.f.finish()

    def test_wrong_host_ipv4_is_refused(self):
        self.prepare()
        runner=self.f.runner
        self.f.runner=lambda a,**kw: '[]' if a[0]=='ip' else runner(a,**kw)
        with self.assertRaisesRegex(self.m.Failure,'WRONG_NODE'):self.f.finish()

    def test_changed_image_is_refused(self):
        self.prepare();self.digest='remnawave/node@sha256:'+'b'*64
        with self.assertRaisesRegex(self.m.Failure,'DRIFT'):self.f.finish()

    def test_pending_network_transaction_refused(self):
        self.prepare();self.write(self.m.STATE+'/network-rollback-armed','')
        with self.assertRaises(self.m.Failure):self.f.finish()

    def test_optional_template_appearance_is_not_silently_ignored(self):
        self.prepare();self.write('etc/vkarmani-node/profile-xhttp.json','{}')
        with self.assertRaises(self.m.Failure):self.f.finish()

    def test_ready_checkpoint_never_overwritten(self):
        self.prepare();before=(self.f.tx/'checkpoint.json').read_bytes()
        with self.assertRaises(self.m.Failure):self.f.prepare(self.source)
        self.assertEqual(before,(self.f.tx/'checkpoint.json').read_bytes())

    def test_ufw_foreign_edit_before_rkn_is_refused(self):
        self.prepare();self.write('etc/ufw/before.rules','foreign edit\n')
        with self.assertRaisesRegex(self.m.Failure,'BASE_UFW_CHANGED'):self.f.finish()
        self.assertEqual((self.root/'etc/ufw/before.rules').read_text(),'foreign edit\n')

    def test_rkn_download_or_activation_failure_allows_only_verified_rollback(self):
        self.prepare();self.fail_activate=True
        self.f.finish()
        self.assertEqual(self.f.checkpoint()['rkn'],'DEGRADED_ROLLED_BACK')
        self.assertEqual((self.root/'etc/ufw/before.rules').read_bytes(),(self.f.tx/'ufw-before.rules').read_bytes())
        self.assertTrue((self.f.state/'INSTALL_COMPLETE').exists())

    def test_rkn_rollback_failure_never_marks_install_complete(self):
        self.prepare();self.fail_activate=True;self.fail_rollback=True
        with self.assertRaises(self.m.Failure):self.f.finish()
        self.assertFalse((self.f.state/'INSTALL_COMPLETE').exists())
        self.assertTrue((self.f.state/'INSTALL_FAILED').exists())

    def test_failed_rkn_timer_reverts_filter(self):
        self.prepare();self.fail_timer=True
        self.f.finish()
        self.assertEqual(self.f.checkpoint()['rkn'],'DEGRADED_ROLLED_BACK')

    def test_post_rkn_check_failure_rolls_back_and_checks_again(self):
        self.prepare();self.fail_check={2}
        self.f.finish()
        self.assertEqual(self.f.checkpoint()['rkn'],'DEGRADED_ROLLED_BACK')
        self.assertGreaterEqual(self.checks,4)

    def test_persistent_failed_postchecks_remain_unfinished(self):
        self.prepare();self.fail_check={2,3,4,5}
        with self.assertRaises(self.m.Failure):self.f.finish()
        self.assertFalse((self.f.state/'INSTALL_COMPLETE').exists())

    def test_interrupted_rkn_phase_uses_original_rollback_before_retry(self):
        self.prepare();obj=self.f.checkpoint();self.f.record(obj,'rkn-started')
        self.f.rkn_function('vk_rkn_activate')
        self.f.finish()
        calls=[a[4] for a,q in self.calls if a[0]=='bash']
        self.assertIn('vk_rkn_abort_setup',calls[1])
        self.assertEqual(self.f.checkpoint()['rkn'],'ENABLED')

    def test_final_marker_publish_failure_preserves_retry(self):
        self.prepare();original=self.f.write
        def broken(p,*a,**kw):
            if p.name=='INSTALL_COMPLETE':raise OSError('ENOSPC fixture')
            return original(p,*a,**kw)
        with patch.object(self.f,'write',side_effect=broken):
            with self.assertRaises(OSError):self.f.finish()
        self.assertFalse((self.f.state/'INSTALL_COMPLETE').exists())
        self.assertTrue((self.f.state/'INSTALL_FAILED').exists())
        self.f.finish()
        self.assertTrue((self.f.state/'INSTALL_COMPLETE').exists())

    def test_interruption_after_marker_publish_only_cleans_own_commit(self):
        self.prepare()
        with patch.object(self.f,'cleanup',side_effect=OSError('interrupted')):
            with self.assertRaises(OSError):self.f.finish()
        self.assertTrue((self.f.state/'INSTALL_COMPLETE').exists())
        calls=len(self.calls)
        self.f.finish()
        self.assertTrue(all('is-enabled' not in a and a[0]!='bash' for a,q in self.calls[calls:]))
        self.assertFalse((self.f.state/'INSTALL_FAILED').exists())

    def test_completion_symlink_or_existing_unrelated_marker_never_overwritten(self):
        self.prepare()
        outside=self.write('root/keep','keep')
        (self.f.state/'INSTALL_COMPLETE').symlink_to(outside)
        with self.assertRaises(self.m.Failure):self.f.finish()
        self.assertEqual(outside.read_text(),'keep')

    def test_symlink_in_ancestor_of_checkpoint_is_refused(self):
        self.prepare()
        original=self.f.tx
        saved=self.f.state/'moved-finalization'
        original.rename(saved);original.symlink_to(saved,target_is_directory=True)
        with self.assertRaises(self.m.Failure):self.f.finish()

    def test_prepare_does_not_overwrite_preexisting_completion(self):
        p=self.write(self.m.STATE+'/INSTALL_COMPLETE','keep')
        with self.assertRaises(self.m.Failure):self.f.prepare(self.source)
        self.assertEqual(p.read_text(),'keep')

    def test_keys_backups_and_marker_stay_private(self):
        self.prepare()
        for path in self.f.tx.rglob('*'):
            self.assertEqual(path.stat().st_mode & 0o077,0,str(path))

    def test_resume_path_is_dispatched_before_fresh_mutation(self):
        main=SCRIPT.split('vkarmani_main() {',1)[1]
        self.assertLess(main.index('FINALIZATION_RESUME=SCOPED'),main.index('vk_collect_inputs\n'))
        self.assertIn('--finish-install) shift; vkarmani_finish_install_main',SCRIPT)
        self.assertIn('python3 -I -B "$LIB/finalize_install.py" prepare',SCRIPT)
        self.assertNotIn("stage 'RKN-Guard data:",main)


class Runner256Tests(unittest.TestCase):
    def setUp(self):self.m=module('VK_FINALIZER_PY')

    def test_quiet_command_error_does_not_print_keys(self):
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            with self.assertRaises(self.m.Failure):
                self.m.run([sys.executable,'-c','import sys;print("SECRET-CANARY");sys.exit(2)'],quiet=True)
        self.assertEqual(out.getvalue(),'');self.assertEqual(err.getvalue(),'')

    def test_timeout_stops_own_descendants(self):
        with tempfile.TemporaryDirectory() as d:
            sentinel=Path(d)/'late'
            child='import time,pathlib;time.sleep(.6);pathlib.Path('+repr(str(sentinel))+').touch()'
            parent='import subprocess,sys,time;subprocess.Popen([sys.executable,"-c",'+repr(child)+']);time.sleep(20)'
            with self.assertRaises(subprocess.TimeoutExpired):
                self.m.run([sys.executable,'-c',parent],timeout=.12,quiet=True)
            time.sleep(.7)
            self.assertFalse(sentinel.exists())


if __name__=='__main__':unittest.main()
