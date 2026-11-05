"""R25 fault-injection regressions for crash-resumable site/network receipts.

Only synthetic filesystem fixtures and fake sysctl/systemctl. Never modify
actual host state or connect to the Internet.
"""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from common import ROOT
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'integrations')]
import staging_web_deploy as web
import network_tuning as tuning
import test_r20_rich_site as rich_fixture


class SiteSwitchRecovery(unittest.TestCase):
    def fixture(self, root):
        fixture = rich_fixture.RichCover()
        site, _, _ = fixture.setup_fixture(root)
        app = web.NodeWeb(root, run=fixture.runner(site), css_check=lambda *_: None)
        app.site_install('111-atlas-docs', 'site.example.test', rich_pages=True)
        app.site_install('116-vinyl-room', 'site.example.test', rich_pages=True, switch=True)
        return app, site

    def test_crash_between_files_and_old_receipt_is_resumable(self):
        with tempfile.TemporaryDirectory() as temp:
            app, site = self.fixture(Path(temp))
            original = app.write_receipt
            failed = [False]
            def fail_restore(kind, receipt):
                if (kind == 'site' and receipt.get('stage') == 'active' and
                        receipt.get('metadata', {}).get('theme') == '111-atlas-docs' and
                        not failed[0]):
                    failed[0] = True
                    raise OSError('simulated crash before reactivating old receipt')
                return original(kind, receipt)
            app.write_receipt = fail_restore
            with self.assertRaisesRegex(OSError, 'simulated crash'):
                app.site_rollback()
            self.assertEqual(app.receipt('site')['stage'], 'rolled_back')
            self.assertTrue(failed[0])
            app.write_receipt = original
            self.assertEqual(app.site_rollback(),
                             'SITE_CHANGE_ROLLBACK=PASS PREVIOUS_THEME_RESTORED')
            self.assertEqual(app.receipt('site')['metadata']['theme'], '111-atlas-docs')
            self.assertEqual(app.site_rollback(), 'SITE_ROLLBACK=PASS')

    def test_refuse_tampered_file_when_restoring_previous_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            app, site = self.fixture(Path(temp))
            original = app.write_receipt
            def fail_restore(kind, receipt):
                if (kind == 'site' and receipt.get('stage') == 'active' and
                        receipt.get('metadata', {}).get('theme') == '111-atlas-docs'):
                    raise OSError('simulated crash')
                return original(kind, receipt)
            app.write_receipt = fail_restore
            with self.assertRaises(OSError):
                app.site_rollback()
            app.write_receipt = original
            index = site / 'index.html'
            index.write_bytes(b'third-party-edited')
            with self.assertRaisesRegex(web.DeployError, 'RESTORED_PREVIOUS_SITE_DRIFT'):
                app.site_rollback()
            self.assertEqual(app.receipt('site')['stage'], 'rolled_back')


class NetworkRecovery(unittest.TestCase):
    def fixture(self, root):
        state = root / 'var/lib/vkarmani-node'
        state.mkdir(parents=True)
        (root / 'etc/sysctl.d').mkdir(parents=True)
        (state / 'owned-installation').touch()
        (state / 'INSTALL_COMPLETE').write_text('version=2.5.18\n')
        live = {k: 4096 for k in tuning.PARAMS.values()}
        def run(argv):
            if argv[1] == '-p':
                for k in live: live[k] = 8192
            elif argv[1] == '-w':
                k, v = argv[2].split('=')
                live[k] = int(v)
        def get(k): return live[k]
        plan = {'recommendations': {k: {'before': 4096, 'after': 8192} for k in live}}
        return state, live, run, get, plan

    def test_crash_after_unlink_is_resumable_with_rolling_back_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state, live, run, get, plan = self.fixture(root)
            tuning.transact(plan, 'apply', root=root, run=run, get=get)
            orig = tuning._atomic
            receipt = state / tuning.RECEIPT
            failed = [False]
            def crash_after_unlink(path, data, *args):
                if (path == receipt and b'"status": "rolled_back"' in data and not failed[0]):
                    failed[0] = True
                    raise OSError('disk write interrupted')
                return orig(path, data, *args)
            with patch.object(tuning, '_atomic', crash_after_unlink):
                with self.assertRaises(OSError):
                    tuning.transact(None, 'rollback', root=root, run=run, get=get)
            self.assertFalse((root / tuning.SYSCTL_FILE.relative_to('/')).exists())
            self.assertEqual(json.loads(receipt.read_bytes())['status'], 'rolling_back')
            self.assertEqual(tuning.transact(None, 'rollback', root=root, run=run, get=get),
                             'NETWORK_TUNING=ROLLBACK_PASS')
            self.assertTrue(all(v == 4096 for v in live.values()))
            self.assertEqual(json.loads(receipt.read_bytes())['status'], 'rolled_back')

    def test_r24_legacy_active_receipt_with_missing_file_is_reconciled(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state, live, run, get, plan = self.fixture(root)
            tuning.transact(plan, 'apply', root=root, run=run, get=get)
            # R24 restored sysctl and deleted the file *before* its receipt.
            for k in live: live[k] = 4096
            (root / tuning.SYSCTL_FILE.relative_to('/')).unlink()
            self.assertEqual(tuning.transact(None, 'rollback', root=root, run=run, get=get),
                             'NETWORK_TUNING=ROLLBACK_PASS')
            self.assertEqual(json.loads((state/tuning.RECEIPT).read_text())['status'], 'rolled_back')

    def test_foreign_values_refuse_resume(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state, live, run, get, plan = self.fixture(root)
            tuning.transact(plan, 'apply', root=root, run=run, get=get)
            live[next(iter(live))] = 8123
            with self.assertRaisesRegex(tuning.TuneError, 'THIRD_PARTY_SYSCTL_CHANGE'):
                tuning.transact(None, 'rollback', root=root, run=run, get=get)
            self.assertTrue((root / tuning.SYSCTL_FILE.relative_to('/')).exists())
            self.assertEqual(json.loads((state/tuning.RECEIPT).read_text())['status'], 'active')

    def test_unfinished_transactions_are_denied_after_lock(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state, live, run, get, plan = self.fixture(root)
            for marker in ('image-update-pending', 'cover-pending', 'RESUME_FAILED',
                           'network-rollback-running', 'FINALIZE_FAILED'):
                with self.subTest(marker=marker):
                    (state / marker).touch()
                    with self.assertRaisesRegex(tuning.TuneError, 'INCOMPLETE_OTHER_TRANSACTION'):
                        tuning.transact(plan, 'apply', root=root, run=run, get=get)
                    (state / marker).unlink()
            checkpoint = state / 'finalization'
            checkpoint.mkdir()
            (checkpoint / 'checkpoint.json').write_text(json.dumps({'phase':'checked','version':'2.5.18'}))
            with self.assertRaisesRegex(tuning.TuneError, 'INCOMPLETE_OTHER_TRANSACTION'):
                tuning.transact(plan, 'apply', root=root, run=run, get=get)
            (checkpoint / 'checkpoint.json').write_text(json.dumps({'phase':'complete','version':'2.5.18'}))
            self.assertEqual(tuning.transact(plan, 'apply', root=root, run=run, get=get),
                             'NETWORK_TUNING=APPLIED_MEASURED_BACKLOG_ONLY')

    def test_shared_installer_lock_excludes_concurrent_tuning(self):
        import fcntl
        import os
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state, live, run, get, plan = self.fixture(root)
            fd = os.open(state/'fixture-installer.lock', os.O_RDWR|os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
                with self.assertRaisesRegex(tuning.TuneError, 'NODE_INSTALLER_OR_MAINTENANCE_BUSY'):
                    tuning.transact(plan, 'apply', root=root, run=run, get=get)
            finally:
                os.close(fd)
            self.assertFalse((root / tuning.SYSCTL_FILE.relative_to('/')).exists())

    def test_install_script_reports_partial_without_install_failed(self):
        text = (ROOT/'install.sh').read_text()
        self.assertIn('INSTALL_RESULT=PARTIAL CORE=PASS OPTIONAL_SITE=FAILED', text)
        self.assertIn('VK_SITE_PARTIAL_FAILURE=1', text)
        self.assertIn('trap - ERR INT TERM HUP\n    return 20', text)
        self.assertIn('INSTALL_RESULT=PASS CORE=PASS OPTIONAL_SITE=PASS_OR_NOT_REQUESTED', text)


if __name__ == '__main__': unittest.main()
