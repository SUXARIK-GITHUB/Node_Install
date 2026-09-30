"""Read-only, exact-phase upgrade eligibility on disposable private fixture files."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from common import ROOT, SCRIPT, module, payload


class ResumeNtpTests(unittest.TestCase):
    def setUp(self):
        self.m = module('PY_RESUME_NTP_CHECK')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in ('var/lib/vkarmani-node', 'etc/vkarmani-node', 'usr/local/lib/vkarmani-node', 'opt/vkarmani-node'):
            (self.root / name).mkdir(parents=True, mode=0o700)
        self.write('var/lib/vkarmani-node/owned-installation', '')
        self.write('var/lib/vkarmani-node/install-version', '2.0.2\n')
        self.write('var/lib/vkarmani-node/INSTALL_FAILED', 'rc=100 line=2761 at=2026-09-30T05:37:49+03:00\n')
        self.write('etc/vkarmani-node/config.json', json.dumps({
            'installation_mode': 'secret-key-only', 'domain': 'node.example.test',
            'panel_ipv4': ['192.0.2.20'], 'public_ipv4': '192.0.2.10'}))
        self.write('etc/vkarmani-node/remnanode.env', 'SECRET_KEY=FIXTURE-NOT-A-REAL-KEY\n')
        self.original_helper = (ROOT / 'tests/fixtures/node_helper_2.0.2.txt').read_bytes()
        self.write('usr/local/lib/vkarmani-node/node_helper.py', self.original_helper)
        self.write('var/lib/vkarmani-node/first-backup-path', '/var/lib/vkarmani-node/backups/20260930-053722-1234\n')
        self.write('var/lib/vkarmani-node/backups/20260930-053722-1234/MANIFEST.sha256', 'a' * 64 + '  ./fixture\n')

    def write(self, name, content):
        p = self.root / name
        p.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        p.write_bytes(content if isinstance(content, bytes) else content.encode())
        p.chmod(0o600)
        return p

    def check(self):
        self.m.check_resume(self.root, expected_uid=os.getuid())

    def test_exact_original_helper_fingerprint_is_pinned(self):
        self.assertEqual(hashlib.sha256(self.original_helper).hexdigest(), self.m.OLD_HELPER_SHA256)

    def test_known_202_package_failure_is_eligible(self):
        self.check()

    def test_different_source_version_is_refused(self):
        self.write('var/lib/vkarmani-node/install-version', '2.0.1\n')
        with self.assertRaises(self.m.Failure):
            self.check()

    def test_different_failure_code_is_refused(self):
        self.write('var/lib/vkarmani-node/INSTALL_FAILED', 'rc=1 line=2761 at=2026-09-30T05:37:49+03:00\n')
        with self.assertRaises(self.m.Failure):
            self.check()

    def test_other_installation_stage_is_refused(self):
        self.write('var/lib/vkarmani-node/INSTALL_FAILED', 'rc=100 line=3060 at=2026-09-30T05:37:49+03:00\n')
        with self.assertRaises(self.m.Failure):
            self.check()

    def test_malformed_failure_record_is_refused(self):
        self.write('var/lib/vkarmani-node/INSTALL_FAILED', 'rc=100 line=2761 at=unknown\nextra-line\n')
        with self.assertRaises(self.m.Failure):
            self.check()

    def test_every_later_managed_artifact_refuses_cross_version_resume(self):
        for name in self.m.LATE_PATHS:
            with self.subTest(path=name):
                p = self.write(name, '')
                try:
                    with self.assertRaises(self.m.Failure):
                        self.check()
                finally:
                    p.unlink()

    def test_dangling_late_marker_symlink_is_refused(self):
        p = self.root / 'var/lib/vkarmani-node/image-digest'
        p.symlink_to(self.root / 'missing')
        with self.assertRaises(self.m.Failure):
            self.check()

    def test_modified_old_helper_is_refused(self):
        self.write('usr/local/lib/vkarmani-node/node_helper.py', self.original_helper + b'\n')
        with self.assertRaisesRegex(self.m.Failure, 'helper differs'):
            self.check()

    def test_foreign_config_mode_is_refused(self):
        self.write('etc/vkarmani-node/config.json', '{"installation_mode":"api"}')
        with self.assertRaises(self.m.Failure):
            self.check()

    def test_bad_json_is_refused(self):
        self.write('etc/vkarmani-node/config.json', '{')
        with self.assertRaises(ValueError):
            self.check()

    def test_empty_secret_file_is_refused(self):
        self.write('etc/vkarmani-node/remnanode.env', '')
        with self.assertRaises(self.m.Failure):
            self.check()

    def test_secret_file_symlink_is_refused(self):
        p = self.root / 'etc/vkarmani-node/remnanode.env'
        p.unlink()
        p.symlink_to(self.write('target', 'secret'))
        with self.assertRaises(self.m.Failure):
            self.check()

    def test_unsafe_directory_is_refused(self):
        (self.root / 'etc/vkarmani-node').chmod(0o755)
        with self.assertRaises(self.m.Failure):
            self.check()

    def test_world_readable_secret_is_refused(self):
        (self.root / 'etc/vkarmani-node/remnanode.env').chmod(0o644)
        with self.assertRaises(self.m.Failure):
            self.check()

    def test_wrong_owner_is_refused(self):
        with self.assertRaises(self.m.Failure):
            self.m.check_resume(self.root, expected_uid=os.getuid() + 10000)

    def test_backup_pointer_escape_is_refused(self):
        self.write('var/lib/vkarmani-node/first-backup-path', '/tmp/20260930-053722-1234\n')
        with self.assertRaises(self.m.Failure):
            self.check()

    def test_missing_original_backup_is_refused(self):
        self.write('var/lib/vkarmani-node/first-backup-path', '/var/lib/vkarmani-node/backups/20260930-053723-1234\n')
        with self.assertRaises(OSError):
            self.check()

    def test_empty_original_manifest_is_refused(self):
        self.write('var/lib/vkarmani-node/backups/20260930-053722-1234/MANIFEST.sha256', '')
        with self.assertRaises(self.m.Failure):
            self.check()

    def snapshot(self):
        return {str(p.relative_to(self.root)): (hashlib.sha256(p.read_bytes()).hexdigest(),
                p.stat().st_mode, p.stat().st_mtime_ns, p.stat().st_ino)
                for p in self.root.rglob('*') if p.is_file()}

    def test_success_never_changes_saved_state(self):
        before = self.snapshot()
        self.check()
        self.assertEqual(before, self.snapshot())

    def test_refusal_never_changes_saved_state(self):
        self.write('var/lib/vkarmani-node/INSTALL_FAILED', 'different stage')
        before = self.snapshot()
        with self.assertRaises(self.m.Failure):
            self.check()
        self.assertEqual(before, self.snapshot())

    def test_cli_does_not_print_saved_key(self):
        # The embedded CLI itself, with ONLY the fixture root/owner substituted.
        code = payload('PY_RESUME_NTP_CHECK').replace('check_resume()\n',
               f'check_resume(Path({str(self.root)!r}), expected_uid={os.getuid()})\n')
        p = subprocess.run(['python3', '-c', code], capture_output=True, text=True, timeout=10)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('ELIGIBLE', p.stdout)
        self.assertNotIn('FIXTURE-NOT-A-REAL-KEY', p.stdout + p.stderr)

    def test_version_guard_runs_under_lock_and_commit_after_backup_verification(self):
        main = SCRIPT.split('vkarmani_main() {', 1)[1]
        self.assertLess(main.index('flock -n 9'), main.index('&& vk_check_202_ntp_resume'))
        self.assertLess(main.index('sha256sum --check --quiet MANIFEST.sha256'),
                        main.index('> "$STATE/install-version.tmp"'))
        self.assertIn('if [[ -z "$RESUME_FROM" ]]; then printf', main)

    def test_normal_cross_version_refusal_is_preserved(self):
        main = SCRIPT.split('vkarmani_main() {', 1)[1]
        self.assertIn('[[ "$PREVIOUS_VERSION" == 2.0.2 ]] && vk_check_202_ntp_resume', main)
        self.assertIn('STOP: незавершённая установка другой версии/этапа.', main)


class ResumeErrorHandlerTests(unittest.TestCase):
    def test_failed_backup_keeps_original_checkpoint(self):
        start = SCRIPT.index('on_error() {')
        end = SCRIPT.index("\ntrap 'on_error", start)
        handler = SCRIPT[start:end]
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            old = 'rc=100 line=2761 at=2026-09-30T05:37:49+03:00\n'
            (state / 'install-version').write_text('2.0.2\n')
            (state / 'INSTALL_FAILED').write_text(old)
            code = ('set -Eeuo pipefail\nSTATE=$1\nLOG="$STATE/test.log"\n'
                    'ERROR_HANDLED=0\nRESUME_FROM=2.0.2\n' + handler + '\non_error 1 123\n')
            p = subprocess.run(['bash', '-c', code, '_', folder], capture_output=True, text=True, timeout=10)
            self.assertEqual(p.returncode, 1)
            self.assertEqual((state / 'INSTALL_FAILED').read_text(), old)
            self.assertIn('rc=1 line=123', (state / 'RESUME_FAILED').read_text())

    def test_failure_after_version_commit_uses_current_checkpoint(self):
        start = SCRIPT.index('on_error() {')
        end = SCRIPT.index("\ntrap 'on_error", start)
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            (state / 'install-version').write_text('2.1.0\n')
            code = ('set -Eeuo pipefail\nSTATE=$1\nLOG="$STATE/test.log"\n'
                    'ERROR_HANDLED=0\nRESUME_FROM=2.0.2\n' + SCRIPT[start:end] + '\non_error 100 999\n')
            p = subprocess.run(['bash', '-c', code, '_', folder], capture_output=True, text=True, timeout=10)
            self.assertEqual(p.returncode, 100)
            self.assertIn('rc=100 line=999', (state / 'INSTALL_FAILED').read_text())
            self.assertFalse((state / 'RESUME_FAILED').exists())


if __name__ == '__main__':
    unittest.main()
