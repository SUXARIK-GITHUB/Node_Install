"""R9 regressions for zero-byte installer marker, separate operator export,
and the legacy-cover / R7 journal mutual exclusion. No server writes.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from common import ROOT, SCRIPT, module, payload


class OperatorExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.m = module('PY_HELPER')
        self.m.ETC = self.base / 'etc/vkarmani-node'
        self.m.ETC.mkdir(parents=True)
        self.m.REALITY_EXPORT = self.base / 'root/reality-keys.txt'
        self.m.PROFILE_EXPORT = self.base / 'root/vkarmani-raw-profile.json'
        self.profile = {'inbounds': [{'tag': 'VK_RAW_TEST', 'protocol': 'vless'}],
                        'routing': {'rules': []}}
        self.profile_source = self.m.ETC / 'profile.json'
        self.profile_source.write_text(json.dumps(self.profile, indent=2) + '\n')
        self.profile_source.chmod(0o600)
        self.keys = {'private_key': 'PRIVATE_CANARY_TEST_ONLY',
                     'public_key': 'PUBLIC_TEST_ONLY', 'short_id': 'aabbccddeeff0011'}
        self.config = {'domain': 'node.example.com'}
        self.make = patch.object(self.m, 'make_keys_profile', return_value=('node', 'tag', self.profile))
        self.read = patch.object(self.m, 'read_json', return_value=self.keys)
        self.make.start(); self.addCleanup(self.make.stop)
        self.read.start(); self.addCleanup(self.read.stop)

    def test_both_root_files_private_same_profile_no_changes_on_retry(self):
        self.m.export_reality_keys_file(self.config)
        exported = self.m.PROFILE_EXPORT
        key_file = self.m.REALITY_EXPORT
        self.assertEqual(json.loads(exported.read_text()), self.profile)
        self.assertEqual(exported.read_bytes(), self.profile_source.read_bytes())
        self.assertIn('PRIVATE_CANARY_TEST_ONLY', key_file.read_text())
        for item in (exported, key_file):
            self.assertEqual(item.stat().st_mode & 0o777, 0o600)
        original = exported.read_bytes()
        self.m.export_reality_keys_file(self.config)
        self.assertEqual(original, exported.read_bytes())

    def test_existing_foreign_or_changed_profile_not_overwritten(self):
        export = self.m.PROFILE_EXPORT
        export.parent.mkdir(parents=True)
        export.write_text('operator edited\n')
        export.chmod(0o600)
        with self.assertRaisesRegex(self.m.Failure, 'изменён относительно'):
            self.m.export_reality_keys_file(self.config)
        self.assertEqual(export.read_text(), 'operator edited\n')
        export.unlink()
        export.symlink_to(self.m.ETC)
        with self.assertRaisesRegex(self.m.Failure, 'небезопасные права'):
            self.m.export_reality_keys_file(self.config)

    def test_cascade_skips_second_operator_profile(self):
        (self.m.ETC / 'cascade-role.json').write_text('{}')
        self.m.export_reality_keys_file(self.config)
        self.assertFalse(self.m.PROFILE_EXPORT.exists())
        self.assertTrue(self.m.REALITY_EXPORT.is_file())


class LegacyCoverR7GuardTests(unittest.TestCase):
    @staticmethod
    def guard_script():
        return payload('VK_LEGACY_COVER_R7_GUARD')

    def test_active_pending_rejected_rolled_back_permitted(self):
        with tempfile.TemporaryDirectory() as t:
            journal = Path(t) / 'r7-web-deploy'
            journal.mkdir(mode=0o700)
            receipt = journal / 'site.json'
            code = self.guard_script().replace(
                "Path('/var/lib/vkarmani-node/r7-web-deploy')", f'Path({str(journal)!r})')
            # Production requires uid=0; this unit-test may run as uid=1000.
            code = code.replace('d.st_uid != 0', 'd.st_uid != os.geteuid()')
            code = code.replace('info.st_uid != 0', 'info.st_uid != os.geteuid()')
            for stage, expected in [('pending', 1), ('active', 1), ('rolled_back', 0)]:
                with self.subTest(stage=stage):
                    receipt.write_text(json.dumps({'schema': 1, 'kind': 'site', 'stage': stage}))
                    receipt.chmod(0o600)
                    p = subprocess.run([sys.executable, '-I', '-B', '-S', '-c', code],
                                       stdin=subprocess.DEVNULL, capture_output=True,
                                       text=True, timeout=10)
                    self.assertEqual(p.returncode, expected, p.stderr)


if __name__ == '__main__':
    unittest.main()
