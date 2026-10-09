import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from common import module, SCRIPT


class RealityKeyExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.h = module('PY_HELPER')

    def config(self):
        return {
            'installation_mode': 'secret-key-only',
            'domain': 'node.example.test',
            'public_ipv4': '8.8.8.8',
            'panel_ipv4': ['1.1.1.1'],
            'node_port': 2222,
        }

    def test_export_is_private_atomic_and_matches_authoritative_keys(self):
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(self.h, 'ETC', Path(folder) / 'etc'), \
             patch.object(self.h, 'REALITY_EXPORT', Path(folder) / 'reality-keys.txt'), \
             patch.object(self.h, 'detect_local_public_ipv4s', return_value={'8.8.8.8': 'eth0'}):
            out = self.h.export_reality_keys_file(self.config())
            self.assertEqual(out, Path(folder) / 'reality-keys.txt')
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)
            self.assertEqual(out.stat().st_uid, os.geteuid())
            keys = self.h.read_json(self.h.ETC / 'reality.json')
            text = out.read_text()
            self.assertIn('PrivateKey: ' + keys['private_key'], text)
            self.assertIn('PublicKey: ' + keys['public_key'], text)
            self.assertIn('ShortID: ' + keys['short_id'], text)
            self.assertIn('minClientVer: 0.0.0', text)
            profile = self.h.read_json(self.h.ETC / 'profile.json')
            reality = profile['inbounds'][0]['streamSettings']['realitySettings']
            self.assertEqual(reality['minClientVer'], '0.0.0')

    def test_export_reuses_same_keys_and_does_not_regenerate(self):
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(self.h, 'ETC', Path(folder) / 'etc'), \
             patch.object(self.h, 'REALITY_EXPORT', Path(folder) / 'reality-keys.txt'), \
             patch.object(self.h, 'detect_local_public_ipv4s', return_value={'8.8.8.8': 'eth0'}):
            first = self.h.export_reality_keys_file(self.config()).read_text()
            keys_before = (self.h.ETC / 'reality.json').read_bytes()
            second = self.h.export_reality_keys_file(self.config()).read_text()
            self.assertEqual(first, second)
            self.assertEqual(keys_before, (self.h.ETC / 'reality.json').read_bytes())

    def test_export_refuses_symlink_and_overpermissive_existing_file(self):
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(self.h, 'ETC', Path(folder) / 'etc'), \
             patch.object(self.h, 'REALITY_EXPORT', Path(folder) / 'reality-keys.txt'), \
             patch.object(self.h, 'detect_local_public_ipv4s', return_value={'8.8.8.8': 'eth0'}):
            target = Path(folder) / 'foreign'
            target.write_text('DO NOT TOUCH')
            self.h.REALITY_EXPORT.symlink_to(target)
            with self.assertRaises(self.h.Failure):
                self.h.export_reality_keys_file(self.config())
            self.assertEqual(target.read_text(), 'DO NOT TOUCH')
            self.assertTrue(self.h.REALITY_EXPORT.is_symlink())

        with tempfile.TemporaryDirectory() as folder, \
             patch.object(self.h, 'ETC', Path(folder) / 'etc'), \
             patch.object(self.h, 'REALITY_EXPORT', Path(folder) / 'reality-keys.txt'), \
             patch.object(self.h, 'detect_local_public_ipv4s', return_value={'8.8.8.8': 'eth0'}):
            self.h.REALITY_EXPORT.write_text('FOREIGN SECRET')
            self.h.REALITY_EXPORT.chmod(0o644)
            with self.assertRaises(self.h.Failure):
                self.h.export_reality_keys_file(self.config())
            self.assertEqual(self.h.REALITY_EXPORT.read_text(), 'FOREIGN SECRET')
            self.assertEqual(self.h.REALITY_EXPORT.stat().st_mode & 0o777, 0o644)

    def test_profile_policy_rejects_changed_or_missing_legacy_floor(self):
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(self.h, 'ETC', Path(folder)), \
             patch.object(self.h, 'detect_local_public_ipv4s', return_value={'8.8.8.8': 'eth0'}):
            _, _, profile = self.h.make_keys_profile(self.config())
            reality = profile['inbounds'][0]['streamSettings']['realitySettings']
            reality.pop('minClientVer')
            with self.assertRaises(self.h.Failure):
                self.h.validate_profile(profile, self.config())
            reality['minClientVer'] = '26.3.27'
            with self.assertRaises(self.h.Failure):
                self.h.validate_profile(profile, self.config())


class RebootContractTests(unittest.TestCase):
    def test_default_one_time_reboot_and_explicit_opt_out(self):
        self.assertIn('NO_REBOOT=0', SCRIPT)
        self.assertIn('--no-reboot) NO_REBOOT=1', SCRIPT)
        self.assertIn('--reboot) NO_REBOOT=0', SCRIPT)
        self.assertIn('--on-active=30s /usr/bin/systemctl reboot', SCRIPT)
        self.assertIn('AUTO_REBOOT=DISABLED_BY_FLAG', SCRIPT)
        self.assertIn('AUTO_REBOOT=FAILED', SCRIPT)

    def test_private_key_display_bypasses_install_log(self):
        self.assertIn('REALITY_KEYS_FILE=/root/reality-keys.txt', SCRIPT)
        self.assertIn("'reality-export'], quiet=True)", SCRIPT)
        self.assertIn("self.read(self.path('root/reality-keys.txt'), private=True)", SCRIPT)
        self.assertIn('cat "$REALITY_KEYS_FILE"', SCRIPT)
        self.assertIn('} > /dev/tty', SCRIPT)
        self.assertIn('PrivateKey не записывается в install log', SCRIPT)


if __name__ == '__main__':
    unittest.main()
