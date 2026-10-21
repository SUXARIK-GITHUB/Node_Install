"""R13 offline matrix: five Ordinary REALITY choices and RAW/XHTTP consistency.

Never runs a live installation, connects to remote hosts, or writes system paths.
The synthetic samples are deliberately non-secret and isolated per test.
"""
import copy
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from common import ROOT, SCRIPT, module, payload


MODES = (('1', 'local'), ('2', 'max.ru'), ('3', 'ya.ru'),
         ('4', 'rutube.ru'), ('5', 'mail.ru'))


class MenuModes(unittest.TestCase):
    @staticmethod
    def choose(choices):
        shell = SCRIPT.split('vk_menu_read() {', 1)[1].split('[[ $EUID -eq 0 ]]', 1)[0]
        selected = ' '.join(repr(x) for x in choices)
        shell = "vk_menu_read() {" + shell + r'''
choices=(%s)
index=0
vk_menu_display_prompt(){ :; }
vk_menu_read(){ VK_MENU_CHOICE="${choices[$index]:-}"; ((index+=1)); }
VK_REALITY_MODE=local
vk_initial_install_menu || exit $?
printf 'SELECTED_MODE=%%s\n' "$VK_REALITY_MODE"
''' % selected
        return subprocess.run(['bash', '-c', shell], capture_output=True, text=True,
                              timeout=5)

    def test_five_choices_before_any_installation(self):
        for digit, mode in MODES:
            with self.subTest(mode=mode):
                done = self.choose(['1', digit])
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertIn('SELECTED_MODE=' + mode, done.stdout)
                self.assertNotIn('STOP', done.stderr)

    def test_invalid_modes_refuse_install(self):
        for sequence in (['1'] + ['bogus'] * 5, ['1'] + [''] * 5):
            with self.subTest(sequence=sequence):
                done = self.choose(sequence)
                self.assertEqual(done.returncode, 2)
                self.assertIn('выбор REALITY не выполнен', done.stderr)

    def test_no_cascade_mode_change_and_resume_field_gate(self):
        entry = self.choose(['2', 'entry', '/root/cascade.json'])
        self.assertEqual(entry.returncode, 0, entry.stderr)
        self.assertIn('SELECTED_MODE=local', entry.stdout)
        self.assertLess(SCRIPT.index('vk_initial_install_menu || return $?'),
                        SCRIPT.index('vk_wait_apt_idle "$APT_LOCK_TOTAL_WAIT"'))
        self.assertIn('len(inputs) == 4', SCRIPT)
        self.assertIn('${saved[3]:-local}', SCRIPT)
        self.assertIn('vk_preflight_reality_external "$VK_REALITY_MODE"', SCRIPT)

    def test_preflight_is_fail_closed_before_persistent_writes(self):
        func = SCRIPT.index('vk_preflight_reality_external() {')
        pre = SCRIPT.index('vk_preflight_reality_external "$VK_REALITY_MODE"', func)
        persistent = SCRIPT.index('install -d -m 0700 "$ETC" "$STATE" "$LIB" "$OPT"', pre)
        self.assertLess(pre, persistent)
        check = payload('PY_REALITY_TARGET_PREFLIGHT')
        for requirement in ('socket.AF_INET', 'is_global', 'ssl.create_default_context()',
                            'TLSVersion.TLSv1_3', 'server_hostname=host', 'timeout=5'):
            self.assertIn(requirement, check)
        self.assertNotIn('subprocess', check)
        self.assertNotIn('shell=True', check)


class ModesProfiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='vk-r13-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.etc = self.root / 'etc'
        self.helper = module('PY_HELPER')
        self.helper.ETC = self.etc
        self.helper.REALITY_EXPORT = self.root / 'root' / 'reality-keys.txt'
        (self.root / 'root').mkdir(mode=0o700)
        spec = importlib.util.spec_from_file_location('vk_xhttp_r13',
                                      ROOT / 'integrations/xhttp_profile.py')
        self.xhttp = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.xhttp)
        injected = patch.object(self.helper, 'detect_local_public_ipv4s',
                                return_value={'8.8.4.4': 'eth0'})
        injected.start()
        self.addCleanup(injected.stop)

    def fixture(self, mode):
        c = {'domain': 'node.example.test', 'public_ipv4': '8.8.4.4',
             'panel_ipv4': ['1.1.1.1'], 'node_port': 2222,
             'reality_mode': mode}
        _, _, raw = self.helper.make_keys_profile(c)
        self.helper.atomic_json(self.etc / 'config.json', c)
        xhttp = self.xhttp.build_xhttp(self.etc)
        return c, raw, xhttp

    def test_all_five_templates_are_consistent_and_secure(self):
        for _, mode in MODES:
            with self.subTest(mode=mode):
                c, raw, xhttp = self.fixture(mode)
                expected_sni = c['domain'] if mode == 'local' else mode
                expected_target = '/dev/shm/nginx.sock'
                expected_xver = 1
                for p in (raw, xhttp):
                    self.assertTrue(self.helper.validate_profile(p, c))
                    self.assertEqual(len(p['inbounds']), 1)
                    self.assertEqual(p['inbounds'][0]['port'], 443)
                    reality = p['inbounds'][0]['streamSettings']['realitySettings']
                    self.assertEqual(reality['target'], expected_target)
                    self.assertEqual(reality['serverNames'], [expected_sni])
                    self.assertEqual(reality['xver'], expected_xver)
                    self.assertEqual(p['outbounds'][0]['protocol'], 'freedom')
                    self.assertEqual(p['outbounds'][0]['streamSettings']['sockopt']['domainStrategy'], 'ForceIPv4')
                    final = p['outbounds'][0]['settings']['finalRules']
                    self.assertEqual(final[0]['action'], 'block')
                    self.assertIn('::/0', final[0]['ip'])
                    self.assertEqual(p['routing']['rules'][0]['protocol'], ['bittorrent'])
                    self.assertEqual(p['routing']['rules'][0]['outboundTag'], 'BLOCK')
                    self.assertEqual(p['dns']['queryStrategy'], 'UseIPv4')
                    self.assertTrue(p['dns']['enableParallelQuery'])
                    self.assertTrue(p['dns']['serveStale'])
                    self.assertEqual(p['dns']['serveExpiredTTL'], 3600)
                    self.assertFalse(p['dns']['disableCache'])
                self.assertEqual(raw['inbounds'][0]['settings']['flow'], 'xtls-rprx-vision')
                self.assertEqual(raw['inbounds'][0]['streamSettings']['network'], 'raw')
                self.assertEqual(xhttp['inbounds'][0]['settings']['flow'], '')
                self.assertEqual(xhttp['inbounds'][0]['streamSettings']['network'], 'xhttp')
                self.assertEqual(xhttp['inbounds'][0]['streamSettings']['xhttpSettings']['host'], expected_sni)
                self.assertEqual(xhttp['inbounds'][0]['streamSettings']['xhttpSettings']['mode'], 'auto')
                self.assertEqual(raw['inbounds'][0]['tag'], xhttp['inbounds'][0]['tag'])
                self.assertEqual(raw['inbounds'][0]['streamSettings']['realitySettings'],
                                 xhttp['inbounds'][0]['streamSettings']['realitySettings'])
                self.assertEqual(raw['outbounds'], xhttp['outbounds'])
                self.assertEqual(raw['routing'], xhttp['routing'])
                self.assertEqual(raw['dns'], xhttp['dns'])
                self.etc.joinpath('profile.json').unlink()
                self.etc.joinpath('config.json').unlink()
                self.etc.joinpath('reality.json').unlink()

    def test_forgeries_are_refused_with_no_mutation(self):
        c, raw, xhttp = self.fixture('max.ru')
        baseline = copy.deepcopy(raw)
        for name, transform in (
            ('target', lambda p: p['inbounds'][0]['streamSettings']['realitySettings'].update(target='max.ru:443')),
            ('sni', lambda p: p['inbounds'][0]['streamSettings']['realitySettings'].update(serverNames=['ya.ru'])),
            ('xver', lambda p: p['inbounds'][0]['streamSettings']['realitySettings'].update(xver=0))):
            with self.subTest(name=name):
                bad = copy.deepcopy(raw)
                transform(bad)
                with self.assertRaises(self.helper.Failure):
                    self.helper.validate_profile(bad, c)
                self.assertEqual(raw, baseline)
        c['reality_mode'] = 'ya.ru'
        self.helper.atomic_json(self.etc / 'config.json', c)
        with self.assertRaises(self.xhttp.Invalid):
            self.xhttp.build_xhttp(self.etc)

    def test_legacy_missing_mode_keeps_local_selfsteal(self):
        c = {'domain': 'node.example.test', 'public_ipv4': '8.8.4.4',
             'panel_ipv4': ['1.1.1.1'], 'node_port': 2222}
        _, _, raw = self.helper.make_keys_profile(c)
        self.helper.atomic_json(self.etc / 'config.json', c)
        xhttp = self.xhttp.build_xhttp(self.etc)
        self.assertEqual(raw['inbounds'][0]['streamSettings']['realitySettings']['xver'], 1)
        self.assertEqual(xhttp['inbounds'][0]['streamSettings']['realitySettings']['target'],
                         '/dev/shm/nginx.sock')
        self.assertTrue(self.helper.validate_profile(xhttp, c))

    def test_invalid_reality_config_rejected(self):
        for invalid in ('fake.com', 'MAX.RU', '', 3, ['max.ru']):
            with self.subTest(invalid=invalid):
                c = {'domain': 'node.example.test', 'public_ipv4': '8.8.4.4',
                     'panel_ipv4': ['1.1.1.1'], 'reality_mode': invalid}
                with self.assertRaises(self.helper.Failure):
                    self.helper.normalize_config(c)


if __name__ == '__main__':
    unittest.main()
