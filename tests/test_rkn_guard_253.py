"""2.5.3 RKN integration tests: real embedded code, no host networking changes.

All ipset/iptables/ufw commands are intercepted and state paths are disposable.
"""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from common import ROOT, module, payload, SCRIPT


class RKNGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / 'integrations/rkn_guard.py').read_text()
        assert payload('VK_RKN_GUARD_PY') == cls.source

    def setUp(self):
        self.m = module('VK_RKN_GUARD_PY')
        self.tmp = tempfile.TemporaryDirectory(prefix='vk-rkn-253-')
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.m.ROOT = root / 'state'
        self.m.CACHE = self.m.ROOT / 'current-v4.txt'
        self.m.CHECKED = self.m.ROOT / 'last-check.json'
        self.m.UFW_FILE = root / 'before.rules'
        self.m.CONFIG = root / 'config.json'
        self.m.OWNER = root / 'owned-installation'
        self.m.LOCK = root / 'rkn.lock'
        self.m.OWNER.touch()
        self.m.CONFIG.write_text(json.dumps({'installation_mode': 'secret-key-only',
                                             'panel_ipv4': ['1.1.1.1'], 'other': 'preserved'}))
        self.baseline = ('# header\n*filter\n:ufw-before-input - [0:0]\n'
                         ':ufw-after-input - [0:0]\n'
                         '# custom comment preserved\n'
                         '-A ufw-before-input -i lo -j ACCEPT\nCOMMIT\n')
        self.m.UFW_FILE.write_text(self.baseline)

    @staticmethod
    def dataset(count=150):
        return '# scanner list\n' + ''.join('23.1.%s.0/24\n' % n for n in range(count)) + '2a03:e140:42::/48\n'

    def test_abort_unconfirmed_ufw_rollback_prevents_auto_reboot(self):
        # The finalizer now owns this ordering. Dynamic interrupted/failed
        # rollback tests in test_finalization_256 execute this actual payload.
        final = payload('VK_FINALIZER_PY')
        self.assertIn('RKN_ROLLBACK_BASE_FIREWALL_MISMATCH_CONSOLE_REQUIRED', final)
        self.assertIn("self.absent(self.path(DROPIN))", final)
        self.assertIn('self.rollback_rkn(obj)\n                self.acceptance()', final)
        self.assertLess(final.index('self.rollback_rkn(obj)'), final.index('self.complete(obj)'))
        tail = SCRIPT.split("stage 'Очистка только APT-кэша и ограниченных журналов'", 1)[1]
        self.assertLess(tail.index('finalize_install.py" finish'),
                        tail.index('--on-active=30s /usr/bin/systemctl reboot'))

    def test_embedded_python_equals_reviewed_source(self):
        self.assertEqual(payload('VK_RKN_GUARD_PY'), self.source)
        self.assertIn('OnCalendar=daily', payload('VK_RKN_UPDATE_TIMER'))
        self.assertIn('Persistent=true', payload('VK_RKN_UPDATE_TIMER'))
        self.assertIn('Requires=vkarmani-rkn-prepare.service', payload('VK_RKN_UFW_DEP'))
        self.assertIn('--enable-rkn-guard', SCRIPT)
        self.assertIn('--rkn-update', SCRIPT)
        self.assertIn('panel) exec /usr/local/sbin/vkarmani-rkn-guard sync-panel', SCRIPT)
        self.assertIn("args.action == 'sync-panel'", self.source)
        self.assertIn('NODE_PACKAGES=(openssh-server ufw ipset', SCRIPT)

    def test_cidr_strict_validation_size_and_ipv6_ignored(self):
        nets = self.m.parse_networks(self.dataset())
        self.assertEqual(len(nets), 150)
        self.assertTrue(all(':' not in x for x in nets))
        self.assertIn('23.1.0.0/24', nets)
        for payload in ('0.0.0.0/0\n', '23.1.0.0/8\n', '23.1.0.0/15\n',
                        'rm -rf /\n', '<html>malicious</html>\n',
                        '2a03:e140::/48\n'):
            with self.subTest(payload=payload), self.assertRaises(self.m.GuardError):
                self.m.parse_networks(payload)
        with self.assertRaises(self.m.GuardError):
            self.m.parse_networks('23.1.0.0/24\n' * 100_000)

    def test_panel_ip_is_loaded_afresh_and_rejects_invalid(self):
        self.assertEqual(self.m.panel_ips(), ['1.1.1.1'])
        self.m.CONFIG.write_text(json.dumps({'installation_mode': 'secret-key-only',
                                             'panel_ipv4': ['8.8.8.8', '1.1.1.1']}))
        self.assertEqual(self.m.panel_ips(), ['1.1.1.1', '8.8.8.8'])
        for value in (['127.0.0.1'], ['192.168.0.1'], ['::1'], ['0.0.0.0'],
                      ['23.1.1.1/32'], ['hello']):
            with self.subTest(value=value):
                self.m.CONFIG.write_text(json.dumps({'installation_mode': 'secret-key-only',
                                                     'panel_ipv4': value}))
                with self.assertRaises(self.m.GuardError):
                    self.m.panel_ips()

    def test_ufw_fragment_exact_idempotent_and_only_80_443(self):
        enabled = self.m.edit_ufw(self.baseline, True)
        self.assertIn('-A ufw-before-input -p tcp -m multiport --dports 80,443', enabled)
        self.assertIn('--match-set ' + self.m.PANEL_SET + ' src -j RETURN', enabled)
        self.assertIn('--match-set ' + self.m.BLOCK_SET + ' src -j DROP', enabled)
        self.assertLess(enabled.index(self.m.PANEL_SET), enabled.index(self.m.BLOCK_SET))
        self.assertEqual(self.m.edit_ufw(enabled, True), enabled)
        self.assertEqual(self.m.edit_ufw(enabled, False), self.baseline)
        self.assertNotIn('2222', enabled)
        self.assertNotIn('1.1.1.1', enabled)
        self.assertNotIn('-A INPUT', enabled)
        self.assertNotIn('ip6tables', enabled)

    def test_unknown_firewall_rules_and_corrupt_owned_section_fail_closed(self):
        for content in ('*filter\n:ufw-before-input - [0:0]\n-A ufw-before-input -j SCANNERS-BLOCK\nCOMMIT\n',
                        self.baseline + self.m.BEGIN,
                        self.baseline.replace(':ufw-before-input', ':something-else')):
            with self.subTest(content=content), self.assertRaises(self.m.GuardError):
                self.m.edit_ufw(content, True)
        valid = self.m.edit_ufw(self.baseline, True)
        corrupted = valid.replace('--dports 80,443', '--dports 22,80,443')
        with self.assertRaises(self.m.GuardError):
            self.m.edit_ufw(corrupted, False)

    def test_network_and_panel_atomic_swap_no_kernel_calls_outside_stubs(self):
        names = set()
        memberships = {}
        commands = []

        def exists(name):
            return name in names

        def stage(name, values):
            names.add(name)
            memberships[name] = list(values)
            commands.append(('stage', name, len(values)))

        def fake_run(*args, **kwargs):
            commands.append(tuple(args))
            if args[:2] == ('ipset', 'create'):
                names.add(args[2])
                memberships[args[2]] = []
            elif args[:2] == ('ipset', 'swap'):
                a, b = args[2:]
                memberships[a], memberships[b] = memberships[b], memberships[a]
            elif args[:2] == ('ufw', 'status'):
                return 'Status: active\n'
            return ''

        with (patch.object(self.m, 'require_node'),
              patch.object(self.m, 'ipset_exists', side_effect=exists),
              patch.object(self.m, 'ipset_stage', side_effect=stage),
              patch.object(self.m, 'run', side_effect=fake_run),
              patch.object(self.m, 'download', return_value=self.dataset()),
              patch.object(self.m, 'check_ufw_jump'),
              contextlib.redirect_stdout(io.StringIO())):
            self.m.enable()
            self.assertEqual(len(memberships[self.m.BLOCK_SET]), 150)
            self.assertEqual(memberships[self.m.PANEL_SET], ['1.1.1.1'])
            self.assertTrue(self.m.CACHE.is_file())
            self.assertTrue(self.m.CHECKED.is_file())
            self.assertIn(self.m.BEGIN, self.m.UFW_FILE.read_text())
            self.m.CONFIG.write_text(json.dumps({'installation_mode': 'secret-key-only',
                                                 'panel_ipv4': ['8.8.8.8']}))
            # The upstream list did not change. A daily refresh must still
            # repair a stale/externally flushed active kernel set.
            memberships[self.m.BLOCK_SET].clear()
            self.m.update()
            self.assertEqual(memberships[self.m.PANEL_SET], ['8.8.8.8'])
            self.assertEqual(len(memberships[self.m.BLOCK_SET]), 150)
            self.assertEqual(self.m.CACHE.read_text().count('\n'), 150)
            self.m.disable()
            self.assertEqual(self.m.UFW_FILE.read_text(), self.baseline)
        self.assertIn(('ipset', 'swap', self.m.PANEL_STAGE, self.m.PANEL_SET), commands)
        self.assertIn(('ipset', 'swap', self.m.BLOCK_STAGE, self.m.BLOCK_SET), commands)
        self.assertFalse(any(args[:2] == ('iptables', '-F') for args in commands))

    def test_ufw_reload_error_restores_original_file(self):
        calls = []
        def fake_run(*args, **kwargs):
            calls.append(args)
            if args[:2] == ('ufw', 'status'):
                return 'Status: active\n'
            if args[:2] == ('ufw', 'reload') and calls.count(('ufw', 'reload')) == 1:
                raise self.m.GuardError('simulated reload failure')
            return ''
        with patch.object(self.m, 'run', side_effect=fake_run):
            with self.assertRaises(self.m.GuardError):
                self.m.apply_ufw(True)
        self.assertEqual(self.m.UFW_FILE.read_text(), self.baseline)
        self.assertEqual(calls.count(('ufw', 'reload')), 2)

    def test_panel_invalid_prepare_disables_block_not_ufw(self):
        self.m.CONFIG.write_text(json.dumps({'installation_mode': 'secret-key-only',
                                             'panel_ipv4': ['127.0.0.1']}))
        calls = []
        def fake_run(*args, **kwargs):
            calls.append(args)
            return ''
        with (patch.object(self.m, 'require_node'),
              patch.object(self.m, 'ipset_exists', return_value=False),
              patch.object(self.m, 'run', side_effect=fake_run),
              contextlib.redirect_stderr(io.StringIO())):
            self.assertFalse(self.m.prepare())
        self.assertIn(('ipset', 'flush', self.m.BLOCK_SET), calls)

    def test_downloader_error_never_deletes_last_good_data(self):
        self.m.ROOT.mkdir()
        previous = self.m.parse_networks(self.dataset())
        self.m.CACHE.write_text(''.join(n + '\n' for n in previous))
        with (patch.object(self.m, 'require_node'),
              patch.object(self.m, 'prepare', return_value=True),
              patch.object(self.m, 'download', side_effect=self.m.GuardError('offline')),
              patch.object(self.m, 'run')):
            self.m.UFW_FILE.write_text(self.m.edit_ufw(self.baseline, True))
            with self.assertRaises(self.m.GuardError):
                self.m.update()
        self.assertEqual(self.m.restore_cached(), previous)


if __name__ == '__main__':
    unittest.main()
