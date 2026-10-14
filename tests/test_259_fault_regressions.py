"""Offline fault-injection regressions for the 2.5.9 RKN/maintenance fixes.

The real production Python bodies are extracted from install.sh. All kernel,
firewall, Docker, and systemd operations are stubbed: this does not claim VM
or VPS acceptance. No actual /etc, UFW, ipset or Docker mutations occur.
"""
import contextlib
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from common import SCRIPT, ROOT, module, payload


def stamp(networks, *, checked_at=None):
    checked_at = checked_at or dt.datetime.now(dt.timezone.utc).isoformat()
    return {'sha256': hashlib.sha256(''.join(n + '\n' for n in networks).encode()).hexdigest(),
            'count_ipv4': len(networks), 'checked_at_utc': checked_at}


class RKNFaultRegression259(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='vk259-rkn-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.m = module('VK_RKN_GUARD_PY')
        self.m.ROOT = self.root / 'rkn'
        self.m.ROOT.mkdir(mode=0o700)
        self.m.CONFIG = self.root / 'config.json'
        self.m.UFW_FILE = self.root / 'before.rules'
        self.m.CACHE = self.m.ROOT / 'current-v4.txt'
        self.m.CHECKED = self.m.ROOT / 'last-check.json'
        self.base = '*filter\n:ufw-before-input - [0:0]\nCOMMIT\n'
        self.nets = ['8.8.8.0/24', '9.9.9.0/24']
        self.panel = ['1.1.1.1']

    def run_ok(self, *args, **kwargs):
        if args[:2] == ('ufw', 'status'):
            return 'Status: active\n'
        return ''

    def test_invalid_panel_json_root_is_guard_error(self):
        for root_value in ([], None, 17, 'text', True):
            with self.subTest(root=root_value):
                self.m.CONFIG.write_text(json.dumps(root_value))
                with self.assertRaisesRegex(self.m.GuardError, 'INVALID_NODE_CONFIG_ROOT'):
                    self.m.panel_ips()

    def test_prepare_invalid_config_takes_degraded_path(self):
        self.m.CONFIG.write_text('[]')
        self.m.UFW_FILE.write_text(self.m.edit_ufw(self.base, True))
        output = io.StringIO()
        with (patch.object(self.m, 'require_node'),
              patch.object(self.m, 'ipset_exists', return_value=True),
              patch.object(self.m, 'run', side_effect=self.run_ok),
              contextlib.redirect_stderr(output)):
            self.assertFalse(self.m.prepare())
        self.assertEqual(self.m.UFW_FILE.read_text(), self.base)
        self.assertIn('RKN_PREPARE=DEGRADED', output.getvalue())

    def test_ufw_fsync_error_after_replace_rolls_back_both_directions(self):
        for enabling in (True, False):
            with self.subTest(enable=enabling):
                before = self.base if enabling else self.m.edit_ufw(self.base, True)
                self.m.UFW_FILE.write_text(before)
                original_atomic = self.m.atomic
                triggered = [False]
                events = []

                def failed_fsync(path, data, mode=0o600):
                    original_atomic(path, data, mode=mode)
                    if path == self.m.UFW_FILE and not triggered[0]:
                        triggered[0] = True
                        raise OSError('injected fsync failure after replace')

                def run_stub(*args, **kwargs):
                    events.append(args)
                    return self.run_ok(*args, **kwargs)

                with (patch.object(self.m, 'atomic', side_effect=failed_fsync),
                      patch.object(self.m, 'run', side_effect=run_stub),
                      patch.object(self.m, 'check_ufw_jump')):
                    with self.assertRaisesRegex(OSError, 'fsync'):
                        self.m.apply_ufw(enabling)
                self.assertEqual(self.m.UFW_FILE.read_text(), before)
                self.assertTrue(triggered[0])
                self.assertIn(('ufw', 'reload'), events)

    def test_ufw_failed_rollback_never_reports_success(self):
        self.m.UFW_FILE.write_text(self.base)
        original = self.m.atomic
        writes = [0]

        def fail_twice(path, data, mode=0o600):
            original(path, data, mode=mode)
            if path == self.m.UFW_FILE:
                writes[0] += 1
                raise OSError('persistent disk fault')

        with (patch.object(self.m, 'atomic', side_effect=fail_twice),
              patch.object(self.m, 'run', side_effect=self.run_ok),
              patch.object(self.m, 'check_ufw_jump')):
            with self.assertRaisesRegex(self.m.GuardError, 'ROLLBACK_UNCONFIRMED'):
                self.m.apply_ufw(True)
        self.assertGreaterEqual(writes[0], 2)

    def test_prepare_degraded_rolls_back_after_publish_fsync_failure(self):
        before = self.m.edit_ufw(self.base, True)
        self.m.UFW_FILE.write_text(before)
        old_atomic = self.m.atomic
        once = [False]

        def injected(path, data, mode=0o600):
            old_atomic(path, data, mode=mode)
            if path == self.m.UFW_FILE and not once[0]:
                once[0] = True
                raise OSError('directory fsync failure')

        with (patch.object(self.m, 'atomic', side_effect=injected),
              patch.object(self.m, 'run', side_effect=lambda *a, **k: 'Status: inactive\n'
                           if a[:2] == ('ufw', 'status') else '')):
            with self.assertRaises(OSError):
                self.m._prepare_degraded('INVALID_CONFIG')
        self.assertEqual(self.m.UFW_FILE.read_text(), before)

    def test_active_panel_ipset_parser_rejects_bad_entries_and_duplicates(self):
        for response in ('add ' + self.m.PANEL_SET + ' not-an-ip\n',
                         'add ' + self.m.PANEL_SET + ' 127.0.0.1\n',
                         'add other-set 1.1.1.1\n',
                         ('add ' + self.m.PANEL_SET + ' 1.1.1.1\n')*2):
            with self.subTest(response=response):
                with patch.object(self.m, 'run', return_value=response):
                    with self.assertRaises(self.m.GuardError):
                        self.m.live_panel_set()

    def status_with(self, panel_ips, *, date=None, kernel_block=None):
        self.m.UFW_FILE.write_text(self.base + '\n' + self.m.BEGIN + '\n')
        self.m.CHECKED.write_text(json.dumps(stamp(self.nets, checked_at=date)))
        kernel_block = kernel_block if kernel_block is not None else self.nets
        ipset = ('add ' + self.m.PANEL_SET + ' ' + panel_ips[0] + '\n') if panel_ips else ''
        block = ''.join('add ' + self.m.BLOCK_SET + ' ' + n + '\n' for n in kernel_block)

        def run_stub(*args, **kwargs):
            if args[:2] == ('ipset', 'save'):
                return ipset if args[2] == self.m.PANEL_SET else block
            return self.run_ok(*args, **kwargs)
        output = io.StringIO()
        with (patch.object(self.m, 'require_node'),
              patch.object(self.m, 'panel_ips', return_value=self.panel),
              patch.object(self.m, 'restore_cached', return_value=self.nets),
              patch.object(self.m, 'check_ufw_jump'),
              patch.object(self.m, 'run', side_effect=run_stub),
              contextlib.redirect_stdout(output)):
            result = self.m.status()
        return result, output.getvalue()

    def test_status_detects_empty_and_wrong_panel_exceptions(self):
        for active in ([], ['8.8.8.8']):
            with self.subTest(active=active):
                result, out = self.status_with(active)
                self.assertEqual(result, 1)
                self.assertIn('RKN_PANEL_SET_MATCH=FAIL', out)
                self.assertNotIn('RKN_PANEL_SET_MATCH=PASS', out)

    def test_status_full_active_sets_and_fresh_checkpoint(self):
        result, out = self.status_with(['1.1.1.1'])
        self.assertEqual(result, 0, out)
        self.assertIn('RKN_PANEL_SET_MATCH=PASS', out)
        self.assertIn('RKN_FRESHNESS=PASS', out)
        self.assertIn('RKN_DATA=PASS', out)

    def test_status_reports_stale_without_unloading_rules(self):
        result, out = self.status_with(['1.1.1.1'], date='2020-01-01T00:00:00+00:00')
        self.assertEqual(result, 1)
        self.assertIn('RKN_FRESHNESS=STALE', out)
        self.assertIn('RKN_DATA=DEGRADED', out)
        self.assertTrue(self.m.UFW_FILE.read_text().startswith(self.base))

    def test_enable_fallback_restores_missing_kernel_members(self):
        self.m.UFW_FILE.write_text(self.m.edit_ufw(self.base, True))
        self.m.CHECKED.write_text(json.dumps(stamp(self.nets)))
        seen = []
        out = io.StringIO()
        with (patch.object(self.m, 'require_node'),
              patch.object(self.m, 'check_ufw_active'),
              patch.object(self.m, 'prepare', return_value=True),
              patch.object(self.m, 'apply_ufw'),
              patch.object(self.m, 'update', side_effect=self.m.GuardError('GITHUB_UNAVAILABLE')),
              patch.object(self.m, 'restore_cached', return_value=self.nets),
              patch.object(self.m, 'live_block_set', side_effect=[[], self.nets]),
              patch.object(self.m, 'ipset_stage', side_effect=lambda *a: seen.append(a)),
              patch.object(self.m, 'run', side_effect=self.run_ok),
              patch.object(self.m, 'panel_ips', return_value=self.panel),
              patch.object(self.m, 'live_panel_set', return_value=self.panel),
              patch.object(self.m, 'check_ufw_jump'),
              contextlib.redirect_stdout(out)):
            self.m.enable()
        self.assertEqual(len(seen), 1)
        self.assertIn('RKN_FIREWALL=ENABLED', out.getvalue())

    def test_enable_fallback_without_restore_never_claims_enabled(self):
        self.m.UFW_FILE.write_text(self.m.edit_ufw(self.base, True))
        self.m.CHECKED.write_text(json.dumps(stamp(self.nets)))
        out = io.StringIO()
        with (patch.object(self.m, 'require_node'),
              patch.object(self.m, 'check_ufw_active'),
              patch.object(self.m, 'prepare', return_value=True),
              patch.object(self.m, 'apply_ufw'),
              patch.object(self.m, 'update', side_effect=self.m.GuardError('GITHUB_UNAVAILABLE')),
              patch.object(self.m, 'restore_cached', return_value=self.nets),
              patch.object(self.m, 'live_block_set', return_value=[]),
              patch.object(self.m, 'ipset_stage', side_effect=self.m.GuardError('KERNEL_FAIL')),
              patch.object(self.m, 'run', side_effect=self.run_ok),
              patch.object(self.m, 'check_ufw_jump'),
              contextlib.redirect_stdout(out)):
            with self.assertRaises(self.m.GuardError):
                self.m.enable()
        self.assertNotIn('RKN_FIREWALL=ENABLED', out.getvalue())

    def test_update_checkpoint_write_failure_restores_kernel_cache_and_checkpoint(self):
        self.m.UFW_FILE.write_text(self.base + self.m.BEGIN)
        self.m.CACHE.write_text(self.nets[0] + '\n')
        checkpoint = json.dumps(stamp([self.nets[0]])) + '\n'
        self.m.CHECKED.write_text(checkpoint)
        updated = self.nets
        old_atomic = self.m.atomic
        failure = [False]
        swaps = []
        # Failure happens during CHECKED write, before post-write verification:
        # one observation before the kernel swap and one after rollback.
        block_calls = iter([[self.nets[0]], [self.nets[0]]])

        def fake_atomic(path, data, mode=0o600):
            old_atomic(path, data, mode=mode)
            if path == self.m.CHECKED and not failure[0]:
                failure[0] = True
                raise OSError('ENOSPC after checkpoint replace')

        def fake_run(*args, **kwargs):
            if args[:2] == ('ipset', 'swap'):
                swaps.append(args)
            return self.run_ok(*args, **kwargs)

        with (patch.object(self.m, 'require_node'),
              patch.object(self.m, 'prepare', return_value=True),
              patch.object(self.m, 'download', return_value='dummy'),
              patch.object(self.m, 'parse_networks', return_value=updated),
              patch.object(self.m, 'restore_cached', return_value=[self.nets[0]]),
              patch.object(self.m, 'live_block_set', side_effect=lambda: next(block_calls)),
              patch.object(self.m, 'ipset_stage'),
              patch.object(self.m, 'atomic', side_effect=fake_atomic),
              patch.object(self.m, 'run', side_effect=fake_run),
              patch.object(self.m, 'check_ufw_jump')):
            with self.assertRaises(OSError):
                self.m.update()
        self.assertEqual(len(swaps), 2)
        self.assertEqual(self.m.CACHE.read_text(), self.nets[0] + '\n')
        self.assertEqual(self.m.CHECKED.read_text(), checkpoint)
        self.assertTrue(failure[0])

    def test_update_rollback_failure_is_explicit(self):
        self.m.UFW_FILE.write_text(self.base + self.m.BEGIN)
        self.m.CACHE.write_text(self.nets[0] + '\n')
        self.m.CHECKED.write_text(json.dumps(stamp([self.nets[0]])))
        count = [0]

        def fake_run(*args, **kwargs):
            if args[:2] == ('ipset', 'swap'):
                count[0] += 1
                if count[0] == 2:
                    raise self.m.GuardError('ROLLBACK_SWAP_FAILED')
            return ''

        with (patch.object(self.m, 'require_node'), patch.object(self.m, 'prepare', return_value=True),
              patch.object(self.m, 'download', return_value='dummy'),
              patch.object(self.m, 'parse_networks', return_value=self.nets),
              patch.object(self.m, 'restore_cached', return_value=[self.nets[0]]),
              patch.object(self.m, 'live_block_set', return_value=[self.nets[0]]),
              patch.object(self.m, 'ipset_stage'),
              patch.object(self.m, 'run', side_effect=fake_run),
              patch.object(self.m, 'atomic', side_effect=OSError('disk full'))):
            with self.assertRaisesRegex(self.m.GuardError, 'ROLLBACK_UNCONFIRMED'):
                self.m.update()
        self.assertEqual(count[0], 2)


class NightlyFaultRegression259(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vk259-night-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.m = module('VK_NIGHT_MAINT_PY')
        self.m.STATE = self.root
        self.m.RESULT = self.root / 'maintenance-last.json'
        self.m.LOCK = self.root / 'installer.lock'
        (self.root / 'INSTALL_COMPLETE').write_text('done\n')
        self.now = dt.datetime(2026, 10, 15, 0, 20, tzinfo=dt.timezone.utc)

    def test_absent_state_is_only_valid_never(self):
        self.assertEqual(self.m.last_result(), {})

    def test_corrupt_state_prevents_second_restart_and_reports_invalid(self):
        for text in ('{broken', '[]', '{}', '{"moscow_date":"2026-10-15"}',
                     '{"moscow_date":"nonsense","status":"STARTED"}'):
            with self.subTest(data=text):
                self.m.RESULT.write_text(text)
                with self.assertRaises(self.m.MaintenanceError):
                    self.m.last_result()
                if self.m.LOCK.exists():
                    self.m.LOCK.unlink()
                events = []
                with (patch.object(self.m, 'call', side_effect=lambda args, **kw: events.append(args) or ''),
                      contextlib.redirect_stdout(io.StringIO())):
                    with self.assertRaises(self.m.MaintenanceError):
                        self.m.do_run(self.now)
                self.assertFalse(any('restart' in a for a in events))
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(self.m.main(['status']), 1)
                self.assertIn('MAINTENANCE_LAST_STATUS=INVALID', out.getvalue())

    def test_marker_symlink_fails_closed(self):
        target = self.root / 'foreign.json'
        target.write_text('not-ours')
        self.m.RESULT.symlink_to(target)
        with self.assertRaisesRegex(self.m.MaintenanceError, 'SYMLINK'):
            self.m.last_result()
        self.assertEqual(target.read_text(), 'not-ours')

    def test_failed_postrestart_inspect_never_reports_success(self):
        observations = iter([True, False])
        calls = []

        def fake_call(args, timeout=None):
            calls.append(args)
            return ''
        out = io.StringIO()
        with (patch.object(self.m, 'local_node_running', side_effect=lambda: next(observations)),
              patch.object(self.m, 'call', side_effect=fake_call),
              contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO())):
            self.assertEqual(self.m.do_run(self.now), 1)
        self.assertEqual(sum(1 for a in calls if 'restart' in a), 1)
        self.assertTrue(self.m.last_result()['status'].startswith('FAIL_'))
        self.assertNotIn('MAINTENANCE=PASS', out.getvalue())
        if self.m.LOCK.exists():
            self.m.LOCK.unlink()
        with (patch.object(self.m, 'call', side_effect=fake_call),
              patch.object(self.m, 'local_node_running', side_effect=AssertionError('repeat was not skipped')),
              contextlib.redirect_stdout(io.StringIO())):
            self.assertEqual(self.m.do_run(self.now), 0)
        self.assertEqual(sum(1 for a in calls if 'restart' in a), 1)

    def test_disable_is_serialized_with_common_installer_lock(self):
        function = 'vkarmani_maintenance_command() {' + SCRIPT.split('vkarmani_maintenance_command() {', 1)[1].split('vkarmani_main() {', 1)[0]
        self.assertLess(function.index('flock -n 8'), function.index('systemctl disable --now vkarmani-node-nightly.timer'))
        locked = self.root / 'installer.lock'
        function = function.replace('/run/lock/vkarmani-node-installer.lock', str(locked))
        function = function.replace('install -d -m 0755 /run/lock', 'install -d -m 0755 "' + str(self.root) + '"')
        # Hold lock through the child process; a correct disable must not call systemctl.
        import fcntl
        with locked.open('w') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            text = 'set -Eeuo pipefail\n' + function + '\nsystemctl(){ echo CALLED; }\nvkarmani_maintenance_command disable\n'
            p = subprocess.run(['bash', '-c', text], capture_output=True, text=True, timeout=5)
            self.assertNotIn('CALLED', p.stdout)
            self.assertNotEqual(p.returncode, 0)


class ReleaseValidation259(unittest.TestCase):
    def test_nfd_alias_path_rejected(self):
        from scripts import verify_release
        with self.assertRaises(ValueError):
            verify_release.verify_name('docs/cafe\u0301.txt')
        self.assertEqual(verify_release.verify_name('docs/caf\u00e9.txt'), 'docs/caf\u00e9.txt')

    def test_standalone_modules_identical_to_installed_payloads(self):
        for tag, path in (('VK_RKN_GUARD_PY', 'integrations/rkn_guard.py'),
                          ('VK_NIGHT_MAINT_PY', 'integrations/nightly_maintenance.py'),
                          ('VK_FINALIZER_PY', 'integrations/finalize_install.py')):
            with self.subTest(tag=tag):
                self.assertEqual(payload(tag), (ROOT / path).read_text())


if __name__ == '__main__':
    unittest.main()
