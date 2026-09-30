"""Actual embedded time helper, synthetic dpkg/DBus replies, no host NTP changes."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from common import SCRIPT, module, payload, template


def row(name, status='install ok installed', provides='time-daemon'):
    return f'{name}\t{status}\t{provides}'


class TimeProviderTests(unittest.TestCase):
    def setUp(self):
        self.m = module('PY_TIME_HELPER')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.etc = self.root / 'etc'
        self.state = self.root / 'state'
        self.etc.mkdir(mode=0o700)
        self.state.mkdir(mode=0o700)
        self.marker = self.root / 'synchronized'
        self.marker.touch()

    def test_preserves_installed_timesyncd(self):
        self.assertEqual(self.m.installed_provider(row('systemd-timesyncd')), 'systemd-timesyncd')

    def test_preserves_installed_chrony(self):
        self.assertEqual(self.m.installed_provider(row('chrony')), 'chrony')

    def test_held_installed_provider_is_recognized(self):
        self.assertEqual(self.m.installed_provider(row('systemd-timesyncd', 'hold ok installed')), 'systemd-timesyncd')

    def test_arch_qualified_provider_is_recognized(self):
        self.assertEqual(self.m.installed_provider(row('chrony:amd64')), 'chrony')

    def test_default_without_time_daemon_is_chrony(self):
        with patch.object(self.m, 'run', return_value=row('bash', provides='')):
            self.assertEqual(self.m.select_provider(self.etc), 'chrony')

    def test_removed_configuration_does_not_select_daemon(self):
        self.assertIsNone(self.m.installed_provider(row('chrony', 'deinstall ok config-files')))

    def test_config_remnants_can_coexist_with_installed_provider(self):
        text = row('chrony', 'deinstall ok config-files') + '\n' + row('systemd-timesyncd')
        self.assertEqual(self.m.installed_provider(text), 'systemd-timesyncd')

    def test_unknown_time_daemon_is_refused(self):
        with self.assertRaisesRegex(self.m.Failure, 'UNSUPPORTED'):
            self.m.installed_provider(row('custom-clock', provides='other-api, time-daemon (= 1)'))

    def test_other_known_ntp_client_is_refused(self):
        with self.assertRaisesRegex(self.m.Failure, 'UNSUPPORTED'):
            self.m.installed_provider(row('ntpsec'))

    def test_two_installed_daemons_are_refused(self):
        with self.assertRaisesRegex(self.m.Failure, 'MULTIPLE'):
            self.m.installed_provider(row('chrony') + '\n' + row('systemd-timesyncd'))

    def test_duplicate_package_is_refused(self):
        with self.assertRaisesRegex(self.m.Failure, 'DUPLICATE'):
            self.m.installed_provider(row('chrony') + '\n' + row('chrony'))

    def test_half_configured_daemon_is_refused(self):
        with self.assertRaisesRegex(self.m.Failure, 'INCOMPLETE'):
            self.m.installed_provider(row('systemd-timesyncd', 'install ok half-configured'))

    def test_dpkg_failure_is_not_no_provider(self):
        with patch.object(self.m, 'run', side_effect=self.m.Failure('READ_FAILED')):
            with self.assertRaises(self.m.Failure):
                self.m.select_provider(self.etc)

    def test_empty_dpkg_reply_is_refused(self):
        with self.assertRaisesRegex(self.m.Failure, 'EMPTY'):
            self.m.installed_provider('')

    def test_malformed_dpkg_reply_is_refused(self):
        with self.assertRaisesRegex(self.m.Failure, 'INVALID_DPKG'):
            self.m.installed_provider('systemd-timesyncd installed')

    def test_saved_provider_written_privately_and_loads(self):
        self.m.save_provider('systemd-timesyncd', self.etc)
        self.assertEqual(self.m.saved_provider(self.etc, self.state), 'systemd-timesyncd')
        self.assertEqual((self.etc / 'time-provider').stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.etc.glob('.time-provider-*')), [])

    def test_provider_drift_is_refused(self):
        self.m.save_provider('chrony', self.etc)
        with patch.object(self.m, 'run', return_value=row('systemd-timesyncd')):
            with self.assertRaisesRegex(self.m.Failure, 'DRIFT'):
                self.m.select_provider(self.etc)

    def test_removed_saved_provider_is_not_silently_reinstalled(self):
        self.m.save_provider('chrony', self.etc)
        with patch.object(self.m, 'run', return_value=row('bash', provides='')):
            with self.assertRaisesRegex(self.m.Failure, 'DRIFT'):
                self.m.select_provider(self.etc)

    def test_invalid_saved_provider_is_refused(self):
        p = self.etc / 'time-provider'
        p.write_text('ntpsec\n')
        p.chmod(0o600)
        with self.assertRaisesRegex(self.m.Failure, 'INVALID_TIME_PROVIDER'):
            self.m.saved_provider(self.etc, self.state)

    def test_saved_provider_symlink_is_refused(self):
        target = self.root / 'target'
        target.write_text('chrony\n')
        target.chmod(0o600)
        (self.etc / 'time-provider').symlink_to(target)
        with self.assertRaisesRegex(self.m.Failure, 'UNSAFE'):
            self.m.saved_provider(self.etc, self.state)

    def test_world_readable_saved_provider_is_refused(self):
        self.m.save_provider('chrony', self.etc)
        (self.etc / 'time-provider').chmod(0o644)
        with self.assertRaisesRegex(self.m.Failure, 'UNSAFE'):
            self.m.saved_provider(self.etc, self.state)

    def test_missing_marker_is_error_for_new_version(self):
        (self.state / 'install-version').write_text('2.0.3\n')
        with self.assertRaisesRegex(self.m.Failure, 'NOT_SAVED'):
            self.m.saved_provider(self.etc, self.state)

    def test_existing_legacy_repair_retains_chrony(self):
        (self.state / 'INSTALL_COMPLETE').write_text('version=1.3.5\n')
        self.assertEqual(self.m.saved_provider(self.etc, self.state), 'chrony')

    def test_atomic_write_failure_preserves_previous_provider(self):
        self.m.save_provider('chrony', self.etc)
        with patch.object(self.m.os, 'replace', side_effect=OSError('injected ENOSPC')):
            with self.assertRaises(OSError):
                self.m.save_provider('systemd-timesyncd', self.etc)
        self.assertEqual(self.m.saved_provider(self.etc, self.state), 'chrony')
        self.assertEqual(list(self.etc.glob('.time-provider-*')), [])

    def timesyncd(self, synced='yes', address='192.0.2.123', failed=None):
        def run(args, deadline):
            if failed and args[0] == failed:
                raise self.m.Failure('INJECTED_COMMAND_FAILURE')
            if args[0] == 'systemctl':
                return ''
            if args[1] == 'show':
                return synced
            if args[1] == 'show-timesync':
                return address
            raise AssertionError(args)
        return run

    def probe(self):
        self.m.probe('systemd-timesyncd', self.m.time.monotonic() + 15, self.marker)

    def test_timesyncd_requires_actual_three_part_sync_evidence(self):
        with patch.object(self.m, 'run', side_effect=self.timesyncd()):
            self.probe()

    def test_timesyncd_active_without_clock_sync_fails(self):
        with patch.object(self.m, 'run', side_effect=self.timesyncd(synced='no')):
            with self.assertRaisesRegex(self.m.Failure, 'CLOCK_NOT'):
                self.probe()

    def test_timesyncd_inactive_fails(self):
        with patch.object(self.m, 'run', side_effect=self.timesyncd(failed='systemctl')):
            with self.assertRaises(self.m.Failure):
                self.probe()

    def test_timesyncd_dbus_error_fails(self):
        with patch.object(self.m, 'run', side_effect=self.timesyncd(failed='timedatectl')):
            with self.assertRaises(self.m.Failure):
                self.probe()

    def test_timesyncd_no_selected_server_fails(self):
        with patch.object(self.m, 'run', side_effect=self.timesyncd(address='')):
            with self.assertRaisesRegex(self.m.Failure, 'NO_IPV4'):
                self.probe()

    def test_timesyncd_ipv6_source_is_rejected(self):
        with patch.object(self.m, 'run', side_effect=self.timesyncd(address='2001:db8::123')):
            with self.assertRaisesRegex(self.m.Failure, 'NO_IPV4'):
                self.probe()

    def test_timesyncd_without_successful_packet_marker_fails(self):
        self.marker.unlink()
        with patch.object(self.m, 'run', side_effect=self.timesyncd()):
            with self.assertRaisesRegex(self.m.Failure, 'NO_SUCCESSFUL'):
                self.probe()

    def test_timesyncd_marker_symlink_is_rejected(self):
        self.marker.unlink()
        target = self.root / 'target'
        target.touch()
        self.marker.symlink_to(target)
        with patch.object(self.m, 'run', side_effect=self.timesyncd()):
            with self.assertRaisesRegex(self.m.Failure, 'INVALID_SYNC_MARKER'):
                self.probe()

    def test_chrony_sync_success_uses_original_correction_threshold(self):
        def run(args, deadline):
            if 'waitsync' in args:
                self.assertEqual(args[-4:], ['1', '0.1', '0.0', '1'])
            return 'Leap status     : Normal' if 'tracking' in args else ''
        with patch.object(self.m, 'run', side_effect=run):
            self.m.probe('chrony', self.m.time.monotonic() + 15)

    def test_chrony_abnormal_leap_fails(self):
        with patch.object(self.m, 'run', return_value='Leap status : Not synchronised'):
            with self.assertRaisesRegex(self.m.Failure, 'CHRONY_NOT'):
                self.m.probe('chrony', self.m.time.monotonic() + 15)

    def test_wait_retries_then_succeeds(self):
        clock = [0.0]
        with patch.object(self.m.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(self.m.time, 'sleep', side_effect=lambda sec: clock.__setitem__(0, clock[0] + sec)), \
             patch.object(self.m, 'probe', side_effect=[self.m.Failure('not yet'), None]) as p:
            self.m.wait_sync('systemd-timesyncd', 5, self.marker)
            self.assertEqual(p.call_count, 2)
            self.assertEqual(clock[0], 2)

    def test_wait_deadline_is_total_not_per_attempt(self):
        clock = [0.0]
        with patch.object(self.m.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(self.m.time, 'sleep', side_effect=lambda sec: clock.__setitem__(0, clock[0] + sec)), \
             patch.object(self.m, 'probe', side_effect=self.m.Failure('NTP blocked')):
            with self.assertRaisesRegex(self.m.Failure, 'NTP_SYNC_TIMEOUT'):
                self.m.wait_sync('systemd-timesyncd', 5, self.marker)
            self.assertEqual(clock[0], 5)

    def test_invalid_wait_budget_fails(self):
        for seconds in (0, -1, 121):
            with self.subTest(seconds=seconds), self.assertRaises(self.m.Failure):
                self.m.wait_sync('chrony', seconds)

    def test_command_timeout_is_not_success(self):
        with patch.object(self.m.subprocess, 'run', side_effect=subprocess.TimeoutExpired('timedatectl', 1)):
            with self.assertRaisesRegex(self.m.Failure, 'TIMEOUT'):
                self.m.run(['timedatectl', 'show'], self.m.time.monotonic() + 1)

    def test_expired_deadline_never_starts_command(self):
        with patch.object(self.m.subprocess, 'run') as p:
            with self.assertRaisesRegex(self.m.Failure, 'DEADLINE'):
                self.m.run(['systemctl'], self.m.time.monotonic() - 1)
            p.assert_not_called()

    def test_readiness_and_postboot_use_selected_provider(self):
        acceptance = payload('VK_PAYLOAD_VK_WRITE_ACCEPTANCE')
        self.assertIn('"$TIME_HELPER" provider', acceptance)
        self.assertIn('fail2ban "$TIME_SERVICE" ufw', acceptance)
        self.assertIn('"$TIME_HELPER" check', acceptance)
        unit = template('/etc/systemd/system/vkarmani-node-postboot.service')
        self.assertEqual(unit.count('${TIME_SERVICE}.service'), 2)
        self.assertNotIn('chrony.service', unit)

    def test_native_ntp_sources_are_not_overwritten(self):
        body = SCRIPT.split("# Keep the distro/provider's NTP sources.", 1)[1].split("stage 'IPv4-only", 1)[0]
        self.assertNotIn('cat > /etc/systemd/timesyncd.conf', body)
        self.assertIn('RestrictAddressFamilies=\nRestrictAddressFamilies=AF_UNIX AF_INET', body)
        self.assertNotIn('unmask', body)
        self.assertNotIn('set-ntp', body)

    def test_backup_contains_native_configuration_and_old_state(self):
        self.assertIn('etc/systemd/timesyncd.conf etc/systemd/timesyncd.conf.d', SCRIPT)
        self.assertIn('var/lib/vkarmani-node/install-version', SCRIPT)
        self.assertIn("'etc/systemd/timesyncd.conf', 'etc/systemd/timesyncd.conf.d'", SCRIPT)


class VersionScopeTests(unittest.TestCase):
    def test_version_bump_does_not_rewrite_ipv4_literals(self):
        start = SCRIPT.index('vk_input_error()')
        end = SCRIPT.index('\n}\n', SCRIPT.index('vk_collect_inputs()')) + 3
        code = SCRIPT[start:end] + '\nvk_validate_ipv4 "$1"\n'
        for address, expected in [('192.0.2.1', 1), ('192.0.3.1', 0), ('203.0.113.1', 1)]:
            with self.subTest(address=address):
                p = subprocess.run(['bash', '-c', code, '_', address], capture_output=True, timeout=5)
                self.assertEqual(p.returncode, expected)


if __name__ == '__main__':
    unittest.main()
