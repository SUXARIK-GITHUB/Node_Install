"""r39: reliable timesyncd acceptance after daemon restart and ignored latest spike.

Read-only mocked VPS tests. These do NOT modify host time, services or clocks.
"""
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from common import module


class Marker:
    def __init__(self, when, owner=0, mode=0o644):
        self.when, self.owner, self.mode = when, owner, mode

    def lstat(self):
        return SimpleNamespace(st_uid=self.owner, st_mode=stat.S_IFREG | self.mode,
                               st_mtime=self.when)


class NtpRestartRecoveryTests(unittest.TestCase):
    NOW_MONO = 500.0
    NOW_WALL = 1000.0
    INV_A = 'a' * 32
    INV_B = 'b' * 32
    REPLY_SPIKE = '{ Leap=0, Version=4, Mode=4, Stratum=2, Ignored=yes, PacketCount=4 }'
    REPLY_OK = REPLY_SPIKE.replace('Ignored=yes', 'Ignored=no')

    def setUp(self):
        self.m = module('PY_TIME_HELPER')

    def runner(self, reply=None, start='450000000', synced='yes', address='192.0.2.53',
               invocation=None, restart=False):
        hits = [0]
        def run(args, deadline):
            if args[:2] == ['systemctl', 'is-active']:
                return ''
            if args[:2] == ['systemctl', 'show']:
                if '--property=ExecMainStartTimestampMonotonic' in args:
                    return start
                hits[0] += 1
                ident = self.INV_B if restart and hits[0] >= 2 else (invocation or self.INV_A)
                return f'ActiveState=active\nSubState=running\nInvocationID={ident}'
            if '--property=NTPSynchronized' in args:
                return synced
            if '--property=ServerAddress' in args:
                return address
            if '--property=NTPMessage' in args:
                return reply or self.REPLY_SPIKE
            raise AssertionError(args)
        return run

    def probe(self, marker=None, **kwargs):
        marker = marker or Marker(self.NOW_WALL - 20)
        with patch.object(self.m.time, 'monotonic', return_value=self.NOW_MONO), \
             patch.object(self.m.time, 'time', return_value=self.NOW_WALL), \
             patch.object(self.m, 'run', side_effect=self.runner(**kwargs)):
            return self.m.probe('systemd-timesyncd', self.NOW_MONO + 15, marker)

    def test_latest_ignored_spike_after_current_invocation_sync_passes(self):
        self.assertEqual(self.probe(), (self.INV_A, '192.0.2.53'))

    def test_nonignored_last_packet_works_as_before(self):
        self.assertEqual(self.probe(reply=self.REPLY_OK, marker=Marker(1.0)),
                         (self.INV_A, '192.0.2.53'))

    def test_previous_invocation_marker_is_not_trusted(self):
        # Service only started 10 seconds ago but last sync was 20 seconds ago.
        with self.assertRaisesRegex(self.m.Failure, 'NO_CURRENT_INVOCATION_SYNC'):
            self.probe(start='490000000')

    def test_marker_near_daemon_start_is_not_sufficient(self):
        with self.assertRaisesRegex(self.m.Failure, 'NO_CURRENT_INVOCATION_SYNC'):
            self.probe(start='480500000')  # Marker monotonic at ~480 s.

    def test_old_marker_does_not_mask_an_outage(self):
        with self.assertRaisesRegex(self.m.Failure, 'NO_CURRENT_INVOCATION_SYNC'):
            self.probe(start='1000000', marker=Marker(self.NOW_WALL - 7201))

    def test_future_marker_clock_jump_is_not_success(self):
        with self.assertRaisesRegex(self.m.Failure, 'NO_CURRENT_INVOCATION_SYNC'):
            self.probe(marker=Marker(self.NOW_WALL + 10))

    def test_untrusted_owner_and_permissions_are_rejected(self):
        for marker in (Marker(980, owner=1001), Marker(980, mode=0o666)):
            with self.subTest(marker=marker), self.assertRaisesRegex(self.m.Failure, 'MARKER_UNTRUSTED'):
                self.probe(marker=marker)

    def test_service_user_owned_marker_is_legitimate(self):
        with patch.object(self.m.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=996)) as user:
            self.assertEqual(self.probe(marker=Marker(980, owner=996)),
                             (self.INV_A, '192.0.2.53'))
            user.assert_called_with('systemd-timesync')

    def test_missing_service_account_does_not_accept_unknown_owner(self):
        with patch.object(self.m.pwd, 'getpwnam', side_effect=KeyError('no account')):
            with self.assertRaisesRegex(self.m.Failure, 'MARKER_UNTRUSTED'):
                self.probe(marker=Marker(980, owner=996))

    def test_invalid_daemon_start_is_not_accepted(self):
        for start in ('', '0', 'bad', '-1', '9999999999'):
            with self.subTest(start=start), self.assertRaisesRegex(self.m.Failure,
                                                                  'SERVICE_START_UNVERIFIED|NO_CURRENT_INVOCATION_SYNC'):
                self.probe(start=start)

    def test_clock_sync_flag_is_required_even_with_current_marker(self):
        with self.assertRaisesRegex(self.m.Failure, 'CLOCK_NOT_SYNCHRONIZED'):
            self.probe(synced='no')

    def test_last_packet_must_be_valid_even_with_current_marker(self):
        invalid = [self.REPLY_SPIKE.replace('PacketCount=4', 'PacketCount=0'),
                   self.REPLY_SPIKE.replace('Leap=0', 'Leap=3'),
                   self.REPLY_SPIKE.replace('Mode=4', 'Mode=3'),
                   self.REPLY_SPIKE.replace('Stratum=2', 'Stratum=16')]
        for reply in invalid:
            with self.subTest(reply=reply), self.assertRaisesRegex(self.m.Failure, 'NO_ACCEPTED'):
                self.probe(reply=reply)

    def test_restart_in_middle_of_probe_is_detected(self):
        with self.assertRaisesRegex(self.m.Failure, 'CHANGED_DURING_PROBE'):
            self.probe(restart=True)

    def test_non_ipv4_source_still_rejected(self):
        with self.assertRaisesRegex(self.m.Failure, 'NO_IPV4'):
            self.probe(address='2001:db8::1')

    def test_no_time_daemon_commands_are_mutated_by_new_check(self):
        from common import payload
        helper = payload('PY_TIME_HELPER')
        for cmd in ('systemctl restart', 'systemctl stop', 'timedatectl set-ntp', 'timedatectl set-time'):
            self.assertNotIn(cmd, helper)
        self.assertIn('accepted_sync_marker_this_invocation', helper)
        self.assertIn('ExecMainStartTimestampMonotonic', helper)


if __name__ == '__main__':
    unittest.main()
