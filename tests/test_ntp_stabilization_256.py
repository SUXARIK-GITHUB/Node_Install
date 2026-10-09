"""Reproduce the VPS final-acceptance race using the REAL embedded NTP helper."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from common import module, payload, SCRIPT


STATE_A = 'ActiveState=active\nSubState=running\nInvocationID=' + 'a' * 32
STATE_B = 'ActiveState=active\nSubState=running\nInvocationID=' + 'b' * 32
REPLY = '{ Leap=0, Version=4, Mode=4, Stratum=2, Ignored=no, PacketCount=3 }'


class Ntp256Tests(unittest.TestCase):
    def setUp(self):
        self.m = module('PY_TIME_HELPER')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.marker = Path(self.tmp.name) / 'synchronized'
        self.marker.touch()

    def reply_runner(self, reply=REPLY, states=None, address='192.0.2.123', synced='yes'):
        states = iter(states) if states else None
        def run(args, deadline):
            if args[:2] == ['systemctl', 'show']:
                return next(states) if states else STATE_A
            if '--property=NTPSynchronized' in args:
                return synced
            if '--property=ServerAddress' in args:
                return address
            if '--property=NTPMessage' in args:
                return reply
            if args[:2] == ['systemctl', 'is-active']:
                return ''
            raise AssertionError(args)
        return run

    def probe(self, **kwargs):
        with patch.object(self.m, 'run', side_effect=self.reply_runner(**kwargs)):
            return self.m.probe('systemd-timesyncd', self.m.time.monotonic()+15, self.marker)

    def test_current_invocation_and_actual_reply_pass(self):
        self.assertEqual(self.probe(), ('a'*32, '192.0.2.123'))

    def test_old_marker_and_synced_flag_without_new_reply_do_not_pass(self):
        for bad in (REPLY.replace('PacketCount=3', 'PacketCount=0'),
                    REPLY.replace('Ignored=no', 'Ignored=yes'),
                    REPLY.replace('Leap=0', 'Leap=3'),
                    REPLY.replace('Mode=4', 'Mode=3'),
                    REPLY.replace('Stratum=2', 'Stratum=0'),
                    REPLY.replace('Stratum=2', 'Stratum=16')):
            with self.subTest(bad=bad), self.assertRaisesRegex(self.m.Failure, 'NO_ACCEPTED'):
                self.probe(reply=bad)

    def test_missing_or_duplicate_reply_fields_refused(self):
        for bad in ('', '{}', REPLY.replace('PacketCount=3', ''),
                    REPLY.replace('PacketCount=3', 'PacketCount=3, PacketCount=4'),
                    REPLY.replace('PacketCount=3', 'PacketCount=bad')):
            with self.subTest(bad=bad), self.assertRaisesRegex(self.m.Failure, 'MESSAGE_INVALID'):
                self.probe(reply=bad)

    def test_healthy_leap_second_indicators_not_misclassified(self):
        for leap in ('1', '2'):
            self.probe(reply=REPLY.replace('Leap=0', 'Leap='+leap))

    def test_restart_during_probe_refused(self):
        with self.assertRaisesRegex(self.m.Failure, 'CHANGED_DURING_PROBE'):
            self.probe(states=[STATE_A, STATE_B])

    def test_inactive_service_not_green_from_old_clock_state(self):
        with self.assertRaisesRegex(self.m.Failure, 'NOT_READY'):
            self.probe(states=[STATE_A.replace('active', 'inactive')])

    def test_invalid_invocation_never_accepted(self):
        for bad in ('', '0'*32, 'secret-not-a-systemd-id'):
            with self.subTest(bad=bad), self.assertRaises(self.m.Failure):
                self.probe(states=[STATE_A.replace('a'*32,bad)])

    def fake_wait(self, failures, seconds=120, stable=2):
        clock = [0.0]
        def probe(*args):
            return failures(clock[0])
        with patch.object(self.m.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(self.m.time, 'sleep', side_effect=lambda t: clock.__setitem__(0, clock[0]+t)), \
             patch.object(self.m, 'probe', side_effect=probe):
            self.m.wait_sync('systemd-timesyncd', seconds, self.marker, stable_samples=stable)
        return clock[0]

    def test_reported_timeline_21s_check_31s_sync_recovers(self):
        # Service restarted t=0; old final check at t=21; first reply at t=31.
        def timeline(elapsed):
            if elapsed < 10:
                raise self.m.Failure('TIMESYNCD_NO_IPV4_TIME_SOURCE')
            return ('a'*32, '192.0.2.123')
        self.assertEqual(self.fake_wait(timeline), 12)

    def test_stability_counter_resets_on_source_or_invocation_change(self):
        samples = iter([('a', '192.0.2.1'), ('b', '192.0.2.1'), ('b', '192.0.2.2'), ('b', '192.0.2.2')])
        self.assertEqual(self.fake_wait(lambda _: next(samples)), 6)

    def test_stability_counter_resets_on_failure(self):
        samples = iter([('a','ip'), None, ('a','ip'), ('a','ip')])
        def sequence(_):
            value=next(samples)
            if value is None:
                raise self.m.Failure('TIME_SERVICE_NOT_READY')
            return value
        self.assertEqual(self.fake_wait(sequence), 6)

    def test_real_outage_is_bounded_and_fails(self):
        def fail(_):
            raise self.m.Failure('TIMESYNCD_NO_IPV4_TIME_SOURCE')
        with self.assertRaisesRegex(self.m.Failure, 'NTP_SYNC_TIMEOUT: TIMESYNCD_NO_IPV4'):
            self.fake_wait(fail, seconds=120)

    def test_permanent_ipv6_does_not_bypass_policy(self):
        with self.assertRaisesRegex(self.m.Failure, 'NO_IPV4'):
            self.probe(address='2001:db8::123')

    def test_deadline_cannot_be_extended_by_repeated_restarts(self):
        with self.assertRaisesRegex(self.m.Failure, 'NTP_SYNC_TIMEOUT'):
            self.fake_wait(lambda t: (str(t), '192.0.2.1'), seconds=5)

    def test_invalid_stability_parameter_rejected(self):
        for value in (0, 4, True, '2'):
            with self.subTest(value=value), self.assertRaises(self.m.Failure):
                self.m.wait_sync('chrony', 120, stable_samples=value)

    def test_acceptance_calls_bounded_wait_once_and_propagates_failure(self):
        code = payload('VK_PAYLOAD_VK_WRITE_ACCEPTANCE')
        section = code.split('case "$MODE" in --preboot|--postboot)',1)[1].split('if [[ $(docker inspect',1)[0]
        section = 'case "$MODE" in --preboot|--postboot)' + section
        shell = '''MODE=$1; TIME_SERVICE=systemd-timesyncd; TIME_HELPER=fixture
python3() { printf 'WAIT_ARGS=%s\\n' "$*"; return "$MOCK_RC"; }
systemctl() { return 0; }
pass() { echo "PASS=$1"; }
fail() { echo "FAIL=$1"; F=1; }
F=0
''' + section + '\nexit "$F"\n'
        for mode, timeout in (('--preboot','120'),('--postboot','120'),('--normal','35'),('--require-xray','35')):
            for rc in (0,1):
                with self.subTest(mode=mode,rc=rc):
                    import os
                    p=subprocess.run(['bash','-c',shell,'_',mode],env={**os.environ,'MOCK_RC':str(rc)},capture_output=True,text=True,timeout=3)
                    self.assertEqual(p.returncode,rc,p.stderr)
                    self.assertIn('wait --seconds '+timeout+' --stable-samples 2',p.stdout)
                    self.assertEqual('PASS=NTP_SYNC' in p.stdout,rc==0)
                    self.assertEqual('FAIL=NTP_SYNC' in p.stdout,rc==1)

    def test_no_time_source_replacement_or_update_disabling_added(self):
        ntp = payload('PY_TIME_HELPER')
        for forbidden in ('set-ntp', 'systemctl restart', 'systemctl stop', 'timedatectl set-time'):
            self.assertNotIn(forbidden,ntp)
        self.assertNotIn('185.125.190.57',ntp)
        self.assertIn('NEEDRESTART_MODE=l',SCRIPT)


if __name__ == '__main__':
    unittest.main()
