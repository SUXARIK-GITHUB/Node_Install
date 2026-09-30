"""Docker remains a mocked boundary; transaction files and failures are real."""
import json
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import test_maintenance as fixture

class UpdateFaultTests(unittest.TestCase):
    setUp = fixture.MaintenanceTests.setUp
    compose_config = fixture.MaintenanceTests.compose_config
    fake_run = fixture.MaintenanceTests.fake_run
    fake_container = fixture.MaintenanceTests.fake_container
    fake_up = fixture.MaintenanceTests.fake_up
    fake_health = fixture.MaintenanceTests.fake_health
    fake_docker = fixture.MaintenanceTests.fake_docker

    def test_compose_timeout_keeps_pending_and_does_not_race_rollback(self):
        with self.fake_docker(), patch.object(self.helper, 'compose_up', side_effect=self.helper.Failure('COMMAND_TIMEOUT: docker')) as up:
            with self.assertRaises(self.helper.Failure):
                self.helper.refresh(self.config, None)
        self.assertEqual(up.call_count, 1)
        self.assertTrue((self.helper.STATE / 'image-update-pending').exists())
        self.assertEqual(self.helper.COMPOSE.read_text(), fixture.COMPOSE.replace(fixture.OLD, fixture.NEW))
        self.assertEqual((self.helper.STATE / 'image-digest').read_text().strip(), fixture.OLD)
        self.assertFalse((self.helper.STATE / 'last-image-transaction').exists())

    def test_interrupted_compose_keeps_recovery_marker(self):
        with self.fake_docker(), patch.object(self.helper, 'compose_up', side_effect=self.helper.Failure('INTERRUPTED signal=15')) as up:
            with self.assertRaises(self.helper.Failure):
                self.helper.refresh(self.config, None)
        self.assertEqual(up.call_count, 1)
        self.assertTrue((self.helper.STATE / 'image-update-pending').exists())

    def test_registry_failure_leaves_running_config_untouched(self):
        original_run = self.fake_run
        def fail_pull(args, timeout=60):
            if args[:2] == ['docker', 'pull']:
                raise self.helper.Failure('COMMAND_FAILED: docker rc=1')
            return original_run(args, timeout)
        with self.fake_docker(), patch.object(self.helper, 'run', fail_pull):
            with self.assertRaises(self.helper.Failure):
                self.helper.refresh(self.config, None)
        self.assertEqual(self.helper.COMPOSE.read_text(), fixture.COMPOSE)
        self.assertFalse((self.helper.STATE / 'image-update-pending').exists())
        self.assertEqual(self.applied, [])

    def test_low_disk_refuses_before_mutation(self):
        with self.fake_docker(), patch.object(self.helper.shutil, 'disk_usage', return_value=SimpleNamespace(free=10)):
            with self.assertRaisesRegex(self.helper.Failure, 'FREE_DISK'):
                self.helper.refresh(self.config, None)
        self.assertEqual(self.helper.COMPOSE.read_text(), fixture.COMPOSE)
        self.assertEqual(self.applied, [])

    def test_commit_disk_error_restores_previous_and_reports_failure(self):
        original_atomic = self.helper.atomic
        triggered = []
        def fail_commit(path, text):
            if Path(path).name == 'COMMITTED' and not triggered:
                triggered.append(True)
                raise OSError(28, 'synthetic disk full')
            original_atomic(path, text)
        with self.fake_docker(), patch.object(self.helper, 'atomic', fail_commit):
            with self.assertRaises(OSError):
                self.helper.refresh(self.config, None)
        self.assertEqual(self.applied, [fixture.NEW, fixture.OLD])
        self.assertEqual(self.helper.COMPOSE.read_text(), fixture.COMPOSE)
        self.assertEqual((self.helper.STATE / 'image-digest').read_text().strip(), fixture.OLD)
        self.assertFalse((self.helper.STATE / 'image-update-pending').exists())

    def test_malformed_registry_json_does_not_apply_image(self):
        original_run = self.fake_run
        def malformed(args, timeout=60):
            if args[-1] == '{{json .RepoDigests}}':
                return '{not-json'
            return original_run(args, timeout)
        with self.fake_docker(), patch.object(self.helper, 'run', malformed):
            with self.assertRaises(json.JSONDecodeError):
                self.helper.refresh(self.config, None)
        self.assertEqual(self.helper.COMPOSE.read_text(), fixture.COMPOSE)
        self.assertEqual(self.applied, [])

class HealthDeadlineTests(unittest.TestCase):
    def test_all_subcommands_share_deadline(self):
        from common import module
        h = module('VK_PAYLOAD_VK_WRITE_MAINTENANCE')
        now, budgets = [0.0], []
        def clock(): return now[0]
        def sleep(value): now[0] += value
        def run(args, timeout=60):
            budgets.append(timeout)
            self.assertLessEqual(timeout, 10.0 - now[0])
            now[0] += min(1.0, timeout)
            return 'id'
        def container(timeout=60):
            budgets.append(timeout)
            self.assertLessEqual(timeout, 10.0 - now[0])
            now[0] += min(1.0, timeout)
            return {'Image': 'id', 'Id': 'same', 'RestartCount': 0, 'State': {'Running': True}}
        with patch.object(h.time, 'monotonic', clock), patch.object(h.time, 'sleep', sleep), patch.object(h, 'run', run), patch.object(h, 'container', container):
            h.healthy({}, False, fixture.OLD, wait=10)
        self.assertEqual(now[0], 10.0)
        self.assertTrue(budgets)

    def test_failed_readiness_cannot_sleep_beyond_total_deadline(self):
        from common import module
        h = module('VK_PAYLOAD_VK_WRITE_MAINTENANCE')
        now = [0.0]
        with patch.object(h.time, 'monotonic', lambda: now[0]), patch.object(h.time, 'sleep', lambda value: now.__setitem__(0, now[0]+value)), patch.object(h, 'run', return_value='id'), patch.object(h, 'container', side_effect=h.Failure('MOCK_DAEMON_NOT_READY')):
            with self.assertRaisesRegex(h.Failure, 'NODE_READINESS_FAILED'):
                h.healthy({}, False, fixture.OLD, wait=3)
        self.assertEqual(now[0], 3)
