"""Transaction tests with a fake Docker boundary. NO Docker daemon is invoked."""
import contextlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from common import module

OLD = 'remnawave/node@sha256:' + 'a' * 64
NEW = 'remnawave/node@sha256:' + 'b' * 64
COMPOSE = ('name: vkarmani-node\nservices:\n  remnanode:\n    image: ' + OLD + '\n'
           '    container_name: remnanode\n    network_mode: host\n    restart: always\n'
           '    env_file: [/etc/vkarmani-node/remnanode.env]\n')


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.helper = module('VK_PAYLOAD_VK_WRITE_MAINTENANCE')
        self.temp = tempfile.TemporaryDirectory(prefix='vk-maint-')
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        for name in ('etc', 'state', 'opt'):
            (root / name).mkdir(mode=0o700)
        self.helper.ETC, self.helper.STATE, self.helper.OPT = (root / x for x in ('etc', 'state', 'opt'))
        self.helper.COMPOSE = self.helper.OPT / 'compose.yaml'
        self.helper.atomic(self.helper.COMPOSE, COMPOSE)
        self.helper.atomic(self.helper.STATE / 'image-digest', OLD + '\n')
        self.commands, self.applied, self.health_checks = [], [], []
        self.running, self.candidate = OLD, NEW
        self.fail_new, self.fail_restore, self.new_attempted = False, False, False
        self.config = {'image': 'remnawave/node:latest', 'domain': 'node.example.test', 'public_ipv4': '8.8.4.4'}

    def compose_config(self, path):
        text = Path(path).read_text()
        return {'image': re.search(r'^    image: (.+)$', text, re.M)[1]}

    def fake_run(self, args, timeout=60):
        self.commands.append(args)
        if args[:3] == ['docker', 'image', 'inspect']:
            if args[-1] == '{{json .RepoDigests}}':
                return json.dumps([self.candidate])
            if args[-1] == '{{.Id}}':
                return args[3]
            return json.dumps([{'Id': args[3], 'Size': 300 * 1024**2}])
        if args[:2] == ['docker', 'info']:
            return str(self.helper.STATE)
        if args[:2] in (['docker', 'pull'], ['docker', 'tag']):
            return ''
        raise AssertionError('unexpected external command in mock: ' + repr(args))

    def fake_container(self):
        return {'Image': self.running, 'State': {'Running': True}}

    def fake_up(self):
        self.running = self.compose_config(self.helper.COMPOSE)['image']
        self.applied.append(self.running)
        if self.running == NEW:
            self.new_attempted = True

    def fake_health(self, config, require_xray, digest, wait=180):
        self.health_checks.append((require_xray, digest))
        if (digest == NEW and self.fail_new) or (digest == OLD and self.new_attempted and self.fail_restore):
            raise self.helper.Failure('simulated health failure')

    @contextlib.contextmanager
    def fake_docker(self):
        with contextlib.ExitStack() as stack:
            for name, value in [('run', self.fake_run), ('compose_config', self.compose_config),
                                ('container', self.fake_container), ('compose_up', self.fake_up),
                                ('healthy', self.fake_health), ('backup', lambda: self.helper.STATE / 'test-backup'),
                                ('xray_listens', lambda: True)]:
                stack.enter_context(patch.object(self.helper, name, value))
            stack.enter_context(patch.object(self.helper.shutil, 'disk_usage', return_value=SimpleNamespace(free=10 * 1024**3)))
            stack.enter_context(patch.object(self.helper.signal, 'signal'))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            yield

    def test_atomic_write_has_private_mode_and_no_temp_files(self):
        path = self.helper.ETC / 'file'
        self.helper.atomic(path, 'first')
        self.helper.atomic(path, 'second')
        self.assertEqual(path.read_text(), 'second')
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.helper.ETC.iterdir()), [path])

    def test_render_changes_exactly_one_image_and_nothing_else(self):
        result = self.helper.render_image(COMPOSE, OLD, NEW)
        self.assertEqual(result.replace(NEW, OLD), COMPOSE)
        for bad in (COMPOSE.replace(OLD, NEW), COMPOSE + '    image: ' + OLD + '\n'):
            with self.assertRaises(self.helper.Failure):
                self.helper.render_image(bad, OLD, NEW)
        with self.assertRaises(self.helper.Failure):
            self.helper.render_image(COMPOSE, OLD, 'untrusted/node:latest')

    def test_command_failures_do_not_expose_captured_secrets(self):
        secret = 'SYNTHETIC_TEST_SECRET_MUST_NOT_BE_LOGGED'
        # A real local process exercises capture/redaction without a Docker daemon.
        with self.assertRaises(self.helper.Failure) as caught:
            self.helper.run(['/bin/sh', '-c', 'printf "%s" "$1"; printf "%s" "$1" >&2; exit 1', '_', secret])
        self.assertNotIn(secret, str(caught.exception))
        self.assertIn('COMMAND_FAILED', str(caught.exception))

    def test_compose_policy_refuses_foreign_or_extra_services(self):
        valid = {'name': 'vkarmani-node', 'services': {'remnanode': {
            'image': OLD, 'network_mode': 'host', 'container_name': 'remnanode', 'restart': 'always'}}}
        with patch.object(self.helper, 'run', return_value=json.dumps(valid)):
            self.assertEqual(self.helper.compose_config(self.helper.COMPOSE)['image'], OLD)
        for change in ('name', 'services', 'network_mode'):
            obj = json.loads(json.dumps(valid))
            if change == 'name':
                obj['name'] = 'another-project'
            elif change == 'services':
                obj['services']['database'] = {}
            else:
                obj['services']['remnanode']['network_mode'] = 'bridge'
            with patch.object(self.helper, 'run', return_value=json.dumps(obj)):
                with self.assertRaises(self.helper.Failure):
                    self.helper.compose_config(self.helper.COMPOSE)

    def test_refresh_commits_only_image_and_retains_previous(self):
        with self.fake_docker():
            self.helper.refresh(self.config, None)
        self.assertEqual(self.applied, [NEW])
        self.assertEqual(self.helper.COMPOSE.read_text(), COMPOSE.replace(OLD, NEW))
        self.assertEqual((self.helper.STATE / 'image-digest').read_text().strip(), NEW)
        self.assertFalse((self.helper.STATE / 'image-update-pending').exists())
        path = Path((self.helper.STATE / 'last-image-transaction').read_text().strip())
        self.assertEqual((path / 'previous.compose.yaml').read_text(), COMPOSE)
        self.assertTrue((path / 'COMMITTED').exists())
        self.assertIn(['docker', 'tag', OLD, 'remnawave/node:vkarmani-rollback'], self.commands)
        self.assertTrue(all(cmd[0] == 'docker' for cmd in self.commands))
        self.assertTrue(all(required for required, _ in self.health_checks))

    def test_failed_candidate_rolls_back_before_returning_error(self):
        self.fail_new = True
        with self.fake_docker():
            with self.assertRaises(self.helper.Failure):
                self.helper.refresh(self.config, None)
        self.assertEqual(self.applied, [NEW, OLD])
        self.assertEqual(self.helper.COMPOSE.read_text(), COMPOSE)
        self.assertFalse((self.helper.STATE / 'image-update-pending').exists())
        self.assertEqual((self.helper.STATE / 'image-digest').read_text().strip(), OLD)

    def test_failed_rollback_keeps_pending_for_operator_recovery(self):
        self.fail_new = self.fail_restore = True
        with self.fake_docker():
            with self.assertRaises(self.helper.Failure):
                self.helper.refresh(self.config, None)
        self.assertTrue((self.helper.STATE / 'image-update-pending').exists())
        self.assertFalse((self.helper.STATE / 'last-image-transaction').exists())
        with self.fake_docker():
            with self.assertRaisesRegex(self.helper.Failure, 'IMAGE_UPDATE_PENDING'):
                self.helper.refresh(self.config, None)

    def test_identical_digest_does_not_recreate_container(self):
        self.candidate = OLD
        with self.fake_docker():
            self.helper.refresh(self.config, None)
        self.assertEqual(self.applied, [])
        self.assertFalse((self.helper.STATE / 'image-transactions').exists())

    def test_foreign_image_is_rejected_before_commands(self):
        with self.fake_docker():
            with self.assertRaisesRegex(self.helper.Failure, 'OFFICIAL'):
                self.helper.refresh(self.config, 'attacker/node:latest')
        self.assertEqual(self.commands, [])

    def test_compose_drift_is_rejected_before_update(self):
        self.helper.atomic(self.helper.COMPOSE, COMPOSE.replace(OLD, NEW))
        with self.fake_docker():
            with self.assertRaisesRegex(self.helper.Failure, 'COMPOSE_DIGEST_DRIFT'):
                self.helper.refresh(self.config, None)
        self.assertEqual(self.applied, [])

    def test_explicit_digest_must_match_registry_result(self):
        with self.fake_docker():
            with self.assertRaisesRegex(self.helper.Failure, 'CANDIDATE_DIGEST'):
                self.helper.refresh(self.config, 'remnawave/node@sha256:' + 'c' * 64)
        self.assertEqual(self.applied, [])

    def test_transaction_checksum_and_path_validation(self):
        with self.fake_docker():
            self.helper.refresh(self.config, None)
        pointer = self.helper.STATE / 'last-image-transaction'
        # Production requires UID 0; emulate only ownership on non-root CI. Mode/hash/path remain real.
        owner = (contextlib.nullcontext() if os.geteuid() == 0
                 else patch.object(self.helper, 'require_private', lambda p: None))
        with owner:
            path, _ = self.helper.read_transaction(pointer)
            old = (path / 'previous.compose.yaml').read_text()
            self.helper.atomic(path / 'previous.compose.yaml', old + '# corrupted\n')
            with self.assertRaisesRegex(self.helper.Failure, 'CHECKSUM'):
                self.helper.read_transaction(pointer)
            self.helper.atomic(pointer, str(self.helper.STATE / '..' / 'unexpected'))
            with self.assertRaisesRegex(self.helper.Failure, 'TRANSACTION_PATH'):
                self.helper.read_transaction(pointer)

    def test_private_path_refuses_symlinks_and_public_permissions(self):
        target = self.helper.ETC / 'private'
        self.helper.atomic(target, 'data')
        alias = self.helper.ETC / 'alias'
        alias.symlink_to(target)
        for path in (alias, self.helper.ETC):
            if path == self.helper.ETC:
                path.chmod(0o755)
            with self.assertRaises(self.helper.Failure):
                self.helper.require_private(path)


if __name__ == '__main__':
    unittest.main()
