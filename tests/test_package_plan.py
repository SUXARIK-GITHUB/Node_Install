"""Real apt solver in an isolated file:// fixture; never runs dpkg or installs packages.
The repository metadata models the time-daemon conflict, NOT a live Ubuntu mirror.
"""
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import tempfile
import unittest

from common import SCRIPT, module


def component_commands(provider, fail_simulation=False):
    start = SCRIPT.index("stage 'Компоненты ноды из подписанных репозиториев")
    end = SCRIPT.index('\nensure_sshd_runtime', start)
    fragment = SCRIPT[start:end]
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        trace = root / 'commands.jsonl'
        spy = root / 'apt-get'
        spy.write_text('#!/usr/bin/env python3\nimport json,os,sys\n'
                       'with open(os.environ["APT_TRACE"], "a") as f: f.write(json.dumps(sys.argv[1:])+"\\n")\n'
                       'sys.exit(100 if os.environ["FAIL_SIM"]=="1" and "--simulate" in sys.argv else 0)\n')
        spy.chmod(0o700)
        preamble = '''set -Eeuo pipefail
stage(){ :; }
vk_write_time_helper(){ :; }
vk_setup_docker_repository(){ :; } # signed repository I/O is outside this isolated solver fixture
python3(){ printf '%s\\n' "$TEST_PROVIDER"; }
LIB="$TEST_LIB"
APT=(apt-get -y --no-remove --no-install-recommends -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
'''
        p = subprocess.run(['bash', '-c', preamble + fragment], capture_output=True, text=True, timeout=15,
                           env={**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH'],
                                'TEST_PROVIDER': provider, 'TEST_LIB': str(root), 'APT_TRACE': str(trace),
                                'FAIL_SIM': str(int(fail_simulation))})
        commands = [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
        return p, commands


class PackageCommandTests(unittest.TestCase):
    def test_actual_component_fragment_preserves_timesyncd(self):
        p, commands = component_commands('systemd-timesyncd')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(len(commands), 2)
        self.assertIn('--simulate', commands[0])
        self.assertIn('docker-ce', commands[0])
        self.assertIn('docker-compose-plugin', commands[0])
        self.assertNotIn('docker-ce', commands[1])
        self.assertNotIn('--simulate', commands[1])
        for command in commands:
            self.assertIn('--no-remove', command)
            self.assertIn('systemd-timesyncd', command)
            self.assertNotIn('chrony', command)

    def test_actual_component_fragment_can_install_chrony_without_replacement(self):
        p, commands = component_commands('chrony')
        self.assertEqual(p.returncode, 0, p.stderr)
        for command in commands:
            self.assertIn('--no-remove', command)
            self.assertIn('chrony', command)
            self.assertNotIn('systemd-timesyncd', command)

    def test_simulation_failure_never_reaches_actual_transaction(self):
        p, commands = component_commands('systemd-timesyncd', fail_simulation=True)
        self.assertEqual(p.returncode, 100)
        self.assertEqual(len(commands), 1)
        self.assertIn('--simulate', commands[0])

    def test_component_install_keeps_every_non_time_dependency(self):
        p, commands = component_commands('systemd-timesyncd')
        packages = commands[1][commands[1].index('install') + 1:]
        self.assertEqual(set(packages), {'openssh-server', 'ufw', 'fail2ban', 'nginx', 'certbot',
                         'systemd-timesyncd', 'logrotate', 'unattended-upgrades', 'ethtool', 'kmod',
                         'util-linux', 'procps', 'dbus', 'python3-systemd'})
        self.assertEqual(len(packages), len(set(packages)))


@unittest.skipUnless(shutil.which('apt-get'), 'apt-get needed for isolated real solver tests')
class AptSolverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='vk-apt-fixture-')
        cls.root = r = Path(cls.temp.name)
        for sub in ('etc/apt.conf.d', 'etc/sources.list.d', 'etc/preferences.d',
                    'var/lib/apt/lists/partial', 'var/cache/apt/archives/partial', 'var/log/apt',
                    'var/lib/dpkg', 'repo/dists/test/main/binary-amd64', 'repo/dists/test/main/binary-all'):
            (r / sub).mkdir(parents=True)
        (r / 'etc/apt.conf').write_text('')
        (r / 'etc/sources.list').write_text(f'deb [trusted=yes] file:{r}/repo test main\n')
        conf = r / 'apt-sandbox.conf'
        conf.write_text(f'''Dir "{r}";
Dir::Etc "{r}/etc";
Dir::State "{r}/var/lib/apt";
Dir::State::status "{r}/var/lib/dpkg/status";
Dir::Cache "{r}/var/cache/apt";
Dir::Log "{r}/var/log/apt";
APT::Architecture "amd64";
APT::Sandbox::User "{pwd.getpwuid(os.getuid()).pw_name}";
Acquire::Languages "none";
''')
        cls.env = {**os.environ, 'APT_CONFIG': str(conf), 'LC_ALL': 'C'}
        _, commands = component_commands('systemd-timesyncd')
        cls.packages = commands[1][commands[1].index('install') + 1:]
        names = sorted(set(cls.packages) | {'chrony', 'unrelated-service', 'bad-addon'})
        metadata = ''
        for name in names:
            metadata += (f'Package: {name}\nVersion: 1.0\nArchitecture: amd64\n'
                         'Maintainer: Fixture <fixture@example.invalid>\n')
            if name in ('chrony', 'systemd-timesyncd'):
                metadata += 'Provides: time-daemon\nConflicts: time-daemon\n'
            if name == 'bad-addon':
                metadata += 'Conflicts: unrelated-service\n'
            metadata += f'Filename: pool/{name}.deb\nSize: 1\nDescription: synthetic isolated solver fixture\n\n'
        (r / 'repo/dists/test/main/binary-amd64/Packages').write_text(metadata)
        (r / 'repo/dists/test/main/binary-all/Packages').write_text('')
        (r / 'var/lib/dpkg/status').write_text('')
        update = subprocess.run(['apt-get', 'update'], env=cls.env, text=True, capture_output=True, timeout=30)
        if update.returncode:
            cls.temp.cleanup()
            raise AssertionError('isolated local repository indexing failed: ' + update.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def solve(self, installed, requested):
        text = ''
        for name in installed:
            text += (f'Package: {name}\nStatus: install ok installed\nPriority: optional\n'
                     'Section: admin\nArchitecture: amd64\nVersion: 1.0\n')
            if name in ('chrony', 'systemd-timesyncd'):
                text += 'Provides: time-daemon\nConflicts: time-daemon\n'
            text += 'Description: synthetic installed-package fixture\n\n'
        status = self.root / 'var/lib/dpkg/status'
        status.write_text(text)
        p = subprocess.run(['apt-get', '--simulate', '--no-remove', '--no-install-recommends', '-y',
                            'install', *requested], env=self.env, capture_output=True, text=True, timeout=20)
        self.assertEqual(status.read_text(), text, 'simulation modified dpkg fixture state')
        return p

    def test_202_failure_reproduced_by_real_solver(self):
        original = ['chrony' if p == 'systemd-timesyncd' else p for p in self.packages]
        p = self.solve(['systemd-timesyncd'], original)
        self.assertEqual(p.returncode, 100, p.stdout + p.stderr)
        self.assertIn('systemd-timesyncd', p.stdout)
        self.assertIn('Packages need to be removed but remove is disabled', p.stderr)

    def test_fixed_timesyncd_plan_needs_zero_removals(self):
        p = self.solve(['systemd-timesyncd'], self.packages)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn('0 to remove', p.stdout)
        self.assertNotIn('Remv ', p.stdout)
        self.assertNotIn('Inst chrony ', p.stdout)

    def test_chrony_already_present_needs_zero_removals(self):
        requested = ['chrony' if p == 'systemd-timesyncd' else p for p in self.packages]
        p = self.solve(['chrony'], requested)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn('0 to remove', p.stdout)

    def test_no_time_daemon_can_install_chrony_without_removals(self):
        requested = ['chrony' if p == 'systemd-timesyncd' else p for p in self.packages]
        p = self.solve([], requested)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn('Inst chrony ', p.stdout)
        self.assertIn('0 to remove', p.stdout)

    def test_unrelated_removal_is_still_blocked(self):
        p = self.solve(['systemd-timesyncd', 'unrelated-service'], self.packages + ['bad-addon'])
        self.assertEqual(p.returncode, 100, p.stdout + p.stderr)
        self.assertIn('Packages need to be removed but remove is disabled', p.stderr)


if __name__ == '__main__':
    unittest.main()
