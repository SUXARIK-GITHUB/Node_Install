"""Execute the actual CI trust step with real Git and private HOME directories.

GIT_TEST_ASSUME_DIFFERENT_OWNER is Git's own test hook; it forces the ownership
check without chown/root, including on the unprivileged 22.04/24.04 runners.
No global Git config belonging to the caller is read or modified by these tests.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml
from common import ROOT


class GitWorkspaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        jobs = yaml.safe_load((ROOT / '.github/workflows/check.yml').read_text())['jobs']
        cls.steps = jobs['ubuntu-26-userspace']['steps']
        cls.trust_step = next(s['run'] for s in cls.steps
                              if 'git config --global --add safe.directory' in s.get('run', ''))

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='vk-git-trust-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.home = self.root / 'shell-home'
        self.home.mkdir()
        self.repo = self.root / 'Node Install with spaces'
        self.other = self.root / 'unrelated-repo'
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(('GIT_', 'SUDO_')) and k not in ('HOME', 'XDG_CONFIG_HOME')}
        self.env.update(HOME=str(self.home), XDG_CONFIG_HOME=str(self.home / 'xdg'),
                        GIT_CONFIG_NOSYSTEM='1', LC_ALL='C', GITHUB_WORKSPACE=str(self.repo))
        for repo in (self.repo, self.other):
            self.call(['git', 'init', '-q', str(repo)], cwd=self.root, ok=True)
        self.env['GIT_TEST_ASSUME_DIFFERENT_OWNER'] = '1'

    def call(self, args, cwd=None, env=None, ok=False):
        result = subprocess.run(args, cwd=cwd or self.repo, env=env or self.env,
                                text=True, capture_output=True, timeout=10)
        if ok:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def trust(self, env=None, cwd=None, ok=True):
        return self.call(['bash', '--noprofile', '--norc', '-euo', 'pipefail', '-c', self.trust_step],
                         cwd=cwd, env=env, ok=ok)

    def assert_blocked(self, repo=None, env=None):
        result = self.call(['git', 'rev-parse', '--is-inside-work-tree'], cwd=repo, env=env)
        self.assertEqual(result.returncode, 128, result.stderr)
        self.assertIn('detected dubious ownership', result.stderr)

    def test_trust_step_is_after_checkout_before_worktree_check(self):
        checkout = next(i for i, s in enumerate(self.steps) if s.get('uses', '').startswith('actions/checkout@'))
        trust = next(i for i, s in enumerate(self.steps) if s.get('run') == self.trust_step)
        verify = next(i for i, s in enumerate(self.steps) if 'git rev-parse' in s.get('run', ''))
        self.assertLess(checkout, trust)
        self.assertLess(trust, verify)
        self.assertIn('"$GITHUB_WORKSPACE"', self.trust_step)
        self.assertNotRegex(self.trust_step, r'(?:chmod|chown|--system|safe\.directory\s+[\'\"]?\*)')

    def test_actual_git_refuses_before_and_accepts_after_exact_trust(self):
        self.assert_blocked()
        old_config = (self.repo / '.git/config').read_bytes()
        self.trust()
        self.assertEqual(self.call(['git', 'rev-parse', '--is-inside-work-tree'], ok=True).stdout.strip(), 'true')
        self.assertEqual((self.repo / '.git/config').read_bytes(), old_config)
        entries = self.call(['git', 'config', '--global', '--get-all', 'safe.directory'], ok=True)
        self.assertEqual(entries.stdout.splitlines(), [str(self.repo)])

    def test_unrelated_repository_remains_blocked(self):
        self.trust()
        self.assert_blocked(self.other)

    def test_checkout_home_exception_does_not_fix_shell_home(self):
        checkout_home = self.root / 'checkout-home'
        checkout_home.mkdir()
        checkout_env = dict(self.env, HOME=str(checkout_home), XDG_CONFIG_HOME=str(checkout_home / 'xdg'))
        self.call(['git', 'config', '--global', '--add', 'safe.directory', str(self.repo)],
                  env=checkout_env, ok=True)
        self.call(['git', 'rev-parse', '--is-inside-work-tree'], env=checkout_env, ok=True)
        previous = (checkout_home / '.gitconfig').read_bytes()
        self.assert_blocked()  # Same repo and process UID, different HOME.
        self.trust()
        self.call(['git', 'rev-parse', '--is-inside-work-tree'], ok=True)
        self.assertEqual((checkout_home / '.gitconfig').read_bytes(), previous)

    def test_missing_workspace_refuses_without_config_write(self):
        env = dict(self.env)
        env.pop('GITHUB_WORKSPACE')
        result = self.trust(env=env, ok=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.home / '.gitconfig').exists())

    def test_relative_workspace_refuses_without_config_write(self):
        result = self.trust(env=dict(self.env, GITHUB_WORKSPACE='.'), ok=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.home / '.gitconfig').exists())

    def test_wrong_working_directory_refuses_without_config_write(self):
        result = self.trust(cwd=self.other, ok=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.home / '.gitconfig').exists())

    def test_archive_without_git_refuses_without_config_write(self):
        empty = self.root / 'no-git'
        empty.mkdir()
        result = self.trust(cwd=empty, env=dict(self.env, GITHUB_WORKSPACE=str(empty)), ok=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.home / '.gitconfig').exists())

    def test_repeat_step_does_not_broaden_trust(self):
        self.trust()
        self.trust()
        entries = self.call(['git', 'config', '--global', '--get-all', 'safe.directory'], ok=True)
        self.assertEqual(set(entries.stdout.splitlines()), {str(self.repo)})
        self.assert_blocked(self.other)


if __name__ == '__main__':
    unittest.main()
