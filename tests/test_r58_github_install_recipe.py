"""GitHub README bootstrap: local-only clone, verified release, and simulated menu.

Never runs the installer or touches GitHub. The only modified part of the recipe
is the TTY redirection (substituted with /dev/null for the inert menu stub)
and the disposable checkout path (no /root access required on CI).
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from common import ROOT


GITHUB = 'https://github.com/SUXARIK-GITHUB/Node_Install.git'


def github_recipe():
    readme = (ROOT / 'README.md').read_text(encoding='utf-8')
    section = readme.split('### 1. 🐙 С GitHub', 1)[1].split('### 2. 📦 Из полного ZIP-архива', 1)[0]
    assert section.count('```bash\n') == 1, 'README must include exactly one current GitHub command'
    return section.split('```bash\n', 1)[1].split('\n```', 1)[0]


class GitHubBootstrapReadmeTests(unittest.TestCase):
    def test_installer_and_verifier_hashes_are_pinned_to_actual_bytes(self):
        recipe = github_recipe()
        self.assertEqual(subprocess.run(['/bin/bash', '-n'], input=recipe, text=True,
                                        capture_output=True).returncode, 0)
        for path in ('install.sh', 'scripts/verify_release.py'):
            digest = hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
            self.assertIn(f"'{digest}' '{path}' | sha256sum --check", recipe)
        self.assertIn('git clone --depth 1 ' + GITHUB, recipe)
        self.assertIn('branch --show-current', recipe)
        self.assertIn('sha256sum --check --status SHA256SUMS', recipe)
        self.assertIn('python3 scripts/verify_release.py --root .', recipe)
        self.assertIn('bash -n install.sh', recipe)
        self.assertIn('bash ./install.sh --menu < /dev/tty', recipe)
        self.assertNotIn('curl | bash', recipe)
        self.assertNotIn('git reset --hard', recipe)
        self.assertNotIn('git push --force', recipe)
        m = json.loads((ROOT / 'BUILD_MANIFEST.json').read_text(encoding='utf-8'))
        self.assertIn("'" + m['build_id'] + "'", recipe)
        self.assertEqual(m['build_id'], json.loads(
            (ROOT / 'docs/RELEASE_VALIDATION.json').read_text(encoding='utf-8'))['build_id'])

    @staticmethod
    def make_origin(td, tamper_installer=False):
        origin = td / 'origin'
        # The supplied source is already checksum-verified in the full suite.
        shutil.copytree(ROOT, origin, ignore=shutil.ignore_patterns('.git', '__pycache__'))
        if tamper_installer:
            with (origin / 'install.sh').open('a') as f:
                f.write('\n# tampered before cloning\n')
        env = dict(os.environ,
                   GIT_AUTHOR_NAME='Offline QA', GIT_AUTHOR_EMAIL='qa@example.invalid',
                   GIT_COMMITTER_NAME='Offline QA', GIT_COMMITTER_EMAIL='qa@example.invalid')
        for cmd in (['git', 'init', '-q', '-b', 'main'], ['git', 'add', '-A'],
                    ['git', 'commit', '-q', '-m', 'Offline synthetic release']):
            p = subprocess.run(cmd, cwd=origin, env=env, capture_output=True, text=True, timeout=40)
            if p.returncode:
                raise AssertionError(f'{cmd!r} failed: {p.stderr}')
        return origin

    @staticmethod
    def run_simulated_recipe(td, origin):
        stubs = td / 'stubs'
        stubs.mkdir()
        marker = td / 'menu-invoked.txt'
        # The stub is intentionally the only reachable --menu executor.
        bash_stub = stubs / 'bash'
        bash_stub.write_text('''#!/bin/sh
if [ "$1" = './install.sh' ] && [ "$2" = '--menu' ] && [ "$#" -eq 2 ]; then
  printf '%s\\n' 'MENU_SIMULATED_ONLY' >> "$MENU_MOCK_LOG"
  exit 0
fi
exec /bin/bash "$@"
''')
        bash_stub.chmod(0o755)
        id_stub = stubs / 'id'
        id_stub.write_text('''#!/bin/sh
if [ "$1" = '-u' ]; then printf '%s\\n' '0'; exit 0; fi
exec /usr/bin/id "$@"
''')
        id_stub.chmod(0o755)
        recipe = github_recipe()
        # Root-owned /root and interactive /dev/tty are unavailable in unprivileged CI.
        # Replace ONLY those two environment dependencies, not any integrity checks.
        self_checkout = str(td / 'checkout-XXXXXXXX')
        assert recipe.count('/root/NodeInstall-git-XXXXXXXX') == 1
        assert recipe.count('< /dev/tty') == 1
        recipe = recipe.replace('/root/NodeInstall-git-XXXXXXXX', self_checkout)
        recipe = recipe.replace('< /dev/tty', '< /dev/null')
        env = dict(os.environ)
        env.update({
            'PATH': str(stubs) + os.pathsep + os.environ['PATH'],
            'MENU_MOCK_LOG': str(marker),
            'GIT_CONFIG_COUNT': '1',
            'GIT_CONFIG_KEY_0': f'url.file://{origin.as_posix()}/.insteadOf',
            'GIT_CONFIG_VALUE_0': GITHUB,
            'GIT_TERMINAL_PROMPT': '0',
        })
        p = subprocess.run(['/bin/bash'], input=recipe, env=env, cwd=td,
                           capture_output=True, text=True, timeout=90)
        return p, marker

    def test_entire_github_recipe_opens_only_stub_menu_from_local_clone(self):
        with tempfile.TemporaryDirectory() as dirname:
            td = Path(dirname)
            origin = self.make_origin(td)
            process, marker = self.run_simulated_recipe(td, origin)
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            self.assertIn('RELEASE_VERIFY=PASS', process.stdout)
            self.assertEqual(marker.read_text(), 'MENU_SIMULATED_ONLY\n')

    def test_tampered_installer_blocks_menu_before_execution(self):
        with tempfile.TemporaryDirectory() as dirname:
            td = Path(dirname)
            origin = self.make_origin(td, tamper_installer=True)
            process, marker = self.run_simulated_recipe(td, origin)
            self.assertNotEqual(process.returncode, 0, process.stdout + process.stderr)
            self.assertIn('FAILED', process.stdout + process.stderr)
            self.assertFalse(marker.exists(), 'a changed installer must NEVER reach the menu')


if __name__ == '__main__':
    unittest.main()
