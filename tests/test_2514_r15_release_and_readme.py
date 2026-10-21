"""R15 offline version, GitHub-install fail-closed, and default-port contracts.

Never clones GitHub, runs installation or changes host state.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import unittest

from common import ROOT, SCRIPT, payload


class Release2514Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.readme = (ROOT / 'README.md').read_text(encoding='utf-8')

    def test_version_matches_primary_installer_and_embedded_finalizer(self):
        self.assertRegex(SCRIPT, r'(?m)^INSTALLER_VERSION=2\.5\.14$')
        self.assertIn("VERSION = '2.5.14'", payload('VK_FINALIZER_PY'))
        self.assertEqual(payload('VK_FINALIZER_PY'),
                         (ROOT / 'integrations/finalize_install.py').read_text())
        for arg in ('--version', '--help'):
            process = subprocess.run(['bash', str(ROOT / 'install.sh'), arg],
                                     capture_output=True, text=True, timeout=10)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertIn('2.5.14', process.stdout)

    def test_older_node_allowed_newer_future_denied(self):
        acceptance = payload('VK_PAYLOAD_VK_WRITE_ACCEPTANCE')
        self.assertIn('2.5.13|2.5.14) printf \'modern', acceptance)
        self.assertNotIn('2.5.15) printf \'modern', acceptance)
        self.assertIn("'version=2.5.13', 'version=2.5.14')", SCRIPT)
        self.assertIn("'2.5.13', '2.5.14') or not re.search", SCRIPT)
        self.assertIn('FINISH_ONLY_RECORDED_2_5_14_SUPPORTED', payload('VK_FINALIZER_PY'))
        self.assertIn("'2.5.13','2.5.14'", (ROOT / 'scripts/staging_web_deploy.py').read_text())

    def test_github_command_pinned_to_this_build_and_no_nondefault_port(self):
        heading = '### 🐙 1. Установка с GitHub · 2.5.14 r15 (после публикации)'
        self.assertEqual(self.readme.count(heading), 1)
        command = self.readme.split(heading, 1)[1].split('```bash\n',1)[1].split('\n```',1)[0]
        self.assertEqual(subprocess.run(['bash', '-n'], input=command, text=True,
                                        capture_output=True).returncode, 0)
        expected = hashlib.sha256((ROOT / 'install.sh').read_bytes()).hexdigest()
        self.assertIn(expected, command)
        self.assertIn('git clone --depth 1 https://github.com/SUXARIK-GITHUB/Node_Install.git', command)
        self.assertIn('sha256sum --check SHA256SUMS', command)
        self.assertIn('python3 scripts/verify_release.py --root .', command)
        self.assertIn("'2.5.14', '20261021-r15-github-install'", command)
        self.assertIn('bash ./install.sh\n', command + '\n')
        self.assertNotIn('--node-port', command)
        self.assertNotIn('curl | bash', command)
        self.assertIn('пока есть только в полном ZIP', self.readme)

    def test_archive_command_consistent_with_manifest_build(self):
        filename='Node_Install_2.5.14-docs-menu_20261021-r15-github-install.zip'
        self.assertIn('unzip -q ' + filename, self.readme)
        self.assertNotIn('bash ./install.sh --node-port 32443', self.readme)
        self.assertIn('NODE_PORT_DEFAULT=2222', SCRIPT)
        self.assertIn('## 2.5.14 r15', (ROOT/'CHANGELOG.md').read_text().splitlines()[0])
        manifest = json.loads((ROOT/'BUILD_MANIFEST.json').read_text())
        self.assertEqual(manifest['version'], '2.5.14')
        self.assertEqual(manifest['build_id'], '20261021-r15-github-install')
        self.assertEqual(manifest['release_status'], 'INCOMPLETE_STAGING_ONLY')


if __name__ == '__main__':
    unittest.main()
