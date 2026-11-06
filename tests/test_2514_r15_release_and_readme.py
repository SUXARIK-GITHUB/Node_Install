"""Current offline version, GitHub-install fail-closed, and default-port contracts.

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
        self.assertRegex(SCRIPT, r'(?m)^INSTALLER_VERSION=2\.5\.18$')
        self.assertIn("VERSION = '2.5.18'", payload('VK_FINALIZER_PY'))
        self.assertEqual(payload('VK_FINALIZER_PY'),
                         (ROOT / 'integrations/finalize_install.py').read_text())
        for arg in ('--version', '--help'):
            process = subprocess.run(['bash', str(ROOT / 'install.sh'), arg],
                                     capture_output=True, text=True, timeout=10)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertIn('2.5.18', process.stdout)

    def test_older_node_allowed_newer_future_denied(self):
        acceptance = payload('VK_PAYLOAD_VK_WRITE_ACCEPTANCE')
        self.assertIn('2.5.15|2.5.16|2.5.17|2.5.18) printf \'modern', acceptance)
        self.assertNotIn('2.5.19) printf \'modern', acceptance)
        self.assertIn("'version=2.5.14', 'version=2.5.15', 'version=2.5.16', 'version=2.5.17', 'version=2.5.18')", SCRIPT)
        self.assertIn("'2.5.14', '2.5.15', '2.5.16', '2.5.17', '2.5.18') or not re.search", SCRIPT)
        self.assertIn('FINISH_ONLY_RECORDED_2_5_18_SUPPORTED', payload('VK_FINALIZER_PY'))
        self.assertIn("'2.5.14','2.5.15','2.5.16','2.5.17','2.5.18'", (ROOT / 'scripts/staging_web_deploy.py').read_text())

    def test_github_command_checks_current_build_and_no_nondefault_port(self):
        manifest=json.loads((ROOT/'BUILD_MANIFEST.json').read_text())
        self.assertEqual(manifest['build_id'], '20261106-r35-automatic-vps-check')
        heading='### 1. 🐙 С GitHub'
        self.assertEqual(self.readme.count(heading),1)
        command=self.readme.split(heading,1)[1].split('```bash\n',1)[1].split('\n```',1)[0]
        result=subprocess.run(['bash','-n'], input=command, text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn(hashlib.sha256((ROOT/'install.sh').read_bytes()).hexdigest(),command)
        self.assertIn('git clone --depth 1 https://github.com/SUXARIK-GITHUB/Node_Install.git',command)
        self.assertIn('sha256sum --check',command)
        self.assertIn('python3 scripts/verify_release.py --root .',command)
        self.assertIn(manifest['build_id'],command)
        self.assertIn('BUILD_MANIFEST.json',command)
        self.assertIn('bash ./install.sh --menu',command)
        self.assertNotIn('--node-port',command)
        self.assertNotIn('curl | bash',command)
        self.assertNotIn('rm -rf',command)
        self.assertIn('текущая staging-сборка',self.readme)

    def test_archive_command_consistent_with_manifest_build(self):
        manifest = json.loads((ROOT/'BUILD_MANIFEST.json').read_text())
        filename=f'Node_Install_2.5.18-docs-menu_{manifest["build_id"]}.zip'
        self.assertIn('archive="/root/' + filename + '"', self.readme)
        self.assertIn('unzip -q "$archive"', self.readme)
        self.assertNotIn('bash ./install.sh --node-port 32443', self.readme)
        self.assertIn('NODE_PORT_DEFAULT=2222', SCRIPT)
        release = manifest['build_id'].split('-', 2)[1]
        self.assertIn('## 2.5.18 ' + release, (ROOT/'CHANGELOG.md').read_text().splitlines()[0])
        self.assertEqual(manifest['version'], '2.5.18')
        # Source/ZIP verifier checks hashes; document the active unpublished
        # staging revision without changing the historical pinned r29 command.
        self.assertRegex(manifest['build_id'], r'^20261106-r35-[A-Za-z0-9_.-]+$')
        self.assertEqual(manifest['release_status'], 'INCOMPLETE_STAGING_ONLY')


if __name__ == '__main__':
    unittest.main()
