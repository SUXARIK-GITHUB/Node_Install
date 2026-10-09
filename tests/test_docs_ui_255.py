"""Docs-only refresh contracts: rich README, Security and full example consistency.

Safe offline tests: no install, no Docker changes, no network, no production secrets.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from common import ROOT


class DocsVisualAndSecurityContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.readme = (ROOT / 'README.md').read_text(encoding='utf-8')
        cls.security = (ROOT / 'SECURITY.md').read_text(encoding='utf-8')

    def test_main_install_command_at_top_is_pinned_verified_and_syntax_valid(self):
        self.assertLess(self.readme.index('## ⚡ ГЛАВНАЯ КОМАНДА УСТАНОВКИ'), 850)
        block = self.readme.split("```bash\n", 1)[1].split('\n```', 1)[0]
        self.assertTrue(block.startswith("sudo bash <<'VKARMANI_NODE_INSTALL_255'"))
        result = subprocess.run(['bash', '-n'], input=block, text=True,
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('raw.githubusercontent.com/SUXARIK-GITHUB/Node_Install/', block)
        self.assertIn('276789eab8a43a9ff08dca124e137456e212b2e3', block)
        self.assertNotIn('/main/install.sh', block)
        self.assertIn('--proto \'=https\'', block)
        self.assertIn('--proto-redir \'=https\'', block)
        self.assertIn('sha256sum --check --status', block)
        self.assertIn('bash -n "$WORK_DIR/install.sh"', block)
        self.assertIn('"2.5.5"', block)
        self.assertIn('--no-reboot', block)
        self.assertNotIn('curl | bash', block)
        sha = re.search(r'EXPECTED_SHA256="([0-9a-f]{64})"', block)
        self.assertIsNotNone(sha)
        self.assertEqual(sha.group(1), hashlib.sha256((ROOT / 'install.sh').read_bytes()).hexdigest())

    def test_full_advanced_profiles_are_single_listener_and_align(self):
        examples = {k: json.loads((ROOT / f'examples/inbound-{k}-full.example.json').read_text())
                    for k in ('raw', 'xhttp')}
        assert examples['raw']['inbounds'][0]['tag'] == examples['xhttp']['inbounds'][0]['tag']
        for kind, cfg in examples.items():
            with self.subTest(kind=kind):
                self.assertEqual(set(cfg), {'log','dns','inbounds','outbounds','routing'})
                self.assertEqual(len(cfg['inbounds']), 1)
                ib = cfg['inbounds'][0]
                self.assertEqual(ib['port'], 443)
                self.assertEqual(ib['streamSettings']['realitySettings']['xver'], 1)
                self.assertEqual(ib['streamSettings']['realitySettings']['target'], '/dev/shm/nginx.sock')
                self.assertEqual(ib['streamSettings']['security'], 'reality')
                self.assertEqual(cfg['dns']['queryStrategy'], 'UseIPv4')
                self.assertEqual(cfg['dns']['servers'], ['1.1.1.1', '1.0.0.1', '8.8.8.8'])
                self.assertEqual(cfg['outbounds'][0]['settings']['finalRules'][0]['action'], 'block')
                self.assertEqual(cfg['routing']['rules'][0]['protocol'], ['bittorrent'])
                self.assertEqual(cfg['routing']['rules'][1]['domain'], ['geosite:private'])
                self.assertIn('::/0', cfg['routing']['rules'][2]['ip'])
                self.assertIn('geoip:private', cfg['routing']['rules'][2]['ip'])
        self.assertEqual(examples['raw']['inbounds'][0]['settings']['flow'], 'xtls-rprx-vision')
        self.assertEqual(examples['xhttp']['inbounds'][0]['settings']['flow'], '')
        self.assertNotIn('xhttpSettings', examples['raw']['inbounds'][0]['streamSettings'])
        self.assertEqual(examples['xhttp']['inbounds'][0]['streamSettings']['xhttpSettings']['mode'], 'auto')
        self.assertEqual(examples['raw']['routing'], examples['xhttp']['routing'])
        self.assertEqual(examples['raw']['dns'], examples['xhttp']['dns'])

    def test_full_json_exactly_matches_readme_and_no_real_secrets(self):
        for mode in ('RAW', 'XHTTP'):
            start = f'<!-- BEGIN {mode} FULL EXAMPLE -->'
            end = f'<!-- END {mode} FULL EXAMPLE -->'
            self.assertEqual(self.readme.count(start), 1)
            self.assertEqual(self.readme.count(end), 1)
            text = self.readme.split(start, 1)[1].split(end, 1)[0].strip()
            self.assertTrue(text.startswith('```json\n'))
            self.assertTrue(text.endswith('\n```'))
            config = text[8:-4].strip()
            self.assertEqual(config, (ROOT / f'examples/inbound-{mode.lower()}-full.example.json').read_text().strip())
            self.assertIn('REPLACE_WITH_PRIVATE_KEY_FROM_NODE', config)
            self.assertIn('REPLACE_WITH_SHORT_ID_FROM_NODE', config)
            self.assertNotIn('SECRET_KEY=', config)

    def test_rich_cards_mermaid_and_links_are_local_valid(self):
        for name, body in (('README.md',self.readme), ('SECURITY.md', self.security)):
            self.assertIn('```mermaid\nflowchart', body)
            self.assertEqual(body.count('```'), body.count('```') // 2 * 2,
                             f'odd fenced code blocks in {name}')
            # Every relative file href must exist (local Markdown navigation).
            for link in re.findall(r'\]\(([^)]+)\)',body):
                target=link.split('#',1)[0]
                if not target or target.startswith(('https://','http://','mailto:','#')): continue
                target=target.split('?',1)[0]
                self.assertTrue((ROOT / target).is_file(), f'{name}: broken link {link}')
                if '#' in link:
                    anchor = link.split('#',1)[1]
                    linked=(ROOT/target).read_text(encoding='utf-8')
                    self.assertIn(f'<a id="{anchor}"></a>', linked, f'{name}: bad link anchor: {link}')
        self.assertIn('## 🗺️ Карта проекта', self.readme)
        self.assertIn('## 🧭 Быстрые карты безопасности',self.security)

    def test_security_report_model_and_preserved_originals(self):
        for anchor in ('report','versions','threat','trust','secrets','ssh','firewall',
                       'container','selfsteal','tls','supply','backup','reboot','incident','limits'):
            self.assertIn(f'<a id="{anchor}"></a>', self.security)
        self.assertIn('Private vulnerability reporting', self.security)
        self.assertIn('NET_ADMIN',self.security)
        self.assertIn('NET_RAW',self.security)
        self.assertIn('Password-only',self.security)
        self.assertIn('IP панели',self.security)
        self.assertNotIn('69177096f8d7142ee578a7bcd9f583b0e934ebe8990341d11a4ef07b24dd0523',self.security)
        self.assertTrue((ROOT / 'docs/history/README_2.5.5_before_ui_refresh.md').is_file())
        self.assertTrue((ROOT / 'docs/history/SECURITY_2.5.5_before_ui_refresh.md').is_file())
        self.assertGreater(len(self.security.splitlines()), 700)
        self.assertIn('не является гарантией',self.security.lower())

    def test_installer_code_unmodified_by_documentation_work(self):
        self.assertEqual(hashlib.sha256((ROOT/'install.sh').read_bytes()).hexdigest(),
                         'ca654e4b36f88338c15f608c1d554acef83d971e68dff9e5c08ddc31822abc40')


if __name__ == '__main__':
    unittest.main()
