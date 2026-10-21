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
        # The published GitHub commit must be shown before the candidate ZIP.
        # No redundant staging banners, yet readiness must remain explicit.
        self.assertTrue(self.readme.startswith('<div align="center">\n'))
        self.assertIn('## ⚡ Установка', self.readme)
        self.assertNotIn('## ⚡ УСТАНОВКА VKARMANI NODE INSTALL 2.5.10', self.readme)
        self.assertNotIn('## ⚠️ Версии и ограничения', self.readme)
        self.assertIn('текущая staging-сборка', self.readme)
        self.assertIn('на разных чистых VPS', self.readme)
        self.assertIn('docs/CASCADE_R5_ROLE_INSTALL_AND_PANEL.md', self.readme)
        published = '### 🐙 1. Установка с GitHub · 2.5.15 r16 (после публикации)'
        archive = '### 📁 2. Из полного ZIP · 2.5.15 r16 (текущая staging-сборка)'
        self.assertLess(self.readme.index(published),self.readme.index(archive))
        github_cmd = self.readme.split(published,1)[1].split('```bash\n',1)[1].split('\n```',1)[0]
        archive_cmd = self.readme.split(archive,1)[1].split('```bash\n',1)[1].split('\n```',1)[0]
        build_id = json.loads((ROOT / 'BUILD_MANIFEST.json').read_text())['build_id']
        self.assertIn('git clone --depth 1 https://github.com/SUXARIK-GITHUB/Node_Install.git', github_cmd)
        # This command becomes runnable only when the verified r15 is published.
        # As long as GitHub is still r12 the pinned hash deliberately fails closed.
        self.assertIn(hashlib.sha256((ROOT / 'install.sh').read_bytes()).hexdigest(), github_cmd)
        self.assertIn('sha256sum --check', github_cmd)
        self.assertIn('sha256sum --check SHA256SUMS', github_cmd)
        self.assertIn("m.get('build_id')", github_cmd)
        self.assertIn("m.get('release_status')", github_cmd)
        self.assertIn('Node_Install_2.5.15-docs-menu_' + build_id + '.zip', archive_cmd)
        self.assertIn('python3 scripts/verify_release.py --root .', archive_cmd)
        self.assertIn('sha256sum --check SHA256SUMS', archive_cmd)
        self.assertIn('bash ./install.sh\n', archive_cmd + '\n')
        for command in (github_cmd, archive_cmd):
            self.assertEqual(subprocess.run(['bash', '-n'], input=command, text=True,
                                            capture_output=True).returncode, 0)
            self.assertNotIn('curl | bash', command)
            self.assertNotIn('/main/install.sh', command)
        self.assertIn('Node_Install-2.5.15', github_cmd)
        self.assertNotIn('--node-port', github_cmd)
        self.assertNotIn('--node-port', archive_cmd)
        self.assertNotIn('2.5.10 r7e', self.readme.split('---', 1)[0])
        self.assertNotIn('--no-reboot', github_cmd)

    def test_two_visual_route_maps_and_remnawave_binding(self):
        self.assertIn('### 🟦 Карта 1 · Обычная нода',self.readme)
        self.assertIn('### 🟪 Карта 2 · Каскад Entry → Exit',self.readme)
        self.assertEqual(self.readme.count('```mermaid\nflowchart'),2)
        for marker in ('ordinary-map','cascade-map','cascade-entry-json','cascade-exit-json'):
            self.assertEqual(self.readme.count(f'<a id="{marker}"></a>'),1)
        self.assertIn('TO_EXIT_VLESS',self.readme)
        self.assertIn('Нет DIRECT fallback',self.readme)
        self.assertIn('**только Exit**',self.readme)
        self.assertIn('VLESS UUID service-user на Exit',self.readme)
        self.assertIn('Host в подписке',self.readme)
        self.assertIn('https://docs.rw/learn-en/config-profiles/',self.readme)

    def test_full_cascade_profiles_are_documented_and_match_generator(self):
        import sys
        sys.path.insert(0, str(ROOT / 'integrations'))
        import cascade_profiles as cp
        configs = {}
        for name in ('entry', 'exit'):
            begin = f'<!-- BEGIN CASCADE {name.upper()} FULL EXAMPLE -->'
            end = f'<!-- END CASCADE {name.upper()} FULL EXAMPLE -->'
            self.assertEqual(self.readme.count(begin), 1)
            self.assertEqual(self.readme.count(end), 1)
            block = self.readme.split(begin, 1)[1].split(end, 1)[0].strip()
            self.assertTrue(block.startswith('```json\n') and block.endswith('\n```'))
            literal = block[len('```json\n'):-len('\n```')]
            source = (ROOT / f'examples/cascade-{name}-profile.reference.json').read_text().strip()
            self.assertEqual(literal, source)
            self.assertIn('REPLACE_WITH_', source)
            configs[name] = json.loads(source)
        entry, exit_cfg = configs['entry'], configs['exit']
        e_in, x_in = entry['inbounds'][0], exit_cfg['inbounds'][0]
        vnext = entry['outbounds'][1]['settings']['vnext'][0]
        remote = entry['outbounds'][1]['streamSettings']['realitySettings']
        cfg = {
            'entry': {'inbound_tag':e_in['tag'], 'domain':e_in['streamSettings']['realitySettings']['serverNames'][0],
                      'short_id':e_in['streamSettings']['realitySettings']['shortIds'][0],
                      'private_key':e_in['streamSettings']['realitySettings']['privateKey'],
                      'public_key':'REPLACE_WITH_ENTRY_PUBLIC_KEY', 'ipv4':'203.0.113.10'},
            'exit': {'inbound_tag':x_in['tag'], 'domain':remote['serverName'],
                     'short_id':x_in['streamSettings']['realitySettings']['shortIds'][0],
                     'private_key':x_in['streamSettings']['realitySettings']['privateKey'],
                     'public_key':remote['publicKey'], 'ipv4':vnext['address']},
            'bridge': {'service_user_uuid':vnext['users'][0]['id']}
        }
        self.assertEqual(entry, cp.entry_profile(cfg))
        self.assertEqual(exit_cfg, cp.exit_profile(cfg))
        self.assertNotIn('dns', entry)
        self.assertEqual([x['tag'] for x in entry['outbounds']], ['BLOCK','TO_EXIT_VLESS'])
        self.assertEqual([x['tag'] for x in exit_cfg['outbounds']], ['DIRECT','BLOCK'])
        self.assertIn('::/0', exit_cfg['outbounds'][0]['settings']['finalRules'][0]['ip'])

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
        self.assertIn('## 🧭 Быстрые переходы', self.readme)
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

    def test_previous_documentation_is_preserved_on_hotfix(self):
        for path in ('docs/history/README_2.5.5.md', 'docs/history/SECURITY_2.5.5.md'):
            self.assertTrue((ROOT/path).is_file())
        self.assertIn('## ⚡ Установка', self.readme)
        self.assertIn('2.5.15', self.readme)
        self.assertIn('docs/history/README_2.5.4.md', self.readme)
        self.assertNotIn('## ⚠️ Версии и ограничения', self.readme)


if __name__ == '__main__':
    unittest.main()
