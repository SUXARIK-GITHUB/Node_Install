"""Safe offline tests for 2.5.10 first-run menu and cascade *reference only*.

No system installation, no real TTY, no Docker, no firewall, no panel access.
"""
import json
from pathlib import Path
import re
import subprocess
import unittest

from common import ROOT, SCRIPT


class Menu2510(unittest.TestCase):
    def choose(self, choices, fail_prompt=False):
        lines = ' '.join(repr(x) for x in choices)
        # Override only the terminal input seam after loading inert definitions.
        shim = (SCRIPT.split("vk_menu_read() {",1)[1].split("[[ $EUID -eq 0 ]]",1)[0])
        shim = "vk_menu_read() {" + shim + r'''
choices=(%s)
index=0
vk_menu_display_prompt(){ %s; }
vk_menu_read(){
    VK_MENU_CHOICE="${choices[$index]:-}"
    ((index+=1))
    return 0
}
vk_initial_install_menu
''' % (lines, 'return 1' if fail_prompt else ':')
        return subprocess.run(['bash', '-c', shim, '_', str(ROOT/'install.sh')],
                              text=True, capture_output=True, timeout=8)

    def test_ordinary_choice_is_success_and_keeps_input_prompts(self):
        result = self.choose(['1'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Режим: обычная нода', result.stdout)
        for field in ('SECRET_KEY', 'Домен', 'IPv4 технички'):
            self.assertIn(field, SCRIPT)

    def test_cascade_selection_refuses_missing_role_and_bad_path(self):
        for choices, expected in ((['2'], 'роль должна быть entry или exit'),
                                  (['2','entry','relative.json'], 'только абсолютный путь'),
                                  (['2','invalid'], 'роль должна быть entry или exit')):
            with self.subTest(choices=choices):
                result = self.choose(choices)
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertIn(expected, result.stderr)
                self.assertNotIn('Режим: обычная нода', result.stdout)

    def test_cascade_entry_and_exit_menu_reach_same_preflight_branch(self):
        for role in ('entry', 'exit'):
            result = self.choose(['2', role, '/root/cascade/role-bundle.json'])
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('Режим: каскадная нода', result.stdout)
            self.assertNotIn('Режим: обычная нода', result.stdout)

    def test_invalid_selection_then_ordinary(self):
        result = self.choose(['3', 'случайно', '1'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreaterEqual(result.stderr.count('Некорректный выбор'), 2)

    def test_no_terminal_fails_safely(self):
        result = self.choose(['1'], fail_prompt=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('необходим интерактивный терминал', result.stderr)

    def test_five_invalid_entries_reject(self):
        result = self.choose(['x']*5)
        self.assertEqual(result.returncode, 2)
        self.assertIn('превышено число попыток', result.stderr)

    def test_choice_occurs_before_mutating_installation(self):
        # Explicit source-order contract. Operational application still needs staging.
        sel = SCRIPT.index('vk_initial_install_menu || return $?')
        for later in ('VK_SOURCE_PATH=$(readlink', 'vk_wait_apt_idle "$APT_LOCK_TOTAL_WAIT"', 'vk_collect_inputs'):
            self.assertLess(sel, SCRIPT.index(later, sel), later)
        self.assertIn('[[ ! -e "$STATE/owned-installation"', SCRIPT[sel-230:sel])

    def test_new_version_remains_eligible_for_explicit_maintenance_and_rkn(self):
        self.assertIn(r"'^version=2\.5\.(8|9|10|11)$'", SCRIPT)
        self.assertIn(r"'^version=2\.5\.([2-9]|10|11)$'", SCRIPT)
        self.assertIn("2.5.10", SCRIPT)

    def test_version_and_help_remain_inert(self):
        for arg in ('--help', '--version', '--not-a-real-flag'):
            p = subprocess.run(['bash', str(ROOT/'install.sh'), arg], capture_output=True, text=True, timeout=7)
            self.assertEqual(p.returncode, 2 if arg=='--not-a-real-flag' else 0)
            if arg != '--not-a-real-flag':
                self.assertIn('2.5.11', p.stdout)
            self.assertNotIn('Выберите 1 или 2:', p.stdout)


class CascadeReference2510(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entry = json.loads((ROOT/'examples/cascade-entry-profile.reference.json').read_text())
        cls.exit = json.loads((ROOT/'examples/cascade-exit-profile.reference.json').read_text())

    def test_distinct_peer_inbounds_with_own_local_selfsteal(self):
        tags=[]
        for profile, domain in ((self.entry,'entry.example.com'),(self.exit,'exit.example.com')):
            expected = {'log','inbounds','outbounds','routing'} if profile is self.entry else {'log','dns','inbounds','outbounds','routing'}
            self.assertEqual(set(profile), expected)
            self.assertEqual(len(profile['inbounds']),1)
            i=profile['inbounds'][0]
            self.assertEqual((i['listen'],i['port'],i['protocol']),('0.0.0.0',443,'vless'))
            self.assertEqual(i['settings']['clients'],[])
            self.assertEqual(i['settings']['flow'],'xtls-rprx-vision')
            self.assertEqual(i['streamSettings']['network'],'raw')
            reality=i['streamSettings']['realitySettings']
            self.assertEqual(reality['target'],'/dev/shm/nginx.sock')
            self.assertEqual(reality['xver'],1)
            self.assertEqual(reality['serverNames'],[domain])
            tags.append(i['tag'])
        self.assertEqual(len(set(tags)),2)

    def test_entry_has_no_direct_fallback_and_uses_service_peer(self):
        tags={i['tag'] for i in self.entry['outbounds']}
        self.assertEqual(tags, {'BLOCK','TO_EXIT_VLESS'})
        self.assertEqual(self.entry['outbounds'][0]['tag'],'BLOCK')
        self.assertEqual(self.entry['routing']['domainStrategy'],'AsIs')
        self.assertNotIn('dns',self.entry)
        rule=self.entry['routing']['rules'][-1]
        self.assertEqual(rule['inboundTag'],[self.entry['inbounds'][0]['tag']])
        self.assertEqual(rule['outboundTag'],'TO_EXIT_VLESS')
        peer=self.entry['outbounds'][1]
        self.assertEqual(peer['protocol'],'vless')
        self.assertEqual(peer['streamSettings']['security'],'reality')
        self.assertIn('REPLACE_WITH_',peer['settings']['vnext'][0]['users'][0]['id'])

    def test_exit_direct_only_after_panel_service_user_assignment(self):
        self.assertEqual(self.exit['outbounds'][0]['tag'],'DIRECT')
        self.assertIn('Internal Squad', (ROOT/'docs/CASCADE_REFERENCE_2.5.10.md').read_text())
        self.assertIn('STAGING_ROLE_INSTALLER',(ROOT/'docs/CASCADE_REFERENCE_2.5.10.md').read_text())
        self.assertNotIn('TO_EXIT_VLESS', [x['tag'] for x in self.exit['outbounds']])

    def test_readme_first_command_and_references_are_not_falsely_published(self):
        content=(ROOT/'README.md').read_text()
        self.assertTrue(content.startswith('<div align="center">'))
        self.assertIn('2.5.11',content)
        self.assertIn('локальный непубликованный staging',content)
        self.assertIn('### 🟦 Карта 1',content)
        self.assertIn('### 🟪 Карта 2',content)
        self.assertEqual(content.count('```mermaid\nflowchart'),2)
        self.assertIn('2.5.9',content)
        self.assertIn('STAGING_ROLE_INSTALLER',(ROOT/'docs/CASCADE_REFERENCE_2.5.10.md').read_text())
        for name in ('cascade-entry-profile.reference.json','cascade-exit-profile.reference.json'):
            self.assertIn('examples/'+name,content)
        for link in re.findall(r'\]\(([^)]+)\)',content):
            target=link.split('#',1)[0]
            if target and not target.startswith(('https://','http://','mailto:')):
                self.assertTrue((ROOT/target).is_file(),link)


if __name__=='__main__':
    unittest.main()
