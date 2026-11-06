"""R30 phase-one acceptance: five feedback items, no live VPS mutations."""
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from common import ROOT
sys.path.insert(0,str(ROOT/'scripts'))
sys.path.insert(0,str(ROOT/'integrations'))
import terminal_ui as tui
import traffic_limits as traffic
from test_r29_tui_full_vps import FakeWindow


class PhaseOneTerminal(unittest.TestCase):
    def terminal(self,window=None):
        with mock.patch.object(tui.curses,'has_colors',return_value=False), \
             mock.patch.object(tui.curses,'curs_set'):
            return tui.Terminal(window or FakeWindow())

    def test_panel_accepts_public_ip_or_fqdn_only(self):
        for value,expected in [('panel.example.com','panel.example.com'),
                               ('Panel.Example.COM','panel.example.com'),
                               ('8.8.8.8','8.8.8.8')]:
            self.assertEqual(tui.validate_panel_target(value),expected)
        for bad in ('127.0.0.1','192.168.1.1','203.0.113.1','panel.local',
                    'https://panel.example.com','panel.example.com:443',
                    'panel.example.com/path','1.2.3.999','1.2.3.4/32'):
            with self.subTest(value=bad),self.assertRaises(ValueError):
                tui.validate_panel_target(bad)

    def test_wizard_argv_has_separate_limits_and_no_credentials(self):
        data={'mode':'ordinary','site':'01-atelier','domain':'node.example.com',
              'panel_ip':'panel.example.com','reality':'local','node_port':2323,
              'in_mbps':35,'out_mbps':55,'in_gib':140,'out_gib':175}
        args=tui.wizard_argv(data,fd=9)
        for flag,number in (('--traffic-in-mbps','35'),('--traffic-out-mbps','55'),
                            ('--traffic-in-gib','140'),('--traffic-out-gib','175'),
                            ('--node-port','2323')):
            self.assertEqual(args[args.index(flag)+1],number)
        self.assertNotIn('node.example.com',' '.join(args))
        self.assertNotIn('panel.example.com',' '.join(args))
        for key in ('in_mbps','out_mbps','in_gib','out_gib'):
            data[key]=None
        args=tui.wizard_argv(data,fd=9)
        self.assertNotIn('--traffic-in-mbps',args)
        self.assertNotIn('--traffic-out-gib',args)

    def test_esc_at_panel_returns_to_domain_then_preserves_values(self):
        inst=self.terminal()
        fields=iter(['S'*88,'node.example.com',None,'node.example.com','8.8.8.8'])
        names=[]
        inst.menu=lambda *a,**kw:0
        inst.themes=lambda:'01-atelier'
        def fake_field(name,*a,**kw):
            names.append(name)
            return next(fields)
        inst.field=fake_field
        inst.extra_settings=lambda *a:True
        inst.message=lambda *a,**k:13
        inst.logs=lambda *a,**k:0
        with mock.patch.object(tui,'has_root',return_value=True), \
             mock.patch.object(tui,'preinstall_state_guard',return_value=True), \
             mock.patch.object(tui,'secret_fd',return_value=os.open('/dev/null',os.O_RDONLY)):
            inst.wizard()
        self.assertEqual(names,['SECRET_KEY','ДОМЕН НОДЫ','АДРЕС ПАНЕЛИ',
                                'ДОМЕН НОДЫ','АДРЕС ПАНЕЛИ'])

    def test_invalid_panel_input_retries_without_losing_previous_steps(self):
        inst=self.terminal()
        entries=iter(['S'*88,'node.example.com','https://panel.example.com',
                      'panel.example.com'])
        names=[]
        inst.menu=lambda *a,**kw:0
        inst.themes=lambda:'01-atelier'
        def fake_field(name,*a,**kw):
            names.append(name)
            return next(entries)
        inst.field=fake_field
        inst.extra_settings=lambda *a:True
        inst.message=lambda *a,**k:13
        inst.logs=lambda *a,**k:0
        with mock.patch.object(tui,'has_root',return_value=True), \
             mock.patch.object(tui,'preinstall_state_guard',return_value=True), \
             mock.patch.object(tui,'secret_fd',return_value=os.open('/dev/null',os.O_RDONLY)):
            inst.wizard()
        self.assertEqual(names,['SECRET_KEY','ДОМЕН НОДЫ',
                       'АДРЕС ПАНЕЛИ','АДРЕС ПАНЕЛИ'])

    def test_first_step_escape_returns_to_main_without_install(self):
        inst=self.terminal()
        inst.menu=lambda *a,**kw:None
        inst.logs=lambda *a,**kw:self.fail('No installer after ESC')
        with mock.patch.object(tui,'has_root',return_value=True), \
             mock.patch.object(tui,'preinstall_state_guard',return_value=True):
            inst.wizard()

    def test_optional_menu_edits_independent_limits_and_can_go_back(self):
        inst=self.terminal()
        selections=iter([1,2,3,4,5,6,7])
        # note: index 7 is Continue after toggling index 6
        inst.menu=lambda *a,**kw:next(selections)
        fields=iter(['10','20','100','110'])
        inst.field=lambda *a,**kw:next(fields)
        options={'node_port':None,'in_mbps':None,'out_mbps':None,
                 'in_gib':None,'out_gib':None,'weekly_reboot':False,'no_reboot':True}
        self.assertTrue(inst.extra_settings('ordinary',options))
        self.assertEqual([options[k] for k in ('in_mbps','out_mbps','in_gib','out_gib')],
                         [10,20,100,110])
        self.assertTrue(options['weekly_reboot'])
        self.assertFalse(options['no_reboot'])

    def test_only_rollback_or_removal_confirmation_uses_two_choices(self):
        inst=self.terminal()
        options=[]
        def fake_menu(name,choices,*a,**kw):
            options.extend(choices);return 1
        inst.menu=fake_menu
        self.assertFalse(inst.confirm_removal('ОТКАТ','snapshot'))
        self.assertEqual([x[0] for x in options],
             ['Я осознаю что делаю и согласен','Я ошибся хочу вернуться назад'])
        # Backups remain free of an extra type-to-confirm question.
        inst=self.terminal()
        choices=iter([11,None]);calls=[]
        inst.menu=lambda *a,**k:next(choices)
        inst.action=lambda *a:calls.append(a)
        inst.installed()
        self.assertEqual(calls,[('--backup',)])

    def test_error_coloring_redactions_and_long_line_wrapping(self):
        clean=tui.safe_log_line('\x1b[31mERROR PrivateKey: ABCSECRET\x1b[0m')
        self.assertIn('ERROR',clean)
        self.assertIn('PrivateKey: [REDACTED]',clean)
        self.assertNotIn('ABCSECRET',clean)
        self.assertNotIn('\x1b',clean)
        self.assertEqual(tui.log_color(clean),4)
        self.assertEqual(tui.log_color('WARNING important'),3)
        self.assertEqual(tui.log_color('INSTALL_COMPLETE=PASS'),6)
        self.assertEqual(tui.log_color('Get:1 http://archive.ubuntu.com'),7)
        self.assertTrue(all(len(x)<=38 for x in tui.linewrap('alpha'*75,38)))

    def test_live_terminal_journal_stays_in_bounds(self):
        # A full subprocess, but only runs a disposable Python print().
        win=FakeWindow([27]*1000,width=70,height=22)
        inst=self.terminal(win)
        with mock.patch.object(tui.curses,'doupdate'):
            rc=inst.logs('ЖУРНАЛ',[sys.executable,'-c',
                'print("Get:1 success"); print("ERROR " + "x"*400); print("ERROR at tail")'])
        self.assertEqual(rc,0)
        self.assertTrue(any('ERROR' in line for _,_,line in win.contents))
        self.assertTrue(all(x+len(value)<70 for _,x,value in win.contents))

    def test_phase2_features_do_not_remove_phase1_functions(self):
        source=(ROOT/'scripts/terminal_ui.py').read_text()
        self.assertIn('def keys_screen',source)
        self.assertIn('def new_install_log',source)
        self.assertIn('ВЫЙТИ ИЗ УСТАНОВЩИКА',source)
        for existing in ('def extra_settings', 'def validate_panel_target',
                         'def confirm_removal', 'def wizard_argv'):
            self.assertIn(existing,source)


class PhaseOneLimits(unittest.TestCase):
    def fixture(self):
        return {'schema':1,'interface':'ens3','exempt_ports':[22,2222],
                'limits':{'in_mbps':50,'out_mbps':100,'in_gib':200,'out_gib':300}}

    def test_independent_directions_ports_and_drop_behavior(self):
        config=self.fixture(); rules=traffic.rules(config,{'in':33,'out':55})
        self.assertIn('hook input priority 10',rules)
        self.assertIn('hook output priority 10',rules)
        self.assertIn('tcp dport { 22, 2222 } accept',rules)
        self.assertIn('tcp sport { 22, 2222 } accept',rules)
        self.assertIn('limit rate over 6250000 bytes/second drop',rules)
        self.assertIn('limit rate over 12500000 bytes/second drop',rules)
        self.assertIn('quota incoming_quota { over 214748364800 bytes used 33 bytes',rules)
        self.assertIn('quota outgoing_quota { over 322122547200 bytes used 55 bytes',rules)
        self.assertNotIn('flush ruleset',rules)
        self.assertNotIn('delete table inet filter',rules)

    def test_policy_rejects_zero_all_invalid_port_and_excess_limits(self):
        with self.assertRaisesRegex(traffic.SafeStop,'ALL_LIMITS_DISABLED'):
            traffic.inputs(0,0,0,0)
        invalid=self.fixture();invalid['exempt_ports']=[0,22]
        with self.assertRaises(traffic.SafeStop):traffic.validate_config(invalid)
        with self.assertRaises(traffic.SafeStop):traffic.inputs(20001,0,0,0)

    def test_configure_verifies_nft_syntax_before_persistent_file(self):
        with tempfile.TemporaryDirectory() as directory:
            dest=Path(directory)
            (dest/'state').mkdir();(dest/'etc').mkdir()
            installed=dest/'state/INSTALL_COMPLETE';installed.write_text('yes')
            calls=[]
            def fake_run(cmd,**kwargs):calls.append(tuple(cmd));return ''
            with mock.patch.multiple(traffic,CONFIG=dest/'etc/traffic-limits.json',
                         USAGE=dest/'state/usage.json',INSTALLED=installed), \
                 mock.patch.object(traffic.os,'geteuid',return_value=0), \
                 mock.patch.object(traffic,'nft_objects',return_value=None), \
                 mock.patch.object(traffic,'network_identity',return_value=('ens3',[22,2222])), \
                 mock.patch.object(traffic,'run',side_effect=fake_run), \
                 mock.patch.object(traffic,'nft_apply',return_value='ACTIVE'), \
                 mock.patch.object(traffic,'setup_units'):
                self.assertEqual(traffic.main(['configure','--in-mbps','50']),0)
                self.assertTrue((dest/'etc/traffic-limits.json').is_file())
                self.assertIn(('nft','-c','-f','-'),calls)

    def test_manual_reset_requires_explicit_flag(self):
        with mock.patch.object(traffic.os,'geteuid',return_value=0), \
             mock.patch.object(traffic,'read_private',return_value=json.dumps(self.fixture())):
            with self.assertRaisesRegex(traffic.SafeStop,'CONFIRMATION_REQUIRED'):
                traffic.main(['reset'])

    def test_installer_dns_target_follows_strict_acl(self):
        installer=(ROOT/'install.sh').read_text()
        helper=installer.split("cat > \"$LIB/node_helper.py\" <<'PY_HELPER'\n",1)[1].split('\nPY_HELPER\n',1)[0]
        compile(helper,'embedded-node-helper','exec')
        pure=helper.split('def panel_addresses(value):',1)[1].split('def _dns_query(',1)[0]
        class Failure(Exception):pass
        def public(ip):
            
            try:address=ipaddress.IPv4Address(ip)
            except ValueError as exc:raise Failure('invalid address') from exc
            if not address.is_global:raise Failure('private address')
            return str(address)
        space={'Failure':Failure,'domain':lambda x:x,'public_ipv4':public,
               '_dns_query':lambda *a: {'8.8.8.8','1.1.1.1'}}
        exec('def panel_addresses(value):'+pure,space)
        self.assertEqual(space['panel_addresses']('panel.example.com'),
                         ('panel.example.com',['1.1.1.1','8.8.8.8']))
        self.assertEqual(space['panel_addresses']('8.8.8.8'),(None,['8.8.8.8']))
        self.assertIn("'panel_hostname':panel_hostname",installer)
        self.assertIn('for panel in "${PANEL_IPS[@]}"; do',installer)


if __name__=='__main__': unittest.main()
