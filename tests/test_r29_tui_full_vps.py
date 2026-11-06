"""R29 regression tests: redraw, resume-safe UX and single VPS assessment.

Only mocks and subprocesses on disposable files; never mutate actual VPS.
"""
import contextlib
import io
from pathlib import Path
import re
import subprocess
import sys
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
sys.path.insert(0,str(ROOT/'integrations'))
import terminal_ui as tui
import vps_connectivity as diag


class FakeWindow:
    def __init__(self,keys=(),width=85,height=29):
        self.height=height
        self.width=width
        self.keys=list(keys)
        self.updates=0
        self.contents=[]
    def getmaxyx(self):return self.height,self.width
    def keypad(self,*a):pass
    def erase(self):pass
    def addnstr(self,y,x,txt,maxlen,attrs):
        self.contents.append((y,x,txt[:maxlen]))
    def noutrefresh(self):self.updates+=1
    def getch(self):return self.keys.pop(0) if self.keys else -1
    def nodelay(self,*a):pass


class Presentation(unittest.TestCase):
    def terminal(self,win):
        with mock.patch.object(tui.curses,'has_colors',return_value=False),\
             mock.patch.object(tui.curses,'curs_set'):
            return tui.Terminal(win)

    def test_header_reports_actual_manifest_revision(self):
        import json
        build=json.loads((ROOT/'BUILD_MANIFEST.json').read_text())['build_id']
        self.assertEqual(tui.release_label(),'v2.5.18 r'+re.search(r'-r(\d+)-',build).group(1))

    def test_menu_is_not_timed_or_redrawn_without_input(self):
        win=FakeWindow([ord('0')])
        instance=self.terminal(win)
        with mock.patch.object(tui.curses,'doupdate') as d:
            self.assertIsNone(instance.menu('ГЛАВНОЕ МЕНЮ',[('ПРОВЕРКА VPS','одна проверка')]))
            self.assertEqual(win.updates,1)
            d.assert_called_once()
        text=' '.join(x[2] for x in win.contents)
        self.assertIn('NODE INSTALL',text)
        self.assertIn('ГЛАВНОЕ МЕНЮ',text)
        self.assertIn('❯',text)
        self.assertIn('╭',text)
        self.assertIn('╰',text)

    def test_navigation_changes_only_on_keystrokes(self):
        win=FakeWindow([tui.curses.KEY_DOWN,13])
        instance=self.terminal(win)
        with mock.patch.object(tui.curses,'doupdate') as d:
            self.assertEqual(instance.menu('ДЕЙСТВИЯ',[('A','one'),('B','two')]),1)
            self.assertEqual(d.call_count,2)

    def test_single_full_vps_action_not_a_submenu(self):
        instance=self.terminal(FakeWindow())
        calls=[]
        instance.vps_process=lambda mode:calls.append(mode) or {'kind':'RUSSIAN_VPS_DIAGNOSTICS'}
        instance.vps_view=lambda record:calls.append(record['kind'])
        instance.menu=lambda *a,**k:self.fail('VPS should not ask before initial read-only check')
        instance.vps()
        self.assertEqual(calls,['full','RUSSIAN_VPS_DIAGNOSTICS'])

    def test_cancelled_full_diagnostic_does_not_open_report(self):
        instance=self.terminal(FakeWindow())
        calls=[]
        instance.vps_process=lambda mode:calls.append(mode) or None
        instance.vps_view=lambda record:self.fail('cancelled report must not open')
        instance.vps()
        self.assertEqual(calls,['full'])

    def test_owned_speed_requires_explicit_destination_only(self):
        instance=self.terminal(FakeWindow([ord('s'),27],width=95,height=30))
        calls=[]
        instance.field=lambda *a,**k:'8.8.8.8'
        instance.vps_process=lambda mode,**kwargs:calls.append((mode,kwargs)) or {'kind':'IPERF3_SPEED','status':'INFO'}
        record={'kind':'RUSSIAN_VPS_DIAGNOSTICS','speed':{'status':'SKIPPED'}}
        with mock.patch.object(tui.curses,'doupdate'),mock.patch.object(tui.curses,'mousemask'),             mock.patch.object(tui.curses,'mouseinterval'):
            instance.vps_view(record)
        self.assertEqual(calls,[('speed',{'server':'8.8.8.8'})])
        self.assertEqual(record['speed']['kind'],'IPERF3_SPEED')

    def test_partial_installation_never_starts_new_install(self):
        instance=self.terminal(FakeWindow())
        calls=[]
        instance.menu=lambda *a,**k:0
        instance.action=lambda *a:calls.append(a)
        with mock.patch.object(tui,'has_root',return_value=True),mock.patch.object(tui,'preinstall_state_guard',return_value=False):
            instance.wizard()
        self.assertEqual(calls,[('--removal-plan','plan')])


class FullVPS(unittest.TestCase):
    def probes(self):
        return dict(local_probe=lambda:{'status':'INFO','os':'Ubuntu 24.04','architecture':'x86_64',
                                       'default_route':'PRESENT','ram_mib':4096},
                    service_probe=lambda **kwargs:{'kind':'SERVICES','results':[{'service':'GitHub','status':'REACHABLE','http':200,'ttfb_ms':82.2}]},
                    quality_probe=lambda name:{'type':'HTTPS_TTFB','host':name,'status':'INFO','p50_ms':82,'p95_ms':110,'jitter_ms':8,'spikes':0},
                    ping_probe=lambda name:{'type':'ICMP','status':'INFO','loss_pct':0,'sent':7,'received':7},
                    trace_probe=lambda name:{'status':'INFO','route':['1','2']},
                    edge_probe=lambda:{'status':'INFO','edge_colo':'TLL','observed_country':'EE'})

    def test_single_full_result_all_stages_speed_skipped_by_default(self):
        stages=[]
        report=diag.full_check(progress=stages.append,**self.probes())
        self.assertEqual(report['kind'],'FULL_VPS')
        self.assertEqual(len(stages),6)
        self.assertEqual(report['speed']['status'],'SKIPPED')
        self.assertEqual(report['status'],'INFO')
        text=diag.render_table(report)
        for term in ('СИСТЕМА','ПУБЛИЧНЫЕ СЕРВИСЫ','JITTER','PING','МАРШРУТ','EDGE','СКОРОСТЬ','GitHub','SKIPPED'):
            self.assertIn(term,text)

    def test_http_403_and_unreachable_are_review_not_false_pass(self):
        probes=self.probes()
        probes['service_probe']=lambda **kwargs:{'kind':'SERVICES','results':[{'service':'GitHub','status':'RESTRICTED_OR_PROTECTED','http':403}]}
        report=diag.full_check(**probes)
        self.assertEqual(report['status'],'REVIEW')
        self.assertNotIn('BLOCKED',diag.render_table(report))

    def test_independent_probe_failure_never_hides_rest(self):
        probes=self.probes()
        probes['ping_probe']=lambda host:(_ for _ in ()).throw(OSError('simulated'))
        report=diag.full_check(**probes)
        self.assertEqual(report['status'],'REVIEW')
        self.assertEqual(report['ping']['status'],'UNVERIFIED')
        self.assertEqual(report['services']['results'][0]['service'],'GitHub')
        self.assertEqual(report['speed']['status'],'SKIPPED')

    def test_speed_only_when_explicit_public_server(self):
        probes=self.probes()
        speeds=[]
        probes['speed_probe']=lambda ip,seconds:speeds.append((ip,seconds)) or {'status':'PASS'}
        diag.full_check(**probes)
        self.assertEqual(speeds,[])
        diag.full_check(speed_server='8.8.8.8',**probes)
        self.assertEqual(speeds,[('8.8.8.8',5)])
        for bad in ('127.0.0.1','192.168.1.1','203.0.113.2','::1','evil.example'):
            with self.assertRaises(ValueError):diag.full_check(speed_server=bad,**probes)

    def test_full_cli_help_and_table_mode(self):
        cp=subprocess.run(['python3',str(ROOT/'integrations/vps_connectivity.py'),'--help'],
                          capture_output=True,text=True,timeout=5)
        self.assertEqual(cp.returncode,0,cp.stderr)
        self.assertIn('full',cp.stdout)
        self.assertIn('--format',cp.stdout)


class GithubBootstrap(unittest.TestCase):
    def test_current_readme_uses_child_shell_and_keeps_existing_checkout(self):
        readme=(ROOT/'README.md').read_text()
        # The historic r29 bootstrap stays pinned, while the current release
        # label changes on every staging build. Test the contract, not r30 text.
        marker=re.search(r'^### 🐙 Исторический GitHub bootstrap · 2\.5\.18 r29 \(НЕ для r\d+\)$',
                         readme, re.M)
        self.assertIsNotNone(marker, 'Historic r29 bootstrap section missing')
        snippet=readme.split(marker.group(),1)[1].split('```bash\n',1)[1].split('\n```',1)[0]
        self.assertEqual(subprocess.run(['bash','-n'],text=True,input=snippet,capture_output=True,timeout=5).returncode,0)
        self.assertIn("bash <<'NODE_INSTALL_BOOTSTRAP'",snippet)
        self.assertIn('if [[ -d "$checkout/.git" ]]',snippet)
        self.assertIn('git clone --depth 1',snippet)
        self.assertIn('sha256sum --check SHA256SUMS',snippet)
        self.assertIn('bash ./install.sh --menu < /dev/tty',snippet)
        self.assertNotIn('rm -rf',snippet)
        self.assertNotIn('git reset --hard',snippet)
        # A failing child cannot exit an interactive parent Bash shell.
        cp=subprocess.run(['bash','-c',"bash <<'CHILD'\nset -e\nexit 1\nCHILD\nprintf 'PARENT_STILL_ALIVE\\n'"],
                          capture_output=True,text=True,timeout=5)
        self.assertIn('PARENT_STILL_ALIVE',cp.stdout)


if __name__=='__main__':unittest.main()
