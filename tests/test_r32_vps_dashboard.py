"""R32 acceptance: Russian VPS diagnostics, mouse wheel, independent checks, private exports.

All tests are offline and must never contact real hosts or mutate an actual VPS.
"""
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from common import ROOT
sys.path.insert(0,str(ROOT/'integrations'))
sys.path.insert(0,str(ROOT/'scripts'))
import vps_dashboard as vdash
import vps_report as reports
import terminal_ui as tui
from test_r29_tui_full_vps import FakeWindow


def sample():
    return {'schema':2,'kind':'RUSSIAN_VPS_DIAGNOSTICS','created_utc':'2026-11-06T01:00:00Z',
      'status':'REVIEW','limitations':['Только VPS, не клиент VPN'],
      'host':{'status':'INFO','os':'Ubuntu 24.04','kernel':'6.8.0','architecture':'x86_64',
              'cpu_model':'AMD Ryzen 7 TEST','cpu_logical':2,'ram_mib':2048,
              'ram_available_mib':1024,'disk_free_mib':16384,'disk_total_gib':20,
              'disk_free_gib':16,'services':{'ssh':'ACTIVE'}},
      'geo':{'status':'REVIEW','country_consensus':'НЕ ПОДТВЕРЖДЕНО','country_discrepancy':True,
             'ip_discrepancy':False,'observations':[
                 {'status':'INFO','source':'ipapi','ip':'8.8.8.8','country':'US','asn':'AS15169','organization':'Google LLC'},
                 {'status':'INFO','source':'ipinfo','ip':'8.8.8.8','country':'GB','asn':'AS15169','organization':'Google LLC'}]},
      'dns':{'status':'INFO','results':[{'host':'github.com','status':'PASS','ip':'140.82.112.3','ms':25}]},
      'services':{'status':'REVIEW','results':[
         {'service':'GitHub','status':'REACHABLE','http':200,'ttfb_ms':57.2},
         {'service':'Netflix','status':'RESTRICTED_OR_PROTECTED','http':403,'ttfb_ms':60.3},
         {'service':'ChatGPT','status':'AUTH_REQUIRED','http':401,'ttfb_ms':45}]},
      'ping':{'status':'INFO','results':[{'target':'Cloudflare 1.1.1.1','status':'MEASURED',
                                        'loss_pct':0,'avg_ms':14,'max_ms':25}]},
      'quality':{'status':'INFO','answered':5,'attempts':5,'failure_pct':0,'p50_ms':44,'p95_ms':53,
                 'jitter_ms':5,'spikes':0},
      'route':{'status':'INFO','route':['1 10.0.0.1','2 140.82.112.3']},
      'cdn':{'status':'INFO','edge_colo':'FRA','observed_country':'DE'},
      'speed':{'status':'SKIPPED'},'benchmark':{'status':'SKIPPED'}}


class Geo(unittest.TestCase):
    def test_only_fixed_https_geo_hosts(self):
        for host,path in (('localhost','/json'),('169.254.169.254','/'),('ipapi.co','/admin')):
            with self.assertRaises(ValueError):vdash.bounded_public_https_json(host,path)
        with self.assertRaises(ValueError):
            vdash.bounded_public_https_json('ipinfo.io','/json',resolve=lambda host:['127.0.0.1'])

    def test_geo_consensus_vs_discrepancy_does_not_invent_risk(self):
        api={'ip':'8.8.8.8','country_code':'US','asn':'AS15169','org':'Google'}
        info={'ip':'8.8.8.8','country':'GB','org':'AS15169 Google'}
        who={'ip':'8.8.8.8','country_code':'US','success':True,'connection':{'asn':15169,'org':'Google'}}
        def fetch(host,path):return {'ipapi.co':api,'ipinfo.io':info,'ipwho.is':who}[host]
        result=vdash.geo_reputation(fetch=fetch)
        self.assertTrue(result['country_discrepancy'])
        self.assertFalse(result['ip_discrepancy'])
        self.assertEqual(result['country_consensus'],'НЕ ПОДТВЕРЖДЕНО')
        self.assertNotIn('risk_score',result)

    def test_geo_error_isolated(self):
        def fetch(host,path):
            if host=='ipapi.co':raise TimeoutError('offline')
            return {'ip':'8.8.8.8','country':'US','country_code':'US','success':True}
        result=vdash.geo_reputation(fetch=fetch)
        self.assertEqual(result['observations'][0]['status'],'TIMEOUT')
        self.assertEqual(result['observations'][1]['status'],'INFO')

    def test_no_remote_injection_in_display_or_json(self):
        item=vdash.normalize_geo('ipapi',{'ip':'8.8.8.8','country':'US',
                                       'org':'Company\x1b[31m\nPrivateKey: SECRET'})
        self.assertNotIn('\x1b',str(item))
        self.assertNotIn('\n',item['organization'])


class Collection(unittest.TestCase):
    def test_service_matrix_aggregates_independent_failures_without_geoblock_claim(self):
        def probe(host,*,path='/',timeout=4):
            if host=='www.netflix.com':return {'status':'RESTRICTED_OR_PROTECTED','http':403}
            if host=='www.youtube.com':raise TimeoutError()
            return {'status':'REACHABLE','http':200,'ttfb_ms':45}
        progress=[]
        result=vdash.services_matrix(probe=probe,progress=progress.append,workers=2)
        self.assertGreaterEqual(len(result['results']),29)
        self.assertEqual(len(progress),len(result['results']))
        netflix=[r for r in result['results'] if r['service']=='Netflix'][0]
        self.assertEqual(netflix['status'],'RESTRICTED_OR_PROTECTED')
        self.assertNotIn('GEO_BLOCKED',str(result))
        self.assertEqual([r for r in result['results'] if r['service']=='YouTube'][0]['status'],'TIMEOUT')

    def test_full_report_independent_failures_do_not_hide_any_section(self):
        fake={key:lambda k=key:{'status':'INFO','check':k} for key in
              ('host','geo','dns','services','ping','quality','route','cdn')}
        fake['dns']=lambda:(_ for _ in ()).throw(OSError('network'))
        logs=[]
        result=vdash.run_full(progress=logs.append,probes=fake)
        self.assertEqual(result['status'],'REVIEW')
        self.assertEqual(result['dns']['status'],'UNVERIFIED')
        self.assertEqual(result['cdn']['status'],'INFO')
        self.assertEqual(len(logs),16)
        self.assertEqual(result['benchmark']['status'],'SKIPPED')

    def test_cpu_bench_bounded_and_cleans_up_disk_temp(self):
        with tempfile.TemporaryDirectory() as tmp:
            report=vdash.cpu_disk_benchmark(run_seconds=0.2,write_mib=8,temp_dir=tmp)
            self.assertEqual(report['kind'],'LIGHT_BENCH')
            self.assertGreater(report['cpu_iterations_per_sec'],0)
            self.assertEqual(report['disk_status'],'TEMP_FSYNC_COMPLETED')
            self.assertEqual(list(Path(tmp).iterdir()),[])

    def test_cli_exposes_stream_mode_not_shell_network_scripts(self):
        cp=subprocess.run([sys.executable,'-I',str(ROOT/'integrations/vps_dashboard.py'),'--help'],
                          text=True,capture_output=True,timeout=5)
        self.assertEqual(cp.returncode,0,cp.stderr)
        self.assertIn('bench',cp.stdout)
        self.assertIn('speed',cp.stdout)


class Export(unittest.TestCase):
    def test_russian_sections_and_correct_http_semantics(self):
        record=sample()
        text=reports.plain_text(record)
        self.assertIn('ПАРАМЕТРЫ СЕРВЕРА',text)
        self.assertIn('IP QUALITY',text)
        self.assertIn('ЗАДЕРЖКА HTTPS',text)
        self.assertIn('403/451 · ограничение/защита',text)
        self.assertNotIn('УСПЕШНО ЗАБЛОКИРОВАН',text)
        self.assertEqual(len(reports.sections(record)),9)

    def test_png_is_valid_rgb_and_does_not_require_pillow(self):
        value=reports.png_bytes(sample())
        self.assertTrue(value.startswith(b'\x89PNG\r\n\x1a\n'))
        self.assertGreater(len(value),2000)
        width,height=struct.unpack('>II',value[16:24])
        self.assertEqual(width,1340)
        self.assertLessEqual(height,7800)
        self.assertEqual(value[-8:-4],b'IEND')

    def test_three_private_files_unique_and_no_unsafe_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp)/'reports'
            d.mkdir(mode=0o700)
            paths=[reports.export_report(sample(),kind,folder=d) for kind in ('txt','png','json')]
            self.assertEqual(len(set(paths)),3)
            self.assertEqual({x.suffix for x in paths},{'.txt','.png','.json'})
            for p in paths:
                self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
                self.assertGreater(p.stat().st_size,400)
            self.assertIn('Ubuntu',paths[0].read_text(encoding='utf-8'))
            self.assertEqual(json.loads(paths[2].read_text())['kind'],'RUSSIAN_VPS_DIAGNOSTICS')
            d.chmod(0o755)
            with self.assertRaises(OSError):reports.export_report(sample(),'txt',folder=d)
            d.chmod(0o700)
            link=Path(tmp)/'symlink';link.symlink_to(d,target_is_directory=True)
            with self.assertRaises(OSError):reports.export_report(sample(),'txt',folder=link)

    def test_invalid_report_rejected_before_creating_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'never-created'
            with self.assertRaises(ValueError):reports.export_report({'kind':'FAKE'},'png',folder=path)
            self.assertFalse(path.exists())

    def test_no_control_characters_in_tui_lines(self):
        record=sample()
        record['geo']['observations'][0]['organization']='TERM\x1b[2J broken'
        raw=reports.plain_text(record)
        self.assertNotIn('\x1b',raw)


class UI(unittest.TestCase):
    def terminal(self,keys=()):
        window=FakeWindow(keys,width=98,height=30)
        with mock.patch.object(tui.curses,'has_colors',return_value=False),\
             mock.patch.object(tui.curses,'curs_set'):
            ui=tui.Terminal(window)
        return ui,window

    def test_first_menu_launches_full_and_renders_result(self):
        ui,win=self.terminal()
        calls=[]
        ui.vps_process=lambda mode:calls.append(mode) or sample()
        ui.vps_view=lambda record:calls.append(record['kind'])
        ui.vps()
        self.assertEqual(calls,['full','RUSSIAN_VPS_DIAGNOSTICS'])

    def test_mouse_wheel_down_scroll_and_escape_back(self):
        events=[tui.curses.KEY_MOUSE,27]
        ui,win=self.terminal(events)
        states=iter([(0,12,12,0,getattr(tui.curses,'BUTTON5_PRESSED',0))])
        with mock.patch.object(tui.curses,'doupdate'),\
             mock.patch.object(tui.curses,'mousemask'),\
             mock.patch.object(tui.curses,'mouseinterval'),\
             mock.patch.object(tui.curses,'getmouse',side_effect=lambda:next(states)):
            ui.vps_view(sample())
        text=' '.join(x[2] for x in win.contents)
        self.assertIn('РЕЗУЛЬТАТЫ ПРОВЕРКИ VPS',text)
        self.assertIn('Строки',text)

    def test_navigation_and_png_export_hotkey(self):
        ui,_=self.terminal([ord('3'),ord('e'),ord('b'),27])
        stages=[]
        ui.vps_export=lambda record:stages.append('export')
        ui.vps_process=lambda mode:stages.append(mode) or {'kind':'LIGHT_BENCH','status':'INFO'}
        with mock.patch.object(tui.curses,'doupdate'),mock.patch.object(tui.curses,'mousemask'),\
             mock.patch.object(tui.curses,'mouseinterval'):
            ui.vps_view(sample())
        self.assertEqual(stages,['export','bench'])


class Protocol(unittest.TestCase):
    def test_structured_child_report_stream_with_no_raw_shell_output(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            f=Path(folder)/'vps_dashboard.py'
            payload=json.dumps(sample(),ensure_ascii=False)
            f.write_text('import json\n'
                         "print(json.dumps({'type':'progress','message':'ГОТОВО: NET'}),flush=True)\n"
                         +f"print(json.dumps({{'type':'result','report':json.loads({payload!r})}}),flush=True)\n")
            win=FakeWindow([-1],width=88,height=29)
            with mock.patch.object(tui.curses,'has_colors',return_value=False), \
                 mock.patch.object(tui.curses,'curs_set'), \
                 mock.patch.object(tui.curses,'doupdate'), \
                 mock.patch.object(tui,'INTEGRATIONS',Path(folder)):
                ui=tui.Terminal(win)
                report=ui.vps_process('full')
            self.assertEqual(report['kind'],'RUSSIAN_VPS_DIAGNOSTICS')
            self.assertIn('ГОТОВО: NET',' '.join(x[2] for x in win.contents))

    def test_escape_cancels_only_child_not_parent(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            f=Path(folder)/'vps_dashboard.py'
            f.write_text('import time\nprint("started",flush=True)\ntime.sleep(8)\n')
            win=FakeWindow([27],width=88,height=29)
            with mock.patch.object(tui.curses,'has_colors',return_value=False), \
                 mock.patch.object(tui.curses,'curs_set'), \
                 mock.patch.object(tui.curses,'doupdate'), \
                 mock.patch.object(tui,'INTEGRATIONS',Path(folder)):
                ui=tui.Terminal(win)
                self.assertIsNone(ui.vps_process('full'))
            self.assertGreater(win.updates,0)


if __name__=='__main__':unittest.main()
