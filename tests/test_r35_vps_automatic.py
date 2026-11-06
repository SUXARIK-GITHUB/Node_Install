"""r35: first VPS item does all bounded checks without asking any questions.

No test contacts a real IP or installs packages; FakeTLS models the HTTPS
speedtest endpoint so requests, limits and failure semantics are inspectable.
"""
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

from common import ROOT
sys.path.insert(0,str(ROOT/'scripts'))
sys.path.insert(0,str(ROOT/'integrations'))
import terminal_ui as tui
import vps_dashboard as vdash
import vps_report as vrep
from test_r29_tui_full_vps import FakeWindow


class FakeTLS:
    def __init__(self,code=200,data=b'',extra_headers=b''):
        self.sent=bytearray()
        self.raw=(f'HTTP/1.1 {code} TEST\r\n'.encode() +
                  extra_headers + b'\r\n'+data)
        self.timeout=None
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def settimeout(self,timeout):self.timeout=timeout
    def sendall(self,data):self.sent.extend(data)
    def makefile(self,mode):return io.BytesIO(self.raw)


class FakeContext:
    def __init__(self,tls):self.tls=tls;self.names=[];self.minimum_version=None
    def wrap_socket(self,raw,*,server_hostname):
        self.names.append(server_hostname)
        return self.tls


class NetworkSafety(unittest.TestCase):
    def test_download_fixed_hostname_tls_request_and_byte_bound(self):
        tls=FakeTLS(data=b'x'*1024,extra_headers=b'Content-Length: 1024\r\n')
        ctx=FakeContext(tls);connections=[]
        def connector(target,timeout):
            connections.append((target,timeout));return FakeTLS()
        with mock.patch.object(vdash.ssl,'create_default_context',return_value=ctx):
            result=vdash._speed_https_exchange('download',ip='8.8.8.8',byte_count=1024,connector=connector)
        self.assertGreater(result,0)
        self.assertEqual(ctx.names,['speed.cloudflare.com'])
        self.assertEqual(connections,[(('8.8.8.8',443),vdash.AUTO_SPEED_TIMEOUT)])
        self.assertTrue(tls.sent.startswith(b'GET /__down?bytes=1024 HTTP/1.1\r\n'))
        self.assertIn(b'Host: speed.cloudflare.com\r\n',tls.sent)
        self.assertIn(b'Accept-Encoding: identity\r\n',tls.sent)
        self.assertEqual(tls.timeout,vdash.AUTO_SPEED_TIMEOUT)

    def test_upload_is_bounded_and_no_credentials(self):
        tls=FakeTLS(code=204)
        ctx=FakeContext(tls)
        with mock.patch.object(vdash.ssl,'create_default_context',return_value=ctx):
            value=vdash._speed_https_exchange('upload',ip='8.8.8.8',byte_count=1024,
                                              connector=lambda *a,**k:FakeTLS())
        self.assertGreater(value,0)
        sent=bytes(tls.sent)
        self.assertIn(b'POST /__up HTTP/1.1',sent)
        self.assertIn(b'Content-Length: 1024',sent)
        head,body=sent.split(b'\r\n\r\n',1)
        self.assertEqual(len(body),1024)
        self.assertEqual(body,b'\x00'*1024)
        self.assertNotIn(b'Authorization:',head)
        self.assertNotIn(b'Cookie:',head)

    def test_bad_ip_no_connection(self):
        for ip in ('127.0.0.1','169.254.169.254','192.168.1.1'):
            with self.subTest(ip=ip):
                with self.assertRaises(ValueError):
                    vdash._speed_https_exchange('download',ip=ip,byte_count=16,
                                               connector=lambda *a,**k:self.fail('PRIVATE_DESTINATION'))

    def test_reject_oversize_wrong_http_and_direction(self):
        bad=FakeTLS(data=b'abc',extra_headers=b'Content-Length: 4096\r\n')
        with mock.patch.object(vdash.ssl,'create_default_context',return_value=FakeContext(bad)):
            with self.assertRaisesRegex(ValueError,'LENGTH_MISMATCH'):
                vdash._speed_https_exchange('download',ip='8.8.8.8',byte_count=8,
                                           connector=lambda *a,**k:FakeTLS())
        with self.assertRaises(ValueError):
            vdash._speed_https_exchange('download',ip='8.8.8.8',byte_count=vdash.AUTO_SPEED_BYTES+1)
        with self.assertRaises(ValueError):
            vdash._speed_https_exchange('oops',ip='8.8.8.8')
        bad_upload=FakeTLS(code=403)
        with mock.patch.object(vdash.ssl,'create_default_context',return_value=FakeContext(bad_upload)):
            with self.assertRaisesRegex(ValueError,'UPLOAD_HTTP_ERROR'):
                vdash._speed_https_exchange('upload',ip='8.8.8.8',byte_count=16,
                                           connector=lambda *a,**k:FakeTLS())

    def test_speed_auto_success_and_partial_failure(self):
        calls=[]
        def exchange(direction,*,ip,byte_count):
            calls.append((direction,ip,byte_count))
            if direction=='upload':raise TimeoutError()
            return 18.75
        report=vdash.automatic_speed_test(resolver=lambda host:['8.8.8.8'],exchange=exchange)
        self.assertEqual(report['status'],'PARTIAL')
        self.assertEqual(report['download_mbps'],18.75)
        self.assertIsNone(report['upload_mbps'])
        self.assertEqual(report['upload_reason'],'TimeoutError')
        self.assertEqual(calls,[('download','8.8.8.8',vdash.AUTO_SPEED_BYTES),
                                ('upload','8.8.8.8',vdash.AUTO_SPEED_BYTES)])
        both=vdash.automatic_speed_test(resolver=lambda h:['8.8.8.8'],exchange=lambda *a,**k:100.0)
        self.assertEqual(both['status'],'MEASURED')
        self.assertEqual(both['upload_mbps'],100.0)

    def test_speed_no_dns_no_fabricated_numbers(self):
        report=vdash.automatic_speed_test(resolver=lambda _:['127.0.0.1'],
            exchange=lambda *a,**k:self.fail('DNS_FAILURE_NOT_ALLOWED'))
        self.assertEqual(report['status'],'UNVERIFIED')
        self.assertIsNone(report['download_mbps'])
        self.assertIsNone(report['upload_mbps'])


class AutomaticFlow(unittest.TestCase):
    def test_full_runs_all_sections_with_no_settings(self):
        keys=('host','geo','dns','services','ping','quality','route','cdn','speed','benchmark')
        probes={key:(lambda name=key:{'status':'INFO','sample':name}) for key in keys}
        stages=[]
        report=vdash.run_full(progress=stages.append,probes=probes)
        self.assertEqual(report['mode'],'BOUNDED_AUTOMATIC')
        self.assertEqual(len(stages),20)
        for key in keys:self.assertEqual(report[key]['sample'],key)
        self.assertEqual(report['status'],'INFO')

    def test_independent_failure_keeps_other_bounded_checks(self):
        keys=('host','geo','dns','services','ping','quality','route','cdn','speed','benchmark')
        probes={key:(lambda name=key:{'status':'INFO','sample':name}) for key in keys}
        probes['speed']=lambda:(_ for _ in ()).throw(TimeoutError('NO_NETWORK'))
        report=vdash.run_full(probes=probes)
        self.assertEqual(report['speed']['status'],'TIMEOUT')
        self.assertEqual(report['benchmark']['sample'],'benchmark')
        self.assertEqual(report['status'],'REVIEW')

    def test_results_explain_unavailable_speed_without_prompt(self):
        report={'kind':'RUSSIAN_VPS_DIAGNOSTICS','created_utc':'2026-11-06',
                'speed':{'kind':'AUTO_HTTPS_SPEED','status':'PARTIAL',
                         'server':'speed.cloudflare.com','download_mbps':10,
                         'upload_mbps':None,'upload_reason':'TimeoutError'},
                'benchmark':{'status':'INFO','cpu_iterations_per_sec':1000,
                             'memory_copy_8mib_ms':1.3,'disk_write_mib_s':100,
                             'disk_status':'TEMP_FSYNC_COMPLETED'}}
        rendered=vrep.plain_text(report)
        self.assertIn('АВТОМАТИЧЕСКАЯ ЭКСПРЕСС-ПРОВЕРКА',rendered)
        self.assertIn('Не измерено',rendered)
        self.assertIn('speed.cloudflare.com',rendered)
        self.assertNotIn('Нажмите B',rendered)
        self.assertNotIn('Нажмите S',rendered)
        self.assertEqual(len(vrep.sections(report)),9)

    def test_first_item_and_results_never_request_user_input(self):
        win=FakeWindow([ord('s'),ord('S'),ord('b'),ord('B'),27],width=98,height=30)
        with mock.patch.object(tui.curses,'has_colors',return_value=False),\
             mock.patch.object(tui.curses,'curs_set'):
            ui=tui.Terminal(win)
        record={'schema':2,'kind':'RUSSIAN_VPS_DIAGNOSTICS','status':'INFO',
                'speed':{'status':'MEASURED'},'benchmark':{'status':'INFO'}}
        actions=[]
        ui.vps_process=lambda mode,**kw:actions.append(mode) or record
        ui.field=lambda *args,**kw:self.fail('USER_INPUT_NOT_ALLOWED')
        ui.menu=lambda *args,**kw:self.fail('SUBMENU_NOT_ALLOWED')
        with mock.patch.object(tui.curses,'doupdate'),\
             mock.patch.object(tui.curses,'mousemask'),\
             mock.patch.object(tui.curses,'mouseinterval'):
            ui.vps()
        self.assertEqual(actions,['full'])
        self.assertNotIn('S iperf',' '.join(x[2] for x in win.contents))

    def test_cli_full_passes_all_probes_without_server_arg(self):
        # The mode emits a result and progress events, without parsing input().
        events=[]
        with mock.patch.object(vdash,'run_full',return_value={'kind':'RUSSIAN_VPS_DIAGNOSTICS'}) as full,\
             mock.patch.object(vdash,'_safe_emit',side_effect=events.append):
            code=vdash.main(['full'])
        self.assertEqual(code,0)
        full.assert_called_once()
        self.assertEqual(events[-1]['type'],'result')


if __name__=='__main__':unittest.main()
