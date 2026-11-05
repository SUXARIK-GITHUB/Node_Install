"""R23 opt-in transports, conditional tuning, real TLS probe and visual QA.

All tests are offline; local TLS fixture binds only 127.0.0.1. No host sysctl,
Docker, firewall, Panel, real domain or external network changes.
"""
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, HTTPServer

from common import ROOT
sys.path[:0] = [str(ROOT/'scripts'),str(ROOT/'integrations')]
import network_tuning as net
import selfsteal_runtime_probe as selfsteal
import throughput_probe as throughput
import optional_transports as ot
import quality_probe as probe
import site_visual_review as visual
import staging_web_deploy as web
import test_r20_rich_site as r20
import test_r22_network_compare as oldnet
import transport_profile_audit as transport


class OptionalTransports(unittest.TestCase):
    def test_xhttp_tls_staging_is_loopback_and_grpc_only(self):
        files = ot.xhttp_tls('node.example.test',33643,'/api/AbCdEf1234567890')
        cfg = json.loads(files['profile-xhttp-tls.json'])
        self.assertEqual(cfg['inbounds'][0]['listen'],'127.0.0.1')
        self.assertEqual(cfg['inbounds'][0]['streamSettings']['security'],'none')
        self.assertEqual(cfg['inbounds'][0]['streamSettings']['network'],'xhttp')
        self.assertIn(b'grpc_pass grpc://127.0.0.1:33643;',files['nginx-location.conf'])
        self.assertNotIn(b'listen 443',files['nginx-location.conf'])
        report=transport.audit(cfg)
        self.assertEqual(report['status'],'REVIEW', report)

    def test_generator_denies_ports_paths_and_domains(self):
        for value in ('/../etc/passwd','/bad path','/x;return-1','/tiny'):
            with self.subTest(value=value), self.assertRaises(ot.Invalid):
                ot.xhttp_tls('node.example.test',33643,value)
        for p in (80,443,2222,3000):
            with self.subTest(port=p), self.assertRaises(ot.Invalid):
                ot.xhttp_tls('node.example.test',p,'/api/AbCdEf1234567890')
        with self.assertRaises(ot.Invalid):
            ot.xhttp_tls('bad_domain',33643,'/api/AbCdEf1234567890')

    def test_hysteria2_optional_udp_tls_auth_and_no_cascade_entry(self):
        files=ot.hysteria2('node.example.test',443)
        cfg=json.loads(files['profile-hysteria2.json'])
        inbound=cfg['inbounds'][0]
        self.assertEqual(inbound['protocol'],'hysteria')
        self.assertEqual(inbound['streamSettings']['security'],'tls')
        self.assertGreater(len(inbound['settings']['users'][0]['auth']),32)
        self.assertIn(b'Never use this direct-exit profile on cascade ENTRY',files['REVIEW.txt'])
        self.assertEqual(transport.audit(cfg)['status'],'REVIEW')
        with self.assertRaises(ot.Invalid):
            ot.hysteria2('node.example.test',443,'short-password')

    def test_amneziawg_keys_unique_matching_and_private(self):
        files=ot.awg2('node.example.test',51820)
        server=files['awg0-server.conf'].decode()
        client=files['client-reference.conf'].decode()
        import re
        self.assertIn('H4 = ',server)
        heads=[]
        for n in range(1,5):
            match=re.search(r'^H'+str(n)+r' = ([0-9]+)-([0-9]+)$',server,re.M)
            self.assertIsNotNone(match)
            heads.append((int(match.group(1)),int(match.group(2))))
            self.assertIn(match.group(0),client)
        for i,(lo,hi) in enumerate(heads):
            self.assertLess(lo,hi)
            for j,(otherlo,otherhi) in enumerate(heads):
                if i!=j:self.assertTrue(hi<otherlo or otherhi<lo)

        self.assertEqual(server.split('PresharedKey = ')[1].splitlines()[0],
                         client.split('PresharedKey = ')[1].splitlines()[0])
        self.assertNotEqual(server.split('PrivateKey = ')[1].splitlines()[0],
                            client.split('PrivateKey = ')[1].splitlines()[0])
        self.assertIn(b'WITHOUT EXPLICITLY CONFIGURED',files['REVIEW.txt'].upper())

    def test_private_bundle_created_0600_no_repo_write(self):
        data=ot.xhttp_tls('node.example.test',33643,'/api/AbCdEf1234567890')
        with tempfile.TemporaryDirectory() as td:
            dest=Path(td)/'new-secure-bundle'
            self.assertEqual(ot.write_bundle(dest,data),None)
            self.assertEqual(dest.stat().st_mode & 0o777,0o700)
            self.assertEqual(set(p.name for p in dest.iterdir()),set(data))
            self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in dest.iterdir()))
            with self.assertRaises(ot.Invalid):ot.write_bundle(dest,data)
        with self.assertRaises(ot.Invalid):
            ot.write_bundle(ROOT/'should-not-create-private-secret-dir',data)


class NginxXHTTP(unittest.TestCase):
    def fixture(self,td):
        root=Path(td)
        fixture=r20.RichCover()
        site,original,conf=fixture.setup_fixture(root)
        app=web.NodeWeb(root,run=fixture.runner(site),css_check=lambda *_:None)
        return app,site,conf

    def test_staging_xhttp_route_atomic_and_reversible(self):
        with tempfile.TemporaryDirectory() as td:
            app,site,orig=self.fixture(td)
            text=app.xhttp_tls_install('site.example.test','/api/AbCdEf1234567890',33643,backend_check=False)
            self.assertIn('DEPLOY=PASS',text)
            self.assertEqual(app.status()['xhttp_tls'],'active')
            self.assertIn(b'grpc_pass grpc://127.0.0.1:33643;',app.webconf.read_bytes())
            self.assertIn(b'location / { return 404; }',app.webconf.read_bytes())
            self.assertEqual(app.xhttp_tls_rollback(),'XHTTP_ROLLBACK=PASS')
            self.assertEqual(app.webconf.read_bytes(),orig)
            self.assertEqual(app.status()['xhttp_tls'],'rolled_back')

    def test_site_can_be_added_after_xhttp_and_rollback_preserves_route(self):
        with tempfile.TemporaryDirectory() as td:
            app,site,original=self.fixture(td)
            app.xhttp_tls_install('site.example.test','/api/AbCdEf1234567890',33643,backend_check=False)
            with_route=app.webconf.read_bytes()
            app.site_install('01-atelier','site.example.test',rich_pages=True)
            self.assertIn(b'VKARMANI_R23_XHTTP_TLS_BEGIN',app.webconf.read_bytes())
            self.assertIn(b'VKARMANI_R20_RICH_BEGIN',app.webconf.read_bytes())
            with self.assertRaisesRegex(web.DeployError,'ROLLBACK_MANAGED_SITE'):
                app.xhttp_tls_rollback()
            self.assertEqual(app.site_rollback(),'SITE_ROLLBACK=PASS')
            self.assertEqual(app.webconf.read_bytes(),with_route)
            self.assertEqual(app.xhttp_tls_rollback(),'XHTTP_ROLLBACK=PASS')
            self.assertEqual(app.webconf.read_bytes(),original)

    def test_xhttp_does_not_change_active_managed_site(self):
        with tempfile.TemporaryDirectory() as td:
            app,site,_=self.fixture(td)
            app.site_install('01-atelier','site.example.test',rich_pages=True)
            html=(site/'index.html').read_bytes()
            with self.assertRaisesRegex(web.DeployError,'ROLLBACK_MANAGED_SITE'):
                app.xhttp_tls_install('site.example.test','/api/AbCdEf1234567890',33643,backend_check=False)
            self.assertEqual((site/'index.html').read_bytes(),html)

    def test_runtime_failure_rolls_back_nginx(self):
        with tempfile.TemporaryDirectory() as td:
            app,site,original=self.fixture(td)
            count=[0]
            def fail_once(argv):
                if argv[:2]==['nginx','-t']:
                    count[0]+=1
                    if count[0]==2: raise web.DeployError('SIMULATED_NGINX_T_FAIL')
                return b''
            app.run=fail_once
            with self.assertRaisesRegex(web.DeployError,'SIMULATED_NGINX_T_FAIL'):
                app.xhttp_tls_install('site.example.test','/api/AbCdEf1234567890',33643,backend_check=False)
            self.assertEqual(app.webconf.read_bytes(),original)
            self.assertEqual(app.status()['xhttp_tls'],'rolled_back')

    def test_real_nginx_fragment_syntax_in_isolated_config(self):
        if not shutil.which('nginx'):self.skipTest('nginx not installed')
        fragment=ot.xhttp_tls('node.example.test',33643,'/api/AbCdEf1234567890')['nginx-location.conf'].decode()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);root.chmod(0o755)
            conf=root/'nginx.conf'
            conf.write_text('worker_processes 1;\npid '+str(root/'nginx.pid')+';\n'
                'error_log '+str(root/'err.log')+' warn;\n'
                'events { worker_connections 64; }\nhttp { server { '
                'listen 127.0.0.1:39088; server_name node.example.test;\n'
                +fragment+'\nlocation / { return 404; } } }\n')
            cp=subprocess.run(['nginx','-t','-c',str(conf)],capture_output=True,text=True,timeout=8)
            self.assertEqual(cp.returncode,0,cp.stderr)


class SelfstealSocketRuntime(unittest.TestCase):
    def test_actual_nginx_unix_tls_with_proxy_v1(self):
        if not (shutil.which('nginx') and shutil.which('openssl')):
            self.skipTest('Nginx/OpenSSL missing')
        import time
        with tempfile.TemporaryDirectory(prefix='vk-selfsteal-r23-') as td:
            root=Path(td);root.chmod(0o755)
            cert=root/'cert.pem';key=root/'key.pem';sock=root/'cover.sock'
            cmd=['openssl','req','-x509','-newkey','rsa:2048','-sha256','-nodes',
                 '-keyout',str(key),'-out',str(cert),'-days','2',
                 '-subj','/CN=node.example.test','-addext','subjectAltName=DNS:node.example.test']
            cp=subprocess.run(cmd,capture_output=True,text=True,timeout=15)
            self.assertEqual(cp.returncode,0,cp.stderr)
            conf=root/'nginx.conf'
            conf.write_text('worker_processes 1;\npid '+str(root/'nginx.pid')+';\n'
                'error_log '+str(root/'error.log')+' warn;\n'
                'events { worker_connections 64; }\nhttp { server { '
                'listen unix:'+str(sock)+' ssl proxy_protocol; '
                'server_name node.example.test; '
                'ssl_certificate '+str(cert)+'; ssl_certificate_key '+str(key)+'; '
                'location / { return 200 \"LOCAL-TLS-SITE\"; } } }\n')
            test=subprocess.run(['nginx','-t','-c',str(conf)],capture_output=True,text=True,timeout=8)
            self.assertEqual(test.returncode,0,test.stderr)
            process=subprocess.Popen(['nginx','-c',str(conf),'-g','daemon off;'],
                                     stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                for _ in range(60):
                    if sock.exists():break
                    if process.poll() is not None:self.fail('Nginx exited unexpectedly')
                    time.sleep(.05)
                self.assertTrue(sock.is_socket())
                report=selfsteal.probe('node.example.test',sock,proxy_v1=True,cafile=cert)
                self.assertEqual(report['status'],'PASS',report)
                self.assertEqual(report['http_code'],200)
                self.assertEqual(report['proxy_protocol'],'v1')
                self.assertNotIn('node.example.test',json.dumps(report))
                with self.assertRaises(selfsteal.CheckError):
                    selfsteal.probe('wrong.example.test',sock,proxy_v1=True,cafile=cert)
            finally:
                process.terminate()
                try:process.wait(timeout=4)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=4)


class NetworkTuning(unittest.TestCase):
    def snapshots(self):
        before=oldnet.snapshot(); after=deepcopy(before)
        before['parameters'].update({'somaxconn':'4096','tcp_max_syn_backlog':'4096'})
        after['parameters'].update({'somaxconn':'4096','tcp_max_syn_backlog':'4096'})
        after['tcp_host_counters']['counters']['ListenOverflows']+=3
        after['tcp_host_counters']['counters']['ListenDrops']+=2
        return before,after

    def test_only_backlog_recommended_if_drops_measured(self):
        a,b=self.snapshots()
        plan=net.suggest(a,b,30)
        self.assertEqual(plan['status'],'RECOMMENDED')
        self.assertEqual(set(plan['recommendations']),set(net.PARAMS.values()))
        self.assertTrue(all(val['after']==8192 for val in plan['recommendations'].values()))
        self.assertEqual(net.suggest(a,a,30)['status'],'NO_CHANGE')
        c=deepcopy(b);c['network_interface']='tun42'
        self.assertEqual(net.suggest(a,c,30)['status'],'NO_CHANGE')

    def test_measured_transaction_apply_rollback_and_failures(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            state=root/'var/lib/vkarmani-node'
            state.mkdir(parents=True)
            (root/'etc/sysctl.d').mkdir(parents=True)
            (state/'owned-installation').touch()
            (state/'INSTALL_COMPLETE').write_text('version=2.5.18\n')
            a,b=self.snapshots();plan=net.suggest(a,b,30)
            live={k:4096 for k in net.PARAMS.values()}
            calls=[]
            def get(k):return live[k]
            def run(argv):
                calls.append(argv)
                if argv[1]=='-p':
                    for k in live:live[k]=8192
                elif argv[1]=='-w':
                    k,v=argv[2].split('=');live[k]=int(v)
            self.assertEqual(net.transact(plan,'apply',root=root,run=run,get=get),
                             'NETWORK_TUNING=APPLIED_MEASURED_BACKLOG_ONLY')
            self.assertEqual(live,{k:8192 for k in live})
            self.assertEqual(net.transact(None,'rollback',root=root,run=run,get=get),
                             'NETWORK_TUNING=ROLLBACK_PASS')
            self.assertEqual(live,{k:4096 for k in live})
            self.assertFalse((root/'etc/sysctl.d/98-vkarmani-measured.conf').exists())
            with self.assertRaises(net.TuneError):net.transact(plan,'apply',root=root,run=run,get=get)

    def test_foreign_sysctl_file_prevents_apply(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);state=root/'var/lib/vkarmani-node';state.mkdir(parents=True)
            conf=root/'etc/sysctl.d';conf.mkdir(parents=True)
            (state/'owned-installation').touch();(state/'INSTALL_COMPLETE').write_text('version=2.5.18\n')
            target=conf/'98-vkarmani-measured.conf';target.write_text('admin=1\n')
            a,b=self.snapshots();plan=net.suggest(a,b,30)
            with self.assertRaisesRegex(net.TuneError,'ALREADY_OWNED_OR_FOREIGN'):
                net.transact(plan,'apply',root=root,run=lambda *_:None,get=lambda *_:4096)
            self.assertEqual(target.read_text(),'admin=1\n')


class TLSQualityProbe(unittest.TestCase):
    def test_denies_private_remote_except_explicit_localtest(self):
        for ip in ('10.0.0.1','192.168.1.1','127.0.0.1','0.0.0.0'):
            with self.assertRaises(probe.ProbeError):probe.validate('node.example.test',ip,443,1)
        self.assertEqual(probe.validate('node.example.test','127.0.0.1',443,1,True),'127.0.0.1')
        with self.assertRaises(probe.ProbeError):probe.validate('node.example.test','127.0.0.1',80,1,True)

    def test_bounded_real_tls_to_loopback_with_ca_and_sni(self):
        if not shutil.which('openssl'):self.skipTest('OpenSSL not installed')
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);cert=root/'cert.pem';key=root/'key.pem'
            cmd=['openssl','req','-x509','-newkey','rsa:2048','-sha256','-nodes',
                 '-keyout',str(key),'-out',str(cert),'-days','2',
                 '-subj','/CN=node.example.test','-addext','subjectAltName=DNS:node.example.test']
            cp=subprocess.run(cmd,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True,timeout=15)
            self.assertEqual(cp.returncode,0,cp.stderr)
            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    body=b'<html><body>Test HTTPS site</body></html>'
                    self.send_response(200);self.send_header('Content-Length',str(len(body)))
                    self.end_headers();self.wfile.write(body)
                def log_message(self,*_):pass
            server=HTTPServer(('127.0.0.1',0),Handler)
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(certfile=str(cert),keyfile=str(key))
            server.socket=ctx.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                report=probe.run('node.example.test','127.0.0.1',server.server_address[1],3,
                                 cafile=cert,loopback=True,delay=0)
                self.assertEqual(report['status'],'PASS', report)
                self.assertEqual(report['ok'],3)
                self.assertGreaterEqual(report['metrics']['tls_ms']['p50'],0)
                self.assertNotIn('127.0.0.1',json.dumps(report))
                self.assertNotIn('node.example.test',json.dumps(report))
            finally:
                server.shutdown();thread.join(timeout=2);server.server_close()


class ThroughputProbe(unittest.TestCase):
    def test_bounded_single_tcp_stream_and_no_peer_ip_in_report(self):
        class FakeProc:
            returncode=0
            stdout=json.dumps({'start':{'connected':[{'remote_host':'203.0.113.10'}]},
                               'end':{'sum_sent':{'retransmits':2,'bits_per_second':7000000},
                                      'sum_received':{'bits_per_second':12345678}}})
        calls=[]
        def fake(argv,**kwargs):calls.append((argv,kwargs));return FakeProc()
        report=throughput.run('8.8.8.8',5201,3,2,runner=fake)
        self.assertEqual(report['status'],'PASS',report)
        self.assertEqual(report['mbps_median'],12.35)
        self.assertEqual(report['retransmits_total'],4)
        self.assertNotIn('203.0.113.10',json.dumps(report))
        self.assertNotIn('8.8.8.8',json.dumps(report))
        for argv,kwargs in calls:
            self.assertIn('--parallel',argv)
            self.assertIn('1',argv)
            self.assertLessEqual(kwargs['timeout'],13)

    def test_refuses_unapproved_peers_and_outsize_probes(self):
        for ip in ('127.0.0.1','10.20.0.4','0.0.0.0'):
            with self.assertRaises(throughput.ThroughputError):
                throughput.prepare(ip,5201,5,2)
        self.assertEqual(throughput.prepare('10.20.0.4',5201,5,2,allow_private=True)[0],'iperf3')
        for sec in (0,2,16,3600):
            with self.assertRaises(throughput.ThroughputError):
                throughput.prepare('8.8.8.8',5201,sec,2)
        with self.assertRaises(throughput.ThroughputError):
            throughput.prepare('8.8.8.8',5201,5,100)
        with self.assertRaises(throughput.ThroughputError):
            throughput.parse(json.dumps({'end':{'sum_received':{'bits_per_second':float('nan')}}}))


class VisualReview(unittest.TestCase):
    def test_trusted_in_memory_css_and_csp_not_written_back(self):
        from cover_rich import render_rich
        bundle=render_rich('115-reading-room','preview.example.test')
        before=deepcopy(bundle)
        html=visual.offline_html(bundle)
        self.assertIn('<style>',html)
        self.assertNotIn('http-equiv="Content-Security-Policy"',html)
        self.assertEqual(bundle,before)
        self.assertEqual(len(visual.ALL),120)

if __name__=='__main__':unittest.main()
