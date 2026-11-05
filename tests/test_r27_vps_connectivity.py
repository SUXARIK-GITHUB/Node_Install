"""No external requests; injected DNS/network and report storage."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'integrations'))
import vps_connectivity as v


class NetTests(unittest.TestCase):
    def test_catalog_exactly_expected(self):
        names={x[0] for x in v.SERVICES}
        for name in ('VK','Яндекс','MAX','YouTube','Reddit','GitHub','X / Twitter',
                     'ChatGPT','DeepSeek','Grok','Claude','Claude Code API'):
            self.assertIn(name,names)
        self.assertEqual(len(names),len(v.SERVICES))

    def test_ssrf_host_and_dns_policy(self):
        for bad in ('http://example.com','localhost','127.0.0.1','10.0.0.2','169.254.1.2',
                    '192.168.1.2','::1','example.com:443','a@b.com','example.com/../../',''):  
            with self.assertRaises(ValueError,msg=bad):v.clean_host(bad)
        self.assertEqual(v.clean_host('OpenAI.com'),'openai.com')
        with self.assertRaises(ValueError):
            v.global_ipv4s('safe.example',resolver=lambda *args:[(None,None,None,None,('10.0.0.9',443))])
        with self.assertRaises(ValueError):
            v.global_ipv4s('safe.example',resolver=lambda *args:[(None,None,None,None,('1.1.1.1',443)),(None,None,None,None,('127.0.0.1',443))])

    def test_ambiguous_http_status(self):
        self.assertEqual(v.classify(204),'REACHABLE')
        self.assertEqual(v.classify(302),'REACHABLE')
        self.assertEqual(v.classify(401),'AUTH_REQUIRED')
        self.assertEqual(v.classify(403),'RESTRICTED_OR_PROTECTED')
        self.assertEqual(v.classify(451),'RESTRICTED_OR_PROTECTED')
        self.assertEqual(v.classify(429),'RATE_LIMITED')
        self.assertEqual(v.classify(403,headers=b'X-Ratelimit-Remaining: 0'),'RATE_LIMITED')

    def test_https_head_bounded_authenticated_tls(self):
        class FakeSocket:
            def __enter__(self):return self
            def __exit__(self,*args):return False
        class FakeTLS(FakeSocket):
            def settimeout(self,*args):pass
            def sendall(self,buffer):
                self.assert_request=buffer
            def recv(self,*args):return b'HTTP/1.1 401 Unauthorized\r\nServer: example\r\n\r\n'
        class FakeContext:
            minimum_version=None
            def set_alpn_protocols(self,*args):pass
            def wrap_socket(self,raw,server_hostname):
                self.host=server_hostname
                return FakeTLS()
        ctx=FakeContext()
        ticks=iter((0.0,.005,.016,.025,.049))
        report=v.https_once('api.openai.com',path='/v1/models',
                   resolver=lambda host:['1.1.1.1'],connector=lambda *args,**kwargs:FakeSocket(),
                   tls_context=ctx,monotonic=lambda:next(ticks))
        self.assertEqual(ctx.host,'api.openai.com')
        self.assertEqual(report['status'],'AUTH_REQUIRED')
        self.assertEqual(report['http'],401)
        self.assertGreater(report['ttfb_ms'],report['tls_ms'])

    def test_quality_and_spikes(self):
        rows=iter([{'status':'REACHABLE','ttfb_ms':12},{'status':'REACHABLE','ttfb_ms':16},
                   {'status':'TIMEOUT'},{'status':'REACHABLE','ttfb_ms':200},
                   {'status':'REACHABLE','ttfb_ms':14}])
        q=v.quality('github.com',samples=5,probe=lambda *_:next(rows),sleep=lambda *a:None)
        self.assertEqual(q['answered'],4)
        self.assertEqual(q['failure_pct'],20)
        self.assertEqual(q['spikes'],1)
        self.assertGreater(q['p95_ms'],q['p50_ms'])
        self.assertEqual(q['type'],'HTTPS_TTFB')

    def test_ping_parser_no_guessed_loss(self):
        result=v.parse_ping('7 packets transmitted, 6 received, 14% packet loss\nrtt min/avg/max/mdev = 10.0/20.0/30.0/6.0 ms',7)
        self.assertEqual(result['loss_pct'],14.3)
        self.assertEqual(result['jitter_mdev_ms'],6)
        self.assertEqual(v.parse_ping('permission denied',7)['status'],'UNVERIFIED')

    def test_edge_do_not_return_observed_ip(self):
        answer=v.cloudflare_edge(probe=lambda:b'ip=1.2.3.4\ncolo=FRA\nloc=DE\n')
        self.assertEqual(answer['edge_colo'],'FRA')
        self.assertNotIn('1.2.3.4',json.dumps(answer))
        self.assertEqual(v.cloudflare_edge(probe=lambda:b'ip=1.2.3.4')['status'],'UNVERIFIED')

    def test_services_mock_no_network(self):
        names=[]
        result=v.services(only=['VK','MAX'],progress=names.append,probe=lambda host,path:{'status':'REACHABLE','http':200})
        self.assertEqual(len(result['results']),2)
        self.assertEqual(names,['VK','MAX'])
        with self.assertRaises(ValueError):v.services(only=['Nonexistent'],probe=lambda *a,**kw:None)

    def test_terminal_table_does_not_guess_status(self):
        result={'kind':'SERVICES','results':[
            {'service':'ChatGPT','status':'AUTH_REQUIRED','http':401,'ttfb_ms':80},
            {'service':'VK','status':'RESTRICTED_OR_PROTECTED','http':403,'ttfb_ms':110},
            {'service':'GitHub','status':'REACHABLE','http':200,'ttfb_ms':45},
        ]}
        rendered=v.render_table(result)
        self.assertIn('ChatGPT',rendered)
        self.assertIn('AUTH_REQUIRED',rendered)
        self.assertIn('403/451 не доказывают блокировку',rendered)
        self.assertNotIn('BLOCKED',rendered)
        small=v.render_table({'type':'HTTPS_TTFB','host':'github.com','attempts':5,'answered':3,
                              'jitter_ms':8.0,'spikes':1})
        self.assertIn('jitter_ms',small)
        self.assertIn('8.0',small)

    def test_cli_table_and_json_default_readonly(self):
        import subprocess
        args=['bash',str(ROOT/'install.sh'),'--vps-check']
        table=subprocess.run(args+['--format','table','local'],capture_output=True,text=True,timeout=10)
        self.assertEqual(table.returncode,0,table.stderr)
        self.assertIn('СОСТОЯНИЕ VPS',table.stdout)
        doc=subprocess.run(args+['catalog'],capture_output=True,text=True,timeout=10)
        self.assertEqual(doc.returncode,0,doc.stderr)
        self.assertIn('VK',json.loads(doc.stdout)['services'][0]['name'])

    def test_custom_port_rejects_unsafe_port_before_dns(self):
        import subprocess
        for port in ('0','65536','-1'):
            cp=subprocess.run(['bash',str(ROOT/'install.sh'),'--vps-check','custom',
                        '--host','example.com','--port',port],capture_output=True,text=True,timeout=5)
            self.assertEqual(cp.returncode,2,cp.stdout)
            self.assertIn('STOP',cp.stdout)

    def test_history_private_and_compare(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp)/'private-history'
            one={'kind':'SERVICES','results':[{'service':'VK','status':'REACHABLE'}]}
            two={'kind':'SERVICES','results':[{'service':'VK','status':'TIMEOUT'}]}
            name1=v.save_report(one,directory)
            name2=v.save_report(two,directory)
            self.assertEqual(directory.stat().st_mode&0o777,0o700)
            self.assertEqual((directory/name1).stat().st_mode&0o777,0o600)
            self.assertIn(name1,v.reports_list(directory))
            self.assertEqual(v.load_report(name1,directory)['report'],one)
            changes=v.compare_reports(name1,name2,directory)['changes']
            self.assertEqual(changes[0]['before'],'REACHABLE')
            with self.assertRaises(ValueError):v.load_report('../escape.json',directory)
            os.chmod(directory,0o755)
            with self.assertRaises(ValueError):v.reports_list(directory)


if __name__=='__main__':unittest.main()
