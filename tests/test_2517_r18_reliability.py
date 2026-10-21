"""R18 offline regression: IPv4, cascade fail-closed, Hybrid Stream, quality sample."""
import copy
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from common import ROOT, SCRIPT, payload
sys.path.insert(0, str(ROOT / 'integrations'))
sys.path.insert(0, str(ROOT / 'scripts'))
import cascade_profiles as cp
import connection_quality as cq
import staging_web_deploy as web


class IPv4InputR18(unittest.TestCase):
    def test_public_range_typo_fixed_without_host_mutation(self):
        for address, expected in [('192.0.1.5', True), ('8.8.8.8', True),
                                  ('192.0.0.5', False), ('192.0.2.4', False),
                                  ('127.0.0.1', False), ('10.2.3.4', False)]:
            # Function is inside the guarded first-install dispatcher: extract
            # just this pure validator, never source/run installation code.
            source = re.search(r'(?ms)^vk_validate_ipv4\(\) \{\n.*?^\}', SCRIPT)
            self.assertIsNotNone(source)
            p = subprocess.run(['bash', '-c', source.group() + '\nvk_validate_ipv4 "$1"',
                                'test', address],
                               capture_output=True, text=True, timeout=8)
            self.assertEqual(p.returncode == 0, expected, (address, p.stderr))


class CascadeGuardsR18(unittest.TestCase):
    @staticmethod
    def config():
        return {
            'entry': {'ipv4':'8.8.4.4','domain':'entry.example.org','inbound_tag':'VK_ENTRY_TAG',
                      'private_key':'A'*43, 'public_key':'B'*43, 'short_id':'01'},
            'exit': {'ipv4':'1.1.1.1','domain':'exit.example.org','inbound_tag':'VK_EXIT_TAG',
                     'private_key':'C'*43, 'public_key':'D'*43,'short_id':'02'},
            'bridge': {'service_user_uuid':'00000000-0000-4000-8000-000000000001'}
        }

    def test_entry_and_exit_explicitly_block_pair_addresses(self):
        cfg=self.config()
        for role, gen in [('entry', cp.entry_profile), ('exit', cp.exit_profile)]:
            p=gen(cfg)
            self.assertTrue(cp.audit(p,role))
            blocked=p['routing']['rules'][2]['ip']
            self.assertEqual(blocked[-2:], ['8.8.4.4/32','1.1.1.1/32'])
            self.assertIn('::/0',blocked)
            if role=='entry':
                self.assertNotIn('DIRECT', [x['tag'] for x in p['outbounds']])
            else:
                self.assertEqual(p['outbounds'][0]['streamSettings'],
                                 {'sockopt':{'domainStrategy':'ForceIPv4'}})
                self.assertEqual(p['outbounds'][0]['settings']['finalRules'],
                                 [{'ip':blocked,'action':'block'}])

    def test_removing_block_or_ipv4_strategy_fails_closed(self):
        cfg=self.config()
        for role, gen in [('entry', cp.entry_profile), ('exit', cp.exit_profile)]:
            p=gen(cfg)
            for mutate in (lambda x:x['routing']['rules'][2]['ip'].pop(),
                           lambda x:x['routing']['rules'][2]['ip'].append('9.9.9.9/32')):
                changed=copy.deepcopy(p)
                mutate(changed)
                with self.assertRaises(cp.Invalid):cp.audit(changed,role)
            if role=='exit':
                for mutate in (lambda x:x['outbounds'][0].pop('streamSettings'),
                               lambda x:x['outbounds'][0]['settings']['finalRules'][0]['ip'].pop()):
                    changed=copy.deepcopy(p)
                    mutate(changed)
                    with self.assertRaises(cp.Invalid):cp.audit(changed,role)


class HybridTcpR18(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        for p in ('var/lib/vkarmani-node','etc/vkarmani-node',
                  'etc/nginx/conf.d','etc/nginx/vkarmani-stream-r7'):
            (self.root/p).mkdir(parents=True,exist_ok=True)
        s=self.root/'var/lib/vkarmani-node'
        (s/'owned-installation').touch()
        (s/'install-version').write_text('2.5.17\n')
        (s/'INSTALL_COMPLETE').write_text('version=2.5.17\n')
        (self.root/'etc/vkarmani-node/config.json').write_text(json.dumps({
            'installation_mode':'secret-key-only', 'domain':'node.example.org',
            'public_ipv4':'8.8.8.8', 'reality_mode':'max.ru'}))
        self.prefix=b'worker_processes auto;\nevents { worker_connections 1024; }\nhttp { include conf.d/*.conf; }\n'
        self.file=self.root/'etc/nginx/nginx.conf'
        self.original=self.prefix+b'\n'+web.HYBRID_TAIL_R18.encode()
        self.file.write_bytes(self.original)
        self.app=web.NodeWeb(self.root,run=lambda _:b'')

    def test_owned_hybrid_adds_only_fragment_and_rolls_back(self):
        result=self.app.tcp_install(9200,9300,portcheck=False)
        self.assertIn('TCP_DEPLOY=PASS',result)
        self.assertEqual(self.file.read_bytes(), self.original)
        self.assertIn('listen 127.0.0.1:9200;',self.app.streamconf.read_text())
        receipt=self.app.receipt('tcp')
        self.assertEqual(set(receipt['files']),{'fragment'})
        self.assertTrue(receipt['metadata']['hybrid_fragment_only'])
        self.assertEqual(self.app.tcp_rollback(),'TCP_ROLLBACK=PASS')
        self.assertFalse(self.app.streamconf.exists())
        self.assertEqual(self.file.read_bytes(),self.original)

    def test_old_hybrid_refused_without_modifying_anything(self):
        original=(self.prefix+b'\n# VKARMANI_HYBRID_STREAM_V1\nstream {\n'
                 b'    include /etc/nginx/vkarmani-hybrid-stream.conf;\n}\n')
        self.file.write_bytes(original)
        with self.assertRaisesRegex(web.DeployError,'HYBRID_STREAM_REQUIRES_R18_INCLUDE'):
            self.app.tcp_install(9200,9300,portcheck=False)
        self.assertEqual(self.file.read_bytes(),original)
        self.assertFalse(self.app.streamconf.exists())

    def test_foreign_stream_and_external_main_changes_refused(self):
        self.file.write_bytes(self.prefix+b'\nstream { server {} }\n'+web.HYBRID_TAIL_R18.encode())
        with self.assertRaises(web.DeployError):self.app.tcp_install(9200,9300,portcheck=False)
        self.file.write_bytes(self.original)
        self.app.tcp_install(9200,9300,portcheck=False)
        self.file.write_bytes(self.original+b'\n# operator edit\n')
        with self.assertRaisesRegex(web.DeployError,'THIRD_PARTY_HYBRID_MAIN_EDIT'):
            self.app.tcp_rollback()
        self.assertTrue(self.app.streamconf.exists())

    def test_installer_owns_empty_glob_include_and_no_public_port(self):
        block = payload('PY_NGINX_HYBRID_STREAM')
        self.assertIn('include /etc/nginx/vkarmani-stream-r7/*.conf;', block)
        self.assertIn('proxy_protocol;', block)
        self.assertIn('install -d -m 0755 /etc/nginx/vkarmani-stream-r7', SCRIPT)
        self.assertNotIn('listen 443;',block)


class QualityR18(unittest.TestCase):
    good='''ESTAB 0 0 192.0.2.5:443 198.51.100.6:12345
 cubic wscale:8,8 rtt:22.50/1.2 mss:1460 retrans:0/0 delivery_rate 8Mbps
ESTAB 0 0 192.0.2.5:443 198.51.100.7:12345
 cubic wscale:8,8 rtt:44.50/2.2 mss:1460 retrans:1/2 bytes_retrans:1000 delivery_rate 2Mbps
'''

    def test_aggregate_is_anon_and_values_are_correct(self):
        vals=cq.aggregate(cq.parse_ss(self.good))
        self.assertEqual(vals['rtt_ms_p50'],22.5)
        self.assertEqual(vals['rtt_ms_p90'],44.5)
        self.assertEqual(vals['delivery_rate_bps_median'],2000000)
        self.assertEqual(vals['retransmission_observed_percent'],50.0)
        report=cq.diagnose(1,reader=lambda:(self.good,None),sleeper=lambda _:None)
        self.assertEqual(report['status'],'REVIEW')
        raw=json.dumps(report)
        for item in ('192.0.2.5','198.51.100.7','12345'):
            self.assertNotIn(item,raw)

    def test_missing_data_and_invalid_metrics_are_not_ok(self):
        self.assertEqual(cq.diagnose(1,lambda:(None,'SS_COMMAND_FAILED'),lambda _:None)['status'],'NOT_VERIFIED')
        self.assertEqual(cq.diagnose(1,lambda:('bad output',None),lambda _:None)['reason'],
                         'NO_ESTABLISHED_TCP_443_CONNECTIONS')
        self.assertRaises(ValueError,cq.parse_ss,'x'*(cq.MAX_SS_BYTES+1))
        self.assertEqual(cq.percentile([],99),None)

    def test_installer_embeds_exact_module_and_cli_is_safe(self):
        self.assertEqual(payload('VK_CONNECTION_QUALITY_PY'),
                         (ROOT/'integrations/connection_quality.py').read_text())
        self.assertIn('--diagnose-quality) shift; vkarmani_quality_main "$@"',SCRIPT)
        for disallowed in ('netplan apply','sysctl -w','ufw allow','docker restart',
                           'ip route add','systemctl reload','ip addr add'):
            self.assertNotIn(disallowed, payload('VK_CONNECTION_QUALITY_PY'))
        r=subprocess.run(['bash',str(ROOT/'install.sh'),'--diagnose-quality','--seconds','0'],
                         capture_output=True,text=True,timeout=8)
        self.assertNotEqual(r.returncode,0)


if __name__=='__main__':
    unittest.main()
