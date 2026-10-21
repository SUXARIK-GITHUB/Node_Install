"""r17 regressions: unprivileged CI and read-only multi-IPv4/network diagnosis."""
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from common import ROOT, SCRIPT, module, payload


class MultiIpAndNodeDiagnostics(unittest.TestCase):
    def setUp(self):
        self.mod = module('VK_NODE_DIAGNOSTICS_PY')

    def test_multiple_ipv4_preserved_and_reported_without_priority_reorder(self):
        addresses = json.dumps([{
            'ifname': 'ens3', 'operstate': 'UP', 'mtu': 1500,
            'addr_info': [
                {'family': 'inet', 'local': '93.184.216.22', 'prefixlen': 24},
                {'family': 'inet', 'local': '93.184.216.34', 'prefixlen': 24, 'secondary': True},
                {'family': 'inet', 'local': '93.184.216.35', 'prefixlen': 24, 'secondary': True},
                {'family': 'inet', 'local': '10.0.0.20', 'prefixlen': 8},
            ]}])
        self.assertEqual([x['ip'] for x in self.mod.parse_addresses(addresses)],
                         ['93.184.216.22', '93.184.216.34', '93.184.216.35'])
        self.assertTrue(self.mod.parse_addresses(addresses)[1]['secondary'])
        self.assertEqual(self.mod.parse_addresses(addresses)[2]['interface'], 'ens3')
        result = self.mod.check_dns('node.example.net', self.mod.parse_addresses(addresses),
                                    lambda args, timeout: ('93.184.216.35 STREAM host\n', None))
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['selected_ipv4'], '93.184.216.35')

    def test_dns_mismatch_multi_a_and_resolver_fail_not_pass(self):
        addresses = [{'ip': '93.184.216.34'}]
        def runner(line, timeout):
            return '93.184.216.34 STREAM x\n93.184.216.35 STREAM x\n', None
        self.assertEqual(self.mod.check_dns('node.example.net', addresses, runner)['reason'],
                         'DNS_A_RECORDS_NOT_UNIQUE')
        self.assertEqual(self.mod.check_dns('node.example.net', addresses,
                                           lambda args, timeout: ('93.184.216.35 STREAM x', None))['status'], 'REVIEW')
        self.assertEqual(self.mod.check_dns('node.example.net', addresses,
                                           lambda args, timeout: (None, 'TIMEOUT'))['status'], 'UNVERIFIED')
        self.assertEqual(self.mod.check_dns(';rm -rf /', addresses)['reason'], 'INVALID_DOMAIN')
        self.assertEqual(self.mod.check_dns('', addresses)['status'], 'SKIPPED')

    def test_duplicate_address_bad_json_and_no_route_fail_closed(self):
        payload = json.dumps([{'ifname':'eth0','addr_info':[{'family':'inet','local':'93.184.216.34'},
                                                             {'family':'inet','local':'93.184.216.34'}]}])
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_PUBLIC_ADDRESS'):
            self.mod.parse_addresses(payload)
        for raw in ('[]', '{}', 'not JSON'):
            with self.assertRaises((ValueError, TypeError)):
                self.mod.parse_route(raw)
        with self.assertRaises(ValueError):
            self.mod.parse_addresses('[{"ifname":"evil name", "addr_info": []}]')

    def test_route_source_different_from_dns_is_explicit_not_overwritten(self):
        fixture = {
            ('ip','-j','-4','address','show','scope','global'): json.dumps([{
                'ifname': 'ens3', 'operstate': 'UP', 'mtu': 1500, 'addr_info': [
                    {'family':'inet','local':'93.184.216.34','prefixlen':24},
                    {'family':'inet','local':'93.184.216.35','prefixlen':24}]}]),
            ('ip','-j','-4','route','get','1.1.1.1'): '[{"dst":"1.1.1.1", "dev":"ens3", "prefsrc":"93.184.216.34"}]',
            ('getent','ahostsv4','node.example.net'): '93.184.216.35 STREAM node.example.net',
            ('ss','-H','-ltn'): 'LISTEN 0 511 0.0.0.0:443 0.0.0.0:*',
            ('tc','-j','qdisc','show'): '[{"dev":"ens3","kind":"fq","root":true}]',
            ('docker','ps','--format','{{.Names}}\t{{.Status}}'): 'remnanode\tUp 10 min',
        }
        def fake_run(args, timeout=5):
            return fixture[tuple(args)], None
        with tempfile.TemporaryDirectory() as tmp:
            report = self.mod.run_diagnostics('node.example.net', fake_run, Path(tmp))
        self.assertEqual(report['addresses']['status'], 'PASS')
        self.assertEqual(len(report['addresses']['public_ipv4']), 2)
        self.assertEqual(report['domain_alignment']['selected_ipv4'], '93.184.216.35')
        self.assertTrue(report['outbound_route']['source_differs_from_inbound_ipv4'])
        self.assertEqual(report['outbound_route']['source_ipv4'], '93.184.216.34')
        self.assertEqual(report['actions_performed'], 'NONE')

    def test_network_config_source_presence_without_reading_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'etc/network').mkdir(parents=True)
            (root/'etc/netplan').mkdir(parents=True)
            (root/'etc/network/interfaces').write_text('password=NOT_TO_BE_EXPOSED\n')
            (root/'etc/netplan/50-cloud-init.yaml').write_text('PRIVATE=NOT_TO_BE_EXPOSED\n')
            report=self.mod.network_backends(root)
            self.assertIn('netplan', report['config_sources'])
            self.assertIn('ifupdown-config-present', report['config_sources'])
            self.assertNotIn('NOT_TO_BE_EXPOSED', json.dumps(report))

    def test_conntrack_near_capacity_and_unavailable_are_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.assertEqual(self.mod.conntrack(root)['status'], 'UNVERIFIED')
            (root/'nf_conntrack_count').write_text('870')
            (root/'nf_conntrack_max').write_text('1000')
            self.assertEqual(self.mod.conntrack(root)['status'], 'REVIEW')
            (root/'nf_conntrack_count').write_text('120')
            self.assertEqual(self.mod.conntrack(root)['status'], 'PASS')

    def test_qdisc_and_docker_status_no_env_or_unrelated_names(self):
        self.assertEqual(self.mod.parse_qdisc('[{"dev":"ens3","kind":"fq","root":true}]')['qdiscs'][0]['kind'], 'fq')
        self.assertEqual(self.mod.parse_qdisc('{"invalid":"schema"}')['status'], 'UNVERIFIED')
        value = self.mod.docker_node_status(lambda args, timeout: (
            'other-app\tUp 3h\nremnanode\tUp 15 minutes\n', None))
        self.assertEqual(value['status'], 'INFO')
        self.assertTrue(value['remnanode_running'])
        self.assertNotIn('other-app', json.dumps(value))
        self.assertEqual(self.mod.docker_node_status(lambda args, timeout: (None, 'COMMAND_MISSING'))['status'], 'UNVERIFIED')

    def test_unprivileged_cli_and_no_mutating_commands(self):
        source=payload('VK_NODE_DIAGNOSTICS_PY')
        self.assertEqual(source, (ROOT/'integrations/node_diagnostics.py').read_text())
        self.assertIn('--diagnose-node) shift; vkarmani_node_diagnostics_main "$@"', SCRIPT)
        for item in ('ip addr add', 'ip route add', 'ifdown ', 'ifup ',
                     'netplan apply', 'systemctl restart', 'ufw allow', 'docker restart',
                     'sysctl -w', 'iptables -A', 'chmod ', 'chown '):
            self.assertNotIn(item, source)
        r=subprocess.run(['bash', str(ROOT/'install.sh'), '--diagnose-node'],
                         capture_output=True,text=True,timeout=15)
        self.assertEqual(r.returncode,0,r.stderr)
        data=json.loads(r.stdout)
        self.assertIn('READ_ONLY_LOCAL_NODE',data['scope'])
        self.assertIn('addresses',data)
        self.assertIn('conntrack',data)
        self.assertEqual(data['actions_performed'],'NONE')

    def test_version_and_staging_safety(self):
        version=subprocess.run(['bash',str(ROOT/'install.sh'),'--version'],
                               capture_output=True,text=True,timeout=10)
        self.assertEqual(version.stdout.strip(),'2.5.17')
        self.assertIn('2.5.17', (ROOT/'README.md').read_text())
        self.assertEqual(json.loads((ROOT/'BUILD_MANIFEST.json').read_text())['release_status'],
                         'INCOMPLETE_STAGING_ONLY')


if __name__ == '__main__':
    unittest.main()
