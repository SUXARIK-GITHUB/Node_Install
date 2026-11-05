"""R20 read-only network health: no sysctl/qdisc/network modifications."""
import json
from pathlib import Path
import subprocess
import sys
import unittest
from common import ROOT, SCRIPT

sys.path.insert(0, str(ROOT / 'integrations'))
import network_health as nh


class NetworkHealth(unittest.TestCase):
    def test_default_route_selection_is_private_and_unambiguous(self):
        s=json.dumps([{'dst':'default','dev':'eth0','gateway':'198.51.100.1','metric':10},
                      {'dst':'default','dev':'ens5','gateway':'203.0.113.1','metric':20}])
        self.assertEqual(nh.default_interface(s),('eth0',None))
        self.assertEqual(nh.default_interface(json.dumps([
            {'dst':'default','dev':'eth0','metric':0},
            {'dst':'default','dev':'eth1','metric':0}]))[1],'ROUTE_AMBIGUOUS')
        self.assertEqual(nh.default_interface('[{"dst":"default","dev":"../secrets"}]')[1],
                         'ROUTE_INTERFACE_INVALID')
        self.assertEqual(nh.default_interface('invalid')[1],'ROUTE_UNPARSEABLE')

    def test_multiqueue_qdisc_detects_child_fq(self):
        tree=json.dumps([{'kind':'mq','root':True},
                         {'kind':'fq','parent':'1:1','stats':{'queue':{'drops':2}}},
                         {'kind':'fq','parent':'1:2'}])
        result=nh.qdisc_summary(tree)
        self.assertTrue(result['verified'])
        self.assertEqual(result['root_kind'],'mq')
        self.assertTrue(result['fq_present'])
        self.assertEqual(result['queue_drops_cumulative'],2)
        self.assertFalse(nh.qdisc_summary('not json')['verified'])
        self.assertFalse(nh.qdisc_summary('[]')['verified'])

    def test_link_counters_and_softnet(self):
        link=json.dumps([{'ifname':'eth0','mtu':1500,'address':'11:22:33:44:55:66',
                          'stats64':{'rx':{'packets':10,'bytes':20,'dropped':3,'errors':0},
                                     'tx':{'packets':30,'bytes':40,'dropped':1,'errors':2}}}])
        res=nh.interface_counters(link,'eth0')
        self.assertTrue(res['verified'])
        self.assertEqual(res['rx_dropped'],3)
        self.assertNotIn('address',res)
        self.assertFalse(nh.interface_counters(link,'other')['verified'])
        sn=nh.softnet_summary('0000000a 00000002 00000001\n00000010 00000000 00000003')
        self.assertEqual(sn['processed_cumulative'],26)
        self.assertEqual(sn['dropped_cumulative'],2)
        self.assertEqual(sn['time_squeeze_cumulative'],4)

    def test_snapshot_is_readonly_aggregate_and_no_sensitive_fields(self):
        calls=[]
        def runner(argv):
            calls.append(argv)
            if argv[:4]==['ip','-j','-4','route']:
                return '[{"dst":"default","dev":"eth0","gateway":"203.0.113.99"}]'
            if argv[0]=='tc':
                return '[{"kind":"mq","root":true},{"kind":"fq","parent":"1:1"}]'
            if argv[0]=='ip':
                return json.dumps([{'ifname':'eth0','stats64':{
                    'rx':{'packets':10,'bytes':20,'dropped':0,'errors':0},
                    'tx':{'packets':8,'bytes':17,'dropped':0,'errors':0}}}])
            raise AssertionError(argv)
        def reader(path):
            if path.endswith('tcp_congestion_control'):return 'bbr'
            if path.endswith('default_qdisc'):return 'fq'
            if path.endswith('nf_conntrack_count'):return '20'
            if path.endswith('nf_conntrack_max'):return '100'
            if path.endswith('softnet_stat'):return '00000010 00000000 00000000'
            return '0'
        report=nh.snapshot(runner,reader)
        self.assertEqual(report['actions_performed'],'NONE')
        self.assertEqual(report['status'],'INFO')
        self.assertTrue(report['qdisc']['fq_present'])
        self.assertEqual(report['conntrack']['usage_percent'],20)
        self.assertNotIn('203.0.113.99',json.dumps(report))
        self.assertTrue(all(argv[0] in ('tc','ip') for argv in calls))

    def test_overloaded_conntrack_reported_but_not_modified(self):
        data=nh.snapshot(lambda _:None,lambda p:'99' if p.endswith('nf_conntrack_count') else
                         '100' if p.endswith('nf_conntrack_max') else None)
        self.assertEqual(data['status'],'REVIEW')
        self.assertIn('CONNTRACK_CAPACITY_HIGH',data['observations'])
        self.assertEqual(data['actions_performed'],'NONE')

    def test_release_verifier_requires_new_components(self):
        verifier=(ROOT/'scripts/verify_release.py').read_text()
        self.assertIn("m['build_id'].startswith('20261105-r20-')",verifier)
        for path in ('network_health.py','cover_rich.py','site_audit.py'):
            self.assertIn(path,verifier)

    def test_embedded_copy_matches_file_and_has_cli_entry(self):
        content=(ROOT/'integrations/network_health.py').read_text()
        self.assertIn("<<'VK_NETWORK_HEALTH_PY'\n"+content+'VK_NETWORK_HEALTH_PY',SCRIPT)
        self.assertIn('--diagnose-network) shift; vkarmani_network_health_main "$@"',SCRIPT)
        p=subprocess.run(['bash',str(ROOT/'install.sh'),'--diagnose-network'],
                         cwd=ROOT,capture_output=True,text=True,timeout=12)
        self.assertEqual(p.returncode,0,p.stderr)
        report=json.loads(p.stdout)
        self.assertEqual(report['actions_performed'],'NONE')
        self.assertIn('qdisc',report)


if __name__ == '__main__':unittest.main()
