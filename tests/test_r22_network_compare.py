"""Network comparison should be diff-only, privacy-limited, and read-only."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from common import ROOT
sys.path.insert(0,str(ROOT/'scripts'))
import network_compare as compare


def snapshot():
    return {'schema':1,'actions_performed':'NONE','network_interface':'eth0',
            'parameters':{'congestion_control':'bbr'},
            'qdisc':{'verified':True,'kinds':['mq','fq'],'queue_drops_cumulative':10},
            'softnet':{'verified':True,'processed_cumulative':4000,'dropped_cumulative':0,'time_squeeze_cumulative':4},
            'tcp_host_counters':{'verified':True,'counters':{'ListenOverflows':5,'ListenDrops':0,'TCPTimeouts':10}},
            'interface_counters':{'verified':True,'rx_packets':1000,'rx_bytes':1000000,'rx_dropped':0,'rx_errors':0,
                                  'tx_packets':600,'tx_bytes':500000,'tx_dropped':0,'tx_errors':0}}


class NetworkDelta(unittest.TestCase):
    def test_zero_deltas_are_not_warnings(self):
        b=snapshot();a=deepcopy(b)
        self.assertEqual(compare.compare(b,a,60)['status'],'INFO')
        self.assertEqual(compare.compare(b,a,60)['deltas']['tcp_host_counters']['ListenDrops']['delta'],0)

    def test_reports_new_not_cumulative_errors(self):
        b=snapshot();a=deepcopy(b)
        a['interface_counters']['rx_bytes']+=120000
        a['interface_counters']['rx_dropped']+=1
        a['tcp_host_counters']['counters']['ListenOverflows']+=2
        r=compare.compare(b,a,60)
        self.assertEqual(r['status'],'REVIEW')
        self.assertEqual(r['deltas']['interface_counters']['rx_bytes']['per_second'],2000)
        self.assertIn('NEW_ERROR_OR_DROP_tcp_host_counters_ListenOverflows',r['observations'])
        self.assertIn('NEW_ERROR_OR_DROP_interface_counters_rx_dropped',r['observations'])

    def test_reset_not_negative_rate(self):
        b=snapshot();a=deepcopy(b)
        a['interface_counters']['rx_bytes']=1
        r=compare.compare(b,a,15)
        self.assertEqual(r['status'],'REVIEW')
        self.assertEqual(r['deltas']['interface_counters']['rx_bytes']['status'],'RESET_OR_RESTART')
        self.assertNotIn('per_second',r['deltas']['interface_counters']['rx_bytes'])

    def test_changed_interface_rejected_for_comparison(self):
        b=snapshot();a=deepcopy(b);a['network_interface']='ens3'
        r=compare.compare(b,a,30)
        self.assertEqual(r['status'],'REVIEW')
        self.assertEqual(r['deltas'],{})

    def test_invalid_interval_and_symlinks(self):
        for s in (0,-1,float('nan'),float('inf'),999999999999):
            with self.assertRaises(ValueError):compare.compare(snapshot(),snapshot(),s)
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);p=root/'first.json';p.write_text(json.dumps(snapshot()))
            q=root/'second.json';q.write_text(json.dumps(snapshot()))
            l=root/'link.json';l.symlink_to(p)
            args=[sys.executable,str(ROOT/'scripts/network_compare.py'),str(p),str(q),'--seconds','30']
            ok=subprocess.run(args,capture_output=True,text=True,timeout=5)
            self.assertEqual(ok.returncode,0,ok.stderr)
            self.assertEqual(json.loads(ok.stdout)['status'],'INFO')
            bad=subprocess.run(args[:2]+[str(l),str(q),'--seconds','30'],capture_output=True,text=True,timeout=5)
            self.assertEqual(bad.returncode,1)
            self.assertNotIn(str(p),bad.stdout+bad.stderr)

if __name__=='__main__':unittest.main()
