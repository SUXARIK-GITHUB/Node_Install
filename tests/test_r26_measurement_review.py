"""Compare only like-for-like direct probes; never claim VPN or DPI results."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from common import ROOT
sys.path.insert(0,str(ROOT/'scripts'))
import measurement_review as mr

class Comparison(unittest.TestCase):
    def https(self, delta):
        return {'schema':1,'status':'PASS','samples':8,'ok':8,'failed':0,
                'measure':'DIRECT_HTTPS_SITE_ONLY','metrics':{
                    n:{'p50':v+delta,'p95':v*2+delta} for n,v in
                    [('tcp_ms',10),('tls_ms',20),('ttfb_ms',35),('total_ms',50)]}}

    def throughput(self, mbps, direction='forward'):
        return {'schema':1,'status':'PASS','measure':'DIRECT_TCP_IPERF3_NOT_VPN',
                'samples':2,'completed':2,'direction':direction,
                'mbps_median':mbps,'retransmits_total':1}

    def test_https_review_only_and_deltas(self):
        a,b=self.https(0),self.https(5)
        r=mr.compare(a,b)
        self.assertEqual(r['status'],'REVIEW')
        self.assertEqual(r['differences']['tcp_ms_p50_change'],5)
        self.assertIn('NOT_A_VPN_CLIENT_BENCHMARK',r['observations'])
        self.assertEqual(r['actions_performed'],'NONE')

    def test_throughput_and_direction_guard(self):
        r=mr.compare(self.throughput(90),self.throughput(100))
        self.assertEqual(r['differences']['mbps_median_change'],10)
        with self.assertRaisesRegex(mr.ReviewError,'DIRECTION'):
            mr.compare(self.throughput(90),self.throughput(100,direction='reverse'))
        with self.assertRaisesRegex(mr.ReviewError,'MEASURE'):
            mr.compare(self.throughput(90),self.https(5))

    def test_reject_invalid_reports_without_leaking(self):
        for value in (float('nan'), -1, 0, 10**14, 'fast'):
            with self.subTest(value=value), self.assertRaises(mr.ReviewError):
                mr.compare(self.throughput(100), self.throughput(value))
        bad=self.https(3);bad['samples']=1
        with self.assertRaisesRegex(mr.ReviewError,'INCOMPLETE'):
            mr.compare(self.https(0),bad)
        bad=self.https(3);bad['metrics']['tcp_ms']['p95'] = 'secret'
        with self.assertRaisesRegex(mr.ReviewError,'INVALID'):
            mr.compare(self.https(0),bad)

    def test_cli_sanitizes_and_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            a=root/'a.json'; b=root/'b.json'
            a.write_text(json.dumps(self.throughput(90)));b.write_text(json.dumps(self.throughput(101)))
            run=subprocess.run([sys.executable,str(ROOT/'scripts/measurement_review.py'),str(a),str(b)],
                               capture_output=True,text=True,timeout=10)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertEqual(json.loads(run.stdout)['status'],'REVIEW')
            link=root/'link.json';link.symlink_to(a)
            run=subprocess.run([sys.executable,str(ROOT/'scripts/measurement_review.py'),str(link),str(b)],
                               capture_output=True,text=True,timeout=10)
            self.assertEqual(run.returncode,1)
            self.assertEqual(json.loads(run.stdout)['status'],'FAIL')

if __name__=='__main__':unittest.main()
