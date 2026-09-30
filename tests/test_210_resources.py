"""Read-only resource parser tests: counter reset is not an apparent improvement."""
import json
import subprocess
import unittest
from unittest.mock import patch
from common import module, payload, ROOT

class ResourceTests(unittest.TestCase):
    def setUp(self):self.m=module('VK_RESOURCES_PY')

    def test_cpu_values_excludes_guest_double_count(self):
        self.assertEqual(self.m.cpu_values('cpu 10 1 2 20 3 4 5 6 99 88\ncpu0 1'),[10,1,2,20,3,4,5,6])
        for raw in ['','cpu 1 2','cpu a 1 2 3 4 5 6 7','cpu -1 2 3 4 5 6 7 8']:
            self.assertIsNone(self.m.cpu_values(raw))

    def test_cpu_and_counter_reset(self):
        a={'cpu':[0]*8,'tcp':{'RetransSegs':10},'tcp_ext':{},'vm':{}}
        b={'cpu':[10,0,0,60,10,0,0,20],'tcp':{'RetransSegs':2},'tcp_ext':{},'vm':{}}
        r=self.m.summarize(a,b)
        self.assertEqual(r['cpu'],{'busy_percent':30.,'iowait_percent':10.,'steal_percent':20.})
        self.assertIsNone(r['tcp_delta']['RetransSegs'])
        self.assertIsNone(self.m.summarize(b,a)['cpu'])

    def test_paired_counters_and_malformed(self):
        raw='Tcp: A RetransSegs OutSegs\nTcp: 1 3 80\n'
        self.assertEqual(self.m.paired_counters(raw,'Tcp',['RetransSegs','OutSegs','absent']),{'RetransSegs':3,'OutSegs':80})
        self.assertEqual(self.m.paired_counters('Tcp: A B\nTcp: 1\n','Tcp',['A']),{})
        self.assertEqual(self.m.paired_counters('Tcp: A\nTcp: bad','Tcp',['A']),{})

    def test_memory_and_pressure(self):
        r=self.m.memory_info('MemTotal: 2048 kB\nMemAvailable: 1024 kB\nSwapTotal: 2048 kB\nSwapFree: 1024 kB\n')
        self.assertEqual(r['SwapUsed_MiB'],1.)
        p=self.m.pressure('some avg10=1.23 avg60=0.12 avg300=0.01 total=1234\nfull avg10=bad\n')
        self.assertEqual(p['some']['total'],1234);self.assertNotIn('avg10',p['full'])
        self.assertIsNone(self.m.pressure(''))

    def test_container_unavailable_and_bad_response_are_not_success(self):
        with patch.object(self.m.shutil,'which',return_value=None):
            self.assertFalse(self.m.container_state()['verified'])
        with patch.object(self.m.shutil,'which',return_value='/test/docker'),patch.object(self.m.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'{"unexpected":"secret"}')):
            r=self.m.container_state();self.assertFalse(r['verified']);self.assertNotIn('secret',str(r))

    def test_actual_readonly_cli_emits_json_without_network_or_mutations(self):
        r=subprocess.run(['bash',str(ROOT/'install.sh'),'--diagnose-resources','--seconds','1'],capture_output=True,text=True,timeout=15)
        self.assertEqual(r.returncode,0,r.stderr);data=json.loads(r.stdout)
        self.assertEqual(data['scope'],'HOST_LOCAL_ONLY_NOT_A_VPN_SPEED_TEST')
        self.assertIn('root_disk',data);self.assertGreaterEqual(data['sample_seconds'],1)
        for command in ['systemctl','sysctl','apt-get','curl','reboot','ip route']:
            self.assertNotIn(command,payload('VK_RESOURCES_PY'))
