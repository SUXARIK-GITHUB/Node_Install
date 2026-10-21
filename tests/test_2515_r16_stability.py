"""r16 read-only network resource sampling and opt-in scheduled restart contracts."""
import json
import re
import subprocess
import unittest
from pathlib import Path
from common import ROOT, SCRIPT, module, payload


class StabilityR16Tests(unittest.TestCase):
    def setUp(self):
        self.d = module('VK_RESOURCES_PY')

    def test_softnet_hex_cpu_aggregation(self):
        data = '0000000a 00000002 00000003 00000000\n00000010 00000004 00000006 00000000\n'
        self.assertEqual(self.d.softnet_counters(data),
                         {'processed': 26, 'dropped': 6, 'time_squeeze': 9})
        for corrupt in ('', 'bad record', 'a b', 'a b G\n', '00 01 02\n00 zz 01\n'):
            self.assertEqual(self.d.softnet_counters(corrupt), {})
        self.assertEqual(self.d.softnet_counters('00 01 02\n' * 4097), {})

    @staticmethod
    def _dev(name, rx=1000, tx=2000, drops=0, errors=0):
        receive = [rx, 12, errors, drops, 0, 0, 0, 0]
        transmit = [tx, 20, errors, drops, 0, 0, 0, 0]
        return f'  {name}: ' + ' '.join(str(x) for x in receive + transmit)

    def test_network_interface_deltas_and_mbps(self):
        hdr = 'Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast |bytes packets errs drop fifo colls carrier compressed\n'
        before = self.d.network_device_counters(hdr + self._dev('lo') + '\n' + self._dev('eth0') + '\n')
        after = self.d.network_device_counters(hdr + self._dev('lo') + '\n' + self._dev('eth0', 101000, 202000, 2, 1) + '\n')
        self.assertEqual(set(before), {'eth0'})
        res = self.d.network_device_deltas(before, after, 1)
        self.assertTrue(res['verified'])
        nic = res['interfaces'][0]
        self.assertEqual(nic['rx_bytes'], 100000)
        self.assertEqual(nic['tx_bytes'], 200000)
        self.assertEqual(nic['rx_Mbps'], 0.8)
        self.assertEqual(nic['tx_Mbps'], 1.6)
        self.assertEqual(nic['rx_dropped'], 2)
        self.assertEqual(nic['tx_errors'], 1)
        self.assertFalse(self.d.network_device_deltas(before, {}, 1)['verified'])
        self.assertFalse(self.d.network_device_deltas(before, after, 0)['verified'])
        after['eth0']['rx_bytes'] = 1
        self.assertFalse(self.d.network_device_deltas(before, after, 1)['verified'])
        after['eth0']['rx_bytes'] = 101000
        after['wg0'] = dict(after['eth0'])
        self.assertFalse(self.d.network_device_deltas(before, after, 1)['verified'])

    def test_network_device_counters_fail_closed(self):
        self.assertEqual(self.d.network_device_counters(''), {})
        self.assertEqual(self.d.network_device_counters('x\ny\ngarbage'), {})
        self.assertEqual(self.d.network_device_counters('x\ny\niface: a b c'), {})
        self.assertEqual(self.d.network_device_counters('x\ny\niface: 0 0'), {})
        self.assertEqual(self.d.network_device_counters('x\ny\n' + self._dev('eth0') + '\n' + self._dev('eth0')), {})

    def test_udp_and_softnet_sample_deltas_optional(self):
        raw = ('Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors\n'
               'Udp: 200 3 7 300 5 1\n')
        self.assertEqual(self.d.paired_counters(raw, 'Udp', ('InErrors','RcvbufErrors','SndbufErrors')),
                         {'InErrors': 7, 'RcvbufErrors': 5, 'SndbufErrors': 1})
        a = {'cpu': [0]*8, 'tcp': {}, 'tcp_ext': {}, 'vm': {},
             'udp': {'InErrors': 5}, 'softnet': {'dropped': 2}}
        b = {'cpu': [1]*8, 'tcp': {}, 'tcp_ext': {}, 'vm': {},
             'udp': {'InErrors': 9}, 'softnet': {'dropped': 4}}
        r = self.d.summarize(a, b)
        self.assertEqual(r['udp_delta']['InErrors'], 4)
        self.assertEqual(r['softnet_delta']['dropped'], 2)
        b['udp']['InErrors'] = 1
        self.assertIsNone(self.d.summarize(a, b)['udp_delta']['InErrors'])

    def test_invalid_counters_are_flagged_not_suppressed(self):
        result = {'cpu': {'busy_percent': 0}, 'memory': {'MemAvailable_MiB': 1000},
                  'root_disk': {'verified': True}, 'pressure': {}, 'tcp_delta': {'RetransSegs': 0},
                  'tcp_ext_delta': {'ListenDrops': 0}, 'udp_delta': {'InErrors': 3},
                  'softnet_delta': {'dropped': 1}, 'vm_delta': {'oom_kill': 0},
                  'netdev_delta': {'verified': True, 'interfaces': [{'interface': 'eth0','rx_dropped': 2}]},
                  'selfsteal_socket_queue': {'verified': False}}
        review = self.d.review_summary(result)
        self.assertTrue(review['review_required'])
        paths = {x['section'] for x in review['findings']}
        self.assertIn('resources.udp_delta.InErrors', paths)
        self.assertIn('resources.softnet_delta.dropped', paths)
        self.assertIn('resources.netdev_delta.rx_dropped', paths)

    def test_default_timer_disabled_only_for_new_ordinary(self):
        self.assertIn('vk_write_nightly_maintenance install-only', SCRIPT)
        self.assertIn('systemctl disable --now vkarmani-node-nightly.timer', SCRIPT)
        self.assertIn('systemctl enable --now vkarmani-node-nightly.timer', SCRIPT)
        self.assertIn('vk_write_nightly_maintenance ;;', SCRIPT)
        self.assertIn('MAINTENANCE_POLICY=OPT_IN_FOR_AUTOMATIC_RESTART', payload('VK_NIGHT_MAINT_PY'))
        self.assertEqual(payload('VK_NIGHT_MAINT_PY'),
                         (ROOT / 'integrations/nightly_maintenance.py').read_text())

    def test_diagnostic_no_mutation_or_network_requests(self):
        helper = payload('VK_RESOURCES_PY')
        for command in ('sysctl -w', 'apt-get install', 'docker restart', 'systemctl restart',
                        'ip route add', 'iptables -A', 'curl '):
            self.assertNotIn(command, helper)
        self.assertIn("text(proc / 'net/softnet_stat')", helper)
        self.assertIn("text(proc / 'net/dev')", helper)
        self.assertIn("text(proc / 'net/snmp'), 'Udp'", helper)
        report = subprocess.run(['bash', str(ROOT/'install.sh'), '--diagnose-resources', '--seconds', '1'],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(report.returncode, 0, report.stderr[:300])
        data = json.loads(report.stdout)
        for key in ('udp_delta', 'softnet_delta', 'netdev_delta', 'review_summary'):
            self.assertIn(key, data)
        self.assertIn('HOST_LOCAL_ONLY_NOT_A_VPN_SPEED_TEST', data['scope'])

    def test_release_document_and_staging_contract(self):
        text = (ROOT / 'docs/RELEASE_2.5.15_R16_STABILITY_20261021.md').read_text()
        self.assertIn('INCOMPLETE_STAGING_ONLY', text)
        self.assertIn('оператор', text)
        self.assertIn('nightly', text)
        self.assertIn('26.10.17', text)
        self.assertIn('2.5.18 r19', (ROOT/'CHANGELOG.md').read_text().splitlines()[0])


if __name__ == '__main__':
    unittest.main()
