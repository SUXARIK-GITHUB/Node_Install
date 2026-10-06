"""2.5.0 resource survivability additions stay read-only and fail honestly."""
import os
from pathlib import Path
import tempfile
import unittest
from common import module, payload


M = module('VK_RESOURCES_PY')


class FakeStat:
    f_blocks = 1000
    f_bavail = 80
    f_frsize = 1048576
    f_files = 1000
    f_favail = 80


class ResourcesSurvivabilityTests(unittest.TestCase):
    def test_conntrack_parser_thresholds_and_absence(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            base = root / 'sys/net/netfilter'; base.mkdir(parents=True)
            (base / 'nf_conntrack_count').write_text('700\n')
            (base / 'nf_conntrack_max').write_text('1000\n')
            r = M.conntrack_snapshot(root)
            self.assertTrue(r['verified']); self.assertEqual(r['percent'], 70.0); self.assertEqual(r['status'], 'WARN')
            (base / 'nf_conntrack_count').write_text('850\n')
            self.assertEqual(M.conntrack_snapshot(root)['status'], 'CRITICAL')
        with tempfile.TemporaryDirectory() as t:
            r = M.conntrack_snapshot(Path(t))
            self.assertFalse(r['verified']); self.assertEqual(r['scope'], 'HOST_WIDE_NOT_VPN_ONLY')

    def test_disk_inode_percentages_and_thresholds(self):
        r = M.disk_snapshot('/', statvfs=lambda _: FakeStat())
        self.assertEqual(r['total_MiB'], 1000.0)
        self.assertEqual(r['available_percent'], 8.0)
        self.assertEqual(r['available_inodes_percent'], 8.0)
        self.assertEqual(r['status'], 'CRITICAL')  # only 80 MiB available triggers the byte threshold
        self.assertEqual(r['inode_status'], 'WARN')
        self.assertEqual(r['basis'], 'statvfs_f_bavail_and_f_favail')

    def test_reboot_required_marker(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); (root / 'var/run').mkdir(parents=True)
            self.assertFalse(M.reboot_required(root))
            (root / 'var/run/reboot-required').write_text('')
            self.assertTrue(M.reboot_required(root))

    def test_no_auto_tuning_or_firewall_mutation(self):
        code = payload('VK_RESOURCES_PY')
        for forbidden in ('sysctl -w', 'nft add', 'nft delete', 'iptables', 'ip route', 'tc qdisc', 'swapon'):
            self.assertNotIn(forbidden, code)


if __name__ == '__main__':
    unittest.main()
