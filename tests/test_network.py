from pathlib import Path
import subprocess
import tempfile
import unittest

from common import module, template


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.h = module('VK_PAYLOAD_VK_WRITE_NETWORK_SCRIPT')
        self.config = template('/etc/sysctl.d/99-vkarmani-node.conf')
        self.entries = self.h.parse_config(self.config)

    def make_proc(self, root, missing=()):
        for key, value in self.entries:
            if key not in missing:
                path = root.joinpath(*key.split('.'))
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(value + '\n')

    def test_actual_sysctl_template_and_mtu_policy(self):
        values = dict(self.entries)
        self.assertEqual(values['net.ipv4.tcp_mtu_probing'], '1')
        self.assertEqual(values['net.ipv4.tcp_congestion_control'], 'bbr')
        self.assertEqual(values['net.core.default_qdisc'], 'fq')
        self.assertNotIn('net.ipv4.tcp_mem', values)
        self.assertNotIn('net.ipv4.tcp_tw_reuse', values)

    def test_duplicate_and_unknown_ipv6_keys_refused(self):
        for extra in ('net.ipv4.tcp_mtu_probing = 1\n', 'net.ipv6.conf.eth0.disable_ipv6 = 1\n', 'NOT_AN_ASSIGNMENT\n'):
            with self.subTest(extra=extra), self.assertRaises(self.h.ApplyError):
                self.h.parse_config(self.config + extra)

    def test_missing_required_acceleration_declaration_fails(self):
        with self.assertRaises(self.h.ApplyError):
            self.h.parse_config(self.config.replace('-net.core.default_qdisc = fq', ''))

    def test_all_present_entries_verified(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.make_proc(root)
            kept, skipped = self.h.select_entries(self.entries, root, False)
            self.assertFalse(skipped)
            self.h.verify_entries(kept, root)

    def test_three_missing_ipv6_keys_only_skipped_after_kernel_disabled(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.make_proc(root, self.h.IPV6_KEYS)
            kept, skipped = self.h.select_entries(self.entries, root, True)
            self.assertEqual(set(skipped), self.h.IPV6_KEYS)
            self.h.verify_entries(kept, root)
            with self.assertRaises(self.h.ApplyError):
                self.h.select_entries(self.entries, root, False)

    def test_missing_non_ipv6_key_never_ignored(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.make_proc(root, {'net.ipv4.tcp_syncookies'})
            with self.assertRaises(self.h.ApplyError):
                self.h.select_entries(self.entries, root, True)

    def test_readback_mismatch_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.make_proc(root)
            root.joinpath('net/ipv4/tcp_syncookies').write_text('0\n')
            with self.assertRaises(self.h.ApplyError):
                self.h.verify_entries(self.entries, root)

    def test_unsupported_bbr_preserves_unchanged_kernel_value_and_reports(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.make_proc(root)
            root.joinpath('net/ipv4/tcp_congestion_control').write_text('cubic\n')
            def run(args, **_):
                return subprocess.CompletedProcess(args, 1 if args[-1].endswith('=bbr') else 0, '', '')
            kept, notes = self.h.resolve_performance(self.entries, root, run=run)
            self.assertEqual(dict(kept)['net.ipv4.tcp_congestion_control'], 'cubic')
            self.assertEqual(len(notes), 1)
            target = root / 'effective.json'
            self.h.save_effective(kept, notes, target)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertIn('cubic', target.read_text())

    def test_failed_write_that_changes_value_is_not_safe_fallback(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.make_proc(root)
            def run(args, **_):
                key = args[-1].split('=')[0]
                root.joinpath(*key.split('.')).write_text('changed\n')
                return subprocess.CompletedProcess(args, 1, '', '')
            with self.assertRaises(self.h.ApplyError):
                self.h.resolve_performance(self.entries, root, run=run)

    def test_built_in_modules_do_not_require_successful_modprobe(self):
        calls = []
        def run(args, **_):
            calls.append(args)
            return subprocess.CompletedProcess(args, 1, '', 'module absent')
        self.h.load_modules(run=run)
        self.assertEqual(calls, [['modprobe', 'tcp_bbr'], ['modprobe', 'sch_fq']])

    def test_sysctl_failure_never_suppressed(self):
        def run(args, **_):
            return subprocess.CompletedProcess(args, 1, '', 'read only')
        with self.assertRaises(self.h.ApplyError):
            self.h.apply_entries(self.entries, run=run)


if __name__ == '__main__':
    unittest.main()
