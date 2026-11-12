"""Report comparison is a read-only, fail-closed, secret-free operation."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from common import ROOT
sys.path.insert(0, str(ROOT / 'scripts'))
import stealth_report_compare as cmp


def sample(*, status='PASS', tls='TLSv1.3'):
    return {'schema': 1, 'scope': 'EXPLICIT_OWNED_ENDPOINT_ONLY',
            'client_or_dpi_stealth_proven': 'NO', 'status': 'UNVERIFIED',
            'checks': {'tls13': {'status': status, 'tls': tls, 'alpn': 'h2'},
                       'post_handshake_records': {'status': 'UNVERIFIED',
                                                   'reason': 'REQUIRES_PCAP_ON_OWN_STAGING'}}}


class CompareTests(unittest.TestCase):
    def test_status_regression_reported_without_values_or_hostnames(self):
        old = sample()
        new = sample(status='FAIL', tls='protocol-failure')
        out = cmp.compare(old, new)
        self.assertEqual(out['status'], 'REVIEW')
        self.assertEqual(out['changed'], [{'check': 'tls13',
                                           'different_fields': ['status', 'tls'],
                                           'status_before': 'PASS', 'status_after': 'FAIL'}])
        self.assertNotIn('node.example.test', json.dumps(out))

    def test_new_parallel_check_not_equated_to_improvement(self):
        new = sample()
        new['checks']['parallel_tls13'] = {'status': 'PASS', 'attempts': 4}
        out = cmp.compare(sample(), new)
        self.assertEqual(out['added_checks'], ['parallel_tls13'])
        self.assertIn('NOT_A_DPI_RESISTANCE_MEASUREMENT', out['observations'])

    def test_file_safety_and_cli_regression_exit(self):
        with tempfile.TemporaryDirectory() as dirname:
            a, b = Path(dirname) / 'a.json', Path(dirname) / 'b.json'
            a.write_text(json.dumps(sample()))
            b.write_text(json.dumps(sample(status='FAIL')))
            self.assertEqual(cmp.main([str(a), str(b), '--strict']), 2)
            b.write_text('{"schema":1,"schema":1}')
            with self.assertRaises(cmp.Invalid):
                cmp.read(b)
            b.unlink()
            b.symlink_to(a)
            with self.assertRaises(OSError):
                cmp.read(b)
            b.unlink()
            a.chmod(0o666)
            with self.assertRaises(cmp.Invalid):
                cmp.read(a)


if __name__ == '__main__':
    unittest.main()
