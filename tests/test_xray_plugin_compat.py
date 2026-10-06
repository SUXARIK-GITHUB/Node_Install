"""Separate Xray functional and reviewed security floors."""
import subprocess
import unittest
from common import SCRIPT, module


M = module('VK_NODE_PLUGINS_PY')


class XrayPluginCompatTests(unittest.TestCase):
    def test_floor_matrix(self):
        cases = {
            '26.3.26': (False, False),
            '26.3.27': (True, False),
            '26.7.10': (True, False),
            '26.7.11': (True, True),
            '26.7.28': (True, True),
        }
        for version, expected in cases.items():
            with self.subTest(version=version):
                status = M.xray_floor_status('Xray ' + version + ' (synthetic)\n')
                self.assertEqual((status['plugin'], status['security']), expected)
        for raw in ('', 'rw-core unknown', 'Xray 26.7', 'Xray 26.7.28\nXray 26.7.29\n'):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    M.parse_xray_version(raw)

    def test_command_failure_and_timeout_not_verified(self):
        def nonzero(*args, **kwargs):
            return subprocess.CompletedProcess(args[0], 1, stdout='', stderr='')
        with self.assertRaises(M.Unverified):
            M.xray_runtime_status(nonzero)
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(args[0], 8)
        with self.assertRaises(M.Unverified):
            M.xray_runtime_status(timeout)

    def test_no_custom_core_download_or_replacement_path(self):
        self.assertNotRegex(SCRIPT, r'curl[^\n]*(?:Xray|xray-core)')
        self.assertNotRegex(SCRIPT, r'(?:cp|mv|install)[^\n]*/usr/local/bin/rw-core')


if __name__ == '__main__':
    unittest.main()
