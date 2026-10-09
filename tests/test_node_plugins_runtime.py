"""Structured nftables runtime contract tests."""
import json
import subprocess
import unittest
from common import module


M = module('VK_NODE_PLUGINS_PY')


def nft_json(omit_set=None, omit_chain=None):
    rows = [{'table': {'family': 'ip', 'name': 'remnanode'}}]
    for name in sorted(M.REQUIRED_SETS):
        if name != omit_set:
            rows.append({'set': {'family': 'ip', 'table': 'remnanode', 'name': name, 'elem': []}})
    for name in sorted(M.REQUIRED_CHAINS):
        if name != omit_chain:
            rows.append({'chain': {'family': 'ip', 'table': 'remnanode', 'name': name, 'counter': {'packets': 0}}})
    return json.dumps({'nftables': rows})


class NodePluginsRuntimeTests(unittest.TestCase):
    def test_good_empty_sets_and_zero_counters_pass(self):
        self.assertEqual(M.parse_nft_contract(nft_json()), (True, 'STRUCTURE_OK'))

    def test_missing_structure_and_malformed_json_fail(self):
        ok, reason = M.parse_nft_contract(nft_json(omit_set='torrent-blocker'))
        self.assertFalse(ok); self.assertIn('torrent-blocker', reason)
        ok, reason = M.parse_nft_contract(nft_json(omit_chain='forward'))
        self.assertFalse(ok); self.assertIn('forward', reason)
        self.assertEqual(M.parse_nft_contract(json.dumps({'nftables': []})), (False, 'MISSING_TABLE'))
        with self.assertRaises((ValueError, json.JSONDecodeError)):
            M.parse_nft_contract('{bad')

    def test_runtime_nonzero_and_timeout_are_not_pass(self):
        def nonzero(*args, **kwargs):
            return subprocess.CompletedProcess(args[0], 1, stdout='', stderr='')
        with self.assertRaises(M.Unverified):
            M.nft_runtime_status(nonzero)
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(args[0], 8)
        with self.assertRaises(M.Unverified):
            M.nft_runtime_status(timeout)


if __name__ == '__main__':
    unittest.main()
