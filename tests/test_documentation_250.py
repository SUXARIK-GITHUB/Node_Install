"""2.5.0 operator documentation and reference policy regressions."""
import json
from pathlib import Path
import unittest
from common import ROOT


class Documentation250Tests(unittest.TestCase):
    def test_reference_plugin_json_exact_ports_and_safe_nonpublic_default(self):
        data = json.loads((ROOT / 'docs/NODE_PLUGINS_REFERENCE_2.5.0.json').read_text())
        cfg = data['pluginConfig']
        self.assertEqual(cfg['egressFilter']['blockedPorts'], [25,137,138,139,445,465,587,2525])
        self.assertEqual(cfg['egressFilter']['blockedIps'], [])
        self.assertEqual(cfg['ingressFilter']['blockedIps'], ['ext:vkarmani_ingress_blocklist'])
        self.assertNotIn('ext:vkarmani_nonpublic_ipv4', json.dumps(cfg))
        self.assertEqual(data['sharedLists']['vkarmani_nonpublic_ipv4']['type'], 'ipList')

    def test_external_taxonomy_and_control_group_are_explicit(self):
        text = (ROOT / 'docs/EXTERNAL_PATH_DIAGNOSTICS_2.5.0.md').read_text()
        for verdict in ('NODE_DOWN', 'PANEL_TO_NODE_BROKEN', 'TCP_443_PATH_BLOCK',
                        'TCP_16_20_SUSPECTED', 'MOBILE_WHITELIST_OR_DEFAULT_DENY',
                        'PREFIX_OR_ASN_PATH_RESTRICTION_SUSPECTED', 'UNKNOWN_PATH_FAILURE'):
            self.assertIn(verdict, text)
        self.assertIn('INCONCLUSIVE', text)
        self.assertIn('non-RU control path', text)
        self.assertIn('RU fixed ISP', text)
        self.assertIn('RU mobile ISP', text)

    def test_replacement_is_node_only_manual_panel_and_not_provider_hopping(self):
        text = (ROOT / 'docs/NODE_REPLACEMENT_2.5.0.md').read_text()
        self.assertIn('Assign Profile/Node Plugins manually in Panel', text)
        self.assertIn('installer remains node-only', text)
        self.assertIn('Do not build a list of “rare ASNs”', text)
        self.assertIn('does not provide an in-place `--repair-acceptance`', text)

    def test_docs_do_not_claim_ban_proof_or_undetectable(self):
        combined = '\n'.join((ROOT / name).read_text() for name in (
            'README.md', 'docs/NODE_PLUGINS_2.5.0.md', 'docs/SURVIVABILITY_2.5.0.md',
            'docs/EXTERNAL_PATH_DIAGNOSTICS_2.5.0.md', 'docs/NODE_REPLACEMENT_2.5.0.md'))
        self.assertIn('not a promise that an IP is ban-proof, undetectable', combined)
        self.assertIn('Cover/REALITY **не гарантируют**', combined)


if __name__ == '__main__':
    unittest.main()
