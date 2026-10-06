"""Host prerequisite and non-mutation contract for Node Plugins."""
import re
import subprocess
import unittest
from common import SCRIPT, module


class NodePluginsPrereqTests(unittest.TestCase):
    def test_kernel_parser_boundaries(self):
        m = module('VK_NODE_PLUGINS_PY')
        for raw, expected in [('5.6.19', False), ('5.7.0', True), ('5.15.0-109', True), ('6.8.0-1', True)]:
            with self.subTest(raw=raw):
                self.assertEqual(m.kernel_supported(raw), expected)
        for raw in ('', '5', 'linux-6.8', 'x.y.z'):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    m.parse_kernel_version(raw)

    def test_shell_preflight_is_before_host_mutation(self):
        self.assertLess(SCRIPT.index('KERNEL_RELEASE=$(uname -r'), SCRIPT.index('vk_wait_apt_idle "$APT_LOCK_TOTAL_WAIT"'))
        self.assertLess(SCRIPT.index('KERNEL_RELEASE=$(uname -r'), SCRIPT.index("stage 'Компоненты ноды"))

    def test_nftables_package_and_cli_without_service_enablement(self):
        package = re.search(r'NODE_PACKAGES=\((.*?)\)\nDOCKER_PACKAGES', SCRIPT, re.S).group(1)
        self.assertIn('nftables', package.split())
        self.assertIn('nft --version', SCRIPT)
        self.assertNotRegex(SCRIPT, r'systemctl\s+(?:enable|start|restart|enable\s+--now)\s+nftables')
        self.assertNotIn('/etc/nftables.conf', SCRIPT)

    def test_no_node_plugin_firewall_mutation(self):
        active = '\n'.join(line for line in SCRIPT.splitlines() if not line.lstrip().startswith('#'))
        forbidden = (r'nft\s+flush\s+ruleset', r'nft\s+(?:add|delete|flush)\s+(?:table|set|chain|rule)', r'iptables\s+-F')
        for pattern in forbidden:
            self.assertNotRegex(active, pattern)


if __name__ == '__main__':
    unittest.main()
