"""2.5.0 negative regressions: no anti-DPI/firewall/custom-core shortcuts."""
import re
import unittest
from pathlib import Path
from common import ROOT, payload, template


class SecurityRegression250Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.install = (ROOT / 'install.sh').read_text()
        cls.acceptance = payload('VK_PAYLOAD_VK_WRITE_ACCEPTANCE')
        cls.compose = template('"$OPT/compose.yaml"')

    def test_no_destructive_firewall_or_rst_autoblock_commands(self):
        forbidden = (
            r'(?m)^\s*(?:sudo\s+)?iptables\s+-F\b',
            r'(?m)^\s*(?:sudo\s+)?nft\s+flush\s+ruleset\b',
            r'(?m)^\s*(?:sudo\s+)?ipset\s+(?:create|add|restore)\b',
        )
        for pattern in forbidden:
            with self.subTest(pattern=pattern):
                self.assertIsNone(re.search(pattern, self.install))
        for marker in ('CyberOK', 'GOVIPS', 'auto_collected', 'upe4d/tspublock'):
            self.assertNotIn(marker, self.install)

    def test_no_censorship_scanner_daemon_or_custom_xray_payload(self):
        for marker in ('rkn-block-checker', 'ByeByeVPN', 'dpi-checker', 'Finalmask'):
            self.assertNotIn(marker, self.install)
        self.assertNotRegex(self.install, r'(?i)(?:curl|wget)[^\n]*(?:xray-core|xray-linux|rw-core)')
        self.assertNotRegex(self.install, r'(?i)\b(?:install|cp|mv)\b[^\n]*/usr/local/bin/rw-core')

    def test_compose_does_not_mount_docker_socket_and_keeps_security_contract(self):
        self.assertNotIn('/var/run/docker.sock:', self.compose)
        self.assertIn('      - NET_ADMIN', self.compose)
        self.assertIn('      - NET_RAW', self.compose)
        self.assertIn('      - no-new-privileges:true', self.compose)
        self.assertIn('network_mode: host', self.compose)

    def test_generated_acceptance_checks_effective_runtime_security(self):
        self.assertIn("{{json .HostConfig.CapAdd}}", self.acceptance)
        self.assertIn("{{json .HostConfig.CapDrop}}", self.acceptance)
        self.assertIn("{{json .HostConfig.SecurityOpt}}", self.acceptance)
        self.assertIn("cap_add != ['NET_ADMIN']", self.acceptance)
        self.assertIn("cap_drop != ['NET_RAW']", self.acceptance)
        self.assertIn("startswith('no-new-privileges')", self.acceptance)

    def test_no_new_public_diagnostics_service_contract(self):
        # External path diagnosis remains a runbook. The node installer must not
        # expose the research tool names or add an additional scanner service.
        for marker in ('rkn-block-checker', 'ByeByeVPN', 'dpi-checker'):
            self.assertNotIn(marker, self.compose)
        self.assertNotIn('docker.sock:/var/run/docker.sock', self.compose)


if __name__ == '__main__':
    unittest.main()
