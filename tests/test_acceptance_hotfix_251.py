"""2.5.1 hotfix regressions for the known 2.5.0 final-acceptance failure."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from common import ROOT, SCRIPT


class AcceptanceHotfix251Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        match = re.search(r'(?ms)^vkarmani_repair_acceptance_main\(\) \{\n.*?^\}\n', SCRIPT)
        if not match:
            raise AssertionError('missing vkarmani_repair_acceptance_main')
        cls.repair = match.group(0)

    def test_fresh_writer_can_stage_all_acceptance_files_without_host_mutation(self):
        with tempfile.TemporaryDirectory(prefix='vk-251-stage-') as tmp:
            root = Path(tmp)
            checker = root / 'vkarmani-node-check'
            plugin = root / 'node_plugins.py'
            time_helper = root / 'time_helper.py'
            code = r'''
source "$1"
LIB="$2"
vk_write_acceptance "$3" "$4" "$5"
'''
            result = subprocess.run(
                ['bash', '-c', code, '_', str(ROOT / 'install.sh'), str(root),
                 str(checker), str(plugin), str(time_helper)],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            subprocess.run(['bash', '-n', str(checker)], check=True, timeout=5)
            compile(plugin.read_text(), str(plugin), 'exec')
            compile(time_helper.read_text(), str(time_helper), 'exec')
            self.assertEqual(checker.stat().st_mode & 0o777, 0o755)
            self.assertEqual(plugin.stat().st_mode & 0o777, 0o700)
            self.assertEqual(time_helper.stat().st_mode & 0o777, 0o700)

    def test_repair_is_exact_failed_250_only_and_preserves_install_version(self):
        self.assertIn('local base_version=2.5.0', self.repair)
        self.assertIn('local repair_version=2.5.2', self.repair)
        self.assertIn("^rc=1 line=6412", self.repair)
        self.assertIn('affb9c5b282d09156ad8eaa304606870698eea12c6f1f54c9e7e36e1c71f789e', self.repair)
        self.assertIn('5e7b09208c07e1121370fd69d0c97d2ca37b2a8c86eb3a0ace0376eb63044fe6', self.repair)
        self.assertIn('2c4ee1fba63649d35f5e0ee164e8598eda05da725c95b7bbcfd7a91697971cbc', self.repair)
        self.assertIn('ACCEPTANCE_REPAIR_2_5_2', self.repair)
        self.assertIn('исходная install-version сохранена как 2.5.0', self.repair)
        self.assertNotRegex(self.repair, r'>\s*"\$state/install-version"')
        self.assertNotIn('install-version.tmp', self.repair)

    def test_repair_does_not_touch_os_network_or_container_lifecycle(self):
        for marker in ('apt-get ', 'apt ', 'ufw ', 'iptables ', 'nft ', 'update-grub',
                       'systemctl restart', 'systemctl reboot', 'docker compose',
                       'docker stop', 'docker rm', 'docker restart'):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, self.repair)
        self.assertIn("docker inspect remnanode --format '{{.State.Running}}'", self.repair)
        self.assertIn('"$checker" --preboot', self.repair)

    def test_cli_exposes_explicit_repair_only(self):
        self.assertIn('--repair-acceptance', SCRIPT)
        self.assertIn('--repair-acceptance) shift; vkarmani_repair_acceptance_main', SCRIPT)


if __name__ == '__main__':
    unittest.main()
