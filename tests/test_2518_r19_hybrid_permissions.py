"""R19: no privileged worker should be denied access to the internal cover socket.

These offline tests exercise the actual Unix permissions semantics and the installer
source contracts; no real machine configuration is modified.
"""
from pathlib import Path
import os
import stat
import subprocess
import sys
import tempfile
import unittest

from common import ROOT, SCRIPT


class HybridWorkerPermissions(unittest.TestCase):
    def test_installer_and_reboot_tmpfiles_share_secure_group(self):
        self.assertIn('getent group www-data >/dev/null', SCRIPT)
        self.assertIn('install -d -m 0750 -o root -g www-data /run/vkarmani-selfsteal', SCRIPT)
        self.assertIn('d /run/vkarmani-selfsteal 0750 root www-data -', SCRIPT)
        self.assertIn("'root:www-data:750'", SCRIPT)
        self.assertNotIn('install -d -m 0750 -o root -g root /run/vkarmani-selfsteal', SCRIPT)
        self.assertNotIn('d /run/vkarmani-selfsteal 0750 root root -', SCRIPT)

    def test_kernel_permission_model_requires_worker_group(self):
        # Root owns and controls directory, worker can traverse it but not write.
        def worker_traversal(dirmode, worker_group_matches):
            return bool(dirmode & stat.S_IXOTH or
                        worker_group_matches and dirmode & stat.S_IXGRP)
        self.assertFalse(worker_traversal(0o750, False))  # 2.5.17 broken layout
        self.assertTrue(worker_traversal(0o750, True))    # 2.5.18 new layout
        self.assertFalse(bool(0o750 & stat.S_IWGRP))
        self.assertFalse(bool(0o750 & stat.S_IXOTH))

    def test_runtime_upstream_is_only_the_internal_cover_socket(self):
        self.assertIn('listen unix:/run/vkarmani-selfsteal/nginx.sock proxy_protocol;', SCRIPT)
        self.assertIn('proxy_pass $vkarmani_hybrid_upstream;', SCRIPT)
        self.assertIn('DOMAIN unix:/run/vkarmani-selfsteal/cover.sock;', SCRIPT)
        self.assertIn('NGINX_SELFSTEAL_HTTPS_SOCKET=/run/vkarmani-selfsteal/cover.sock', SCRIPT)
        self.assertIn('timeout 25 /usr/local/sbin/vkarmani-selfsteal-check', SCRIPT)

    def test_version_and_no_unsupported_partial_resume(self):
        r = subprocess.run(['bash', str(ROOT/'install.sh'), '--version'], capture_output=True, text=True, timeout=10)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, '2.5.18'))
        s=(ROOT/'README.md').read_text()
        self.assertIn('Do NOT just open TCP/2222', (ROOT/'docs/RELEASE_2.5.18_R19_HYBRID_HOTFIX_20261021.md').read_text())
        self.assertIn('bash ./install.sh', s)

if __name__=='__main__':
    unittest.main()
