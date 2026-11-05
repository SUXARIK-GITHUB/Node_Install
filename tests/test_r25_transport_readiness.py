"""Offline validation for optional transports; no service or firewall changes."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from common import ROOT
sys.path.insert(0, str(ROOT/'integrations'))
import optional_transports as opt
import transport_readiness as readiness


class BundleGate(unittest.TestCase):
    domain = 'node.example.test'

    def content(self, mode):
        if mode == 'xhttp-tls':
            return opt.xhttp_tls(self.domain, 33643, '/api/AbCdEf1234567890')
        if mode == 'hysteria2':
            return opt.hysteria2(self.domain, 443)
        return opt.awg2(self.domain, 51820)

    def test_every_optional_transport_is_explicitly_review_not_deployed(self):
        if not shutil.which('openssl'):
            self.skipTest('openssl required for AWG2 key generation')
        with tempfile.TemporaryDirectory() as td:
            for mode in ('xhttp-tls', 'hysteria2', 'awg2'):
                with self.subTest(mode=mode):
                    dest = Path(td)/mode
                    data = self.content(mode)
                    opt.write_bundle(dest, data)
                    result = readiness.check(mode, dest, self.domain)
                    self.assertEqual(result['status'], 'REVIEW')
                    self.assertEqual(result['static_bundle'], 'VALID')
                    self.assertEqual(result['actions_performed'], 'NONE')
                    self.assertGreaterEqual(len(result['missing_verification']), 4)
                    serialized = json.dumps(result)
                    self.assertNotIn(self.domain, serialized)
                    for item in (data.get('client-reference.json'), data.get('client-reference.conf')):
                        if item:
                            self.assertNotIn(item.decode()[:70], serialized)
                    run = subprocess.run([sys.executable, '-B', str(ROOT/'integrations/transport_readiness.py'),
                                          mode, '--bundle', str(dest), '--expected-domain', self.domain,
                                          '--strict'], capture_output=True, text=True, timeout=12)
                    self.assertEqual(run.returncode, 2, run.stderr)
                    self.assertEqual(json.loads(run.stdout)['status'], 'REVIEW')

    def test_fails_tampering_and_privilege_relaxation(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td)/'bundle'
            bundle = self.content('hysteria2')
            opt.write_bundle(folder, bundle)
            file = folder/'client-reference.json'
            original = json.loads(file.read_bytes())
            original['auth'] = 'not-the-server-auth'
            file.write_text(json.dumps(original))
            with self.assertRaisesRegex(readiness.CheckError, 'CLIENT_SERVER_MISMATCH'):
                readiness.check('hysteria2', folder, self.domain)
            file.write_bytes(bundle['client-reference.json'])
            file.chmod(0o644)
            with self.assertRaisesRegex(readiness.CheckError, 'PERMISSIONS_INVALID'):
                readiness.check('hysteria2', folder, self.domain)
            file.chmod(0o600)
            with self.assertRaisesRegex(readiness.CheckError, 'CASCADE'):
                readiness.check('hysteria2', folder, self.domain, 'entry')
            with self.assertRaisesRegex(readiness.CheckError, 'CASCADE'):
                readiness.check('hysteria2', folder, self.domain, 'exit')
            folder.chmod(0o755)
            with self.assertRaisesRegex(readiness.CheckError, 'PRIVATE_BUNDLE_PERMISSIONS_INVALID'):
                readiness.check('hysteria2', folder, self.domain)

    def test_rejects_symlinks_and_incorrect_route(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            folder = root/'bundle'
            opt.write_bundle(folder, self.content('xhttp-tls'))
            route=folder/'nginx-location.conf'
            raw=route.read_bytes()
            route.write_bytes(raw.replace(b':33643', b':33644'))
            with self.assertRaisesRegex(readiness.CheckError, 'NGINX_AND_XHTTP_ROUTE_DIVERGED'):
                readiness.check('xhttp-tls', folder, self.domain)
            route.unlink()
            route.symlink_to('/etc/passwd')
            with self.assertRaises(OSError):
                readiness.check('xhttp-tls', folder, self.domain)

    def test_main_install_entrypoint_dispatches_readiness_without_activating_services(self):
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)/'safe-bundle'
            opt.write_bundle(directory, self.content('xhttp-tls'))
            run = subprocess.run(['bash', str(ROOT/'install.sh'), '--transport-readiness',
                                  'xhttp-tls', '--bundle', str(directory),
                                  '--expected-domain', self.domain, '--strict'],
                                 capture_output=True, text=True, timeout=12)
            self.assertEqual(run.returncode, 2, run.stderr)
            result = json.loads(run.stdout)
            self.assertEqual(result['status'], 'REVIEW')
            self.assertEqual(result['actions_performed'], 'NONE')
            self.assertNotIn(self.domain, run.stdout + run.stderr)

    def test_symlinked_bundle_parent_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            folder = root / 'safe'
            opt.write_bundle(folder, self.content('xhttp-tls'))
            (root/'link').symlink_to(folder, target_is_directory=True)
            with self.assertRaisesRegex(readiness.CheckError, 'PRIVATE_BUNDLE_SYMLINK_COMPONENT'):
                readiness.check('xhttp-tls', root/'link', self.domain)

    def test_awg_public_key_and_header_mismatches(self):
        if not shutil.which('openssl'):
            self.skipTest('openssl required for AWG2')
        with tempfile.TemporaryDirectory() as td:
            folder=Path(td)/'bundle'
            data=self.content('awg2')
            opt.write_bundle(folder,data)
            server=folder/'awg0-server.conf'
            content=server.read_text()
            server.write_text(content.replace('PresharedKey = ', 'PresharedKey = XYZ', 1))
            with self.assertRaisesRegex(readiness.CheckError, 'PSK_MISMATCH'):
                readiness.check('awg2', folder, self.domain)
            server.write_bytes(data['awg0-server.conf'])
            content=server.read_text()
            import re
            h1=re.search(r'(?m)^H1 = (.*)$', content)
            self.assertIsNotNone(h1)
            server.write_text(content.replace('H2 = ', 'H2 = ' + h1.group(1) + '\n# old = ', 1))
            with self.assertRaisesRegex(readiness.CheckError, 'AWG2_ADDRESS_MTU_OR_OBFUSCATION_MISMATCH'):
                readiness.check('awg2', folder, self.domain)


if __name__ == '__main__': unittest.main()
