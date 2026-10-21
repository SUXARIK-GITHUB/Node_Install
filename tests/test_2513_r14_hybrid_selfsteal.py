"""R14 offline contracts: SNI-only passthrough, own HTTPS, and scoped NODE_PORT.

No installation, no network requests, no modification outside disposable tempdirs.
"""
import copy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from common import ROOT, SCRIPT, module, payload, template

MODES = ('max.ru', 'ya.ru', 'rutube.ru', 'mail.ru')
SOCKET = '/dev/shm/nginx.sock'


class HybridConfiguration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vk-r14-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.conf = self.root / 'nginx.conf'
        self.fragment = self.root / 'hybrid.conf'
        self.original = 'events { worker_connections 2048; }\nhttp {}\n'
        self.conf.write_text(self.original)

    def generator(self, mode, domain='node.example.test'):
        code = payload('PY_NGINX_HYBRID_STREAM')
        self.assertIn("Path('/etc/nginx/nginx.conf')", code)
        self.assertIn("Path('/etc/nginx/vkarmani-hybrid-stream.conf')", code)
        code = code.replace("Path('/etc/nginx/nginx.conf')", f'Path({str(self.conf)!r})')
        code = code.replace("Path('/etc/nginx/vkarmani-hybrid-stream.conf')", f'Path({str(self.fragment)!r})')
        return subprocess.run([sys.executable, '-B', '-c', code, domain, mode],
                              capture_output=True, text=True, timeout=5)

    def test_each_external_mode_routes_only_selected_sni_and_own_site(self):
        for mode in MODES:
            with self.subTest(mode=mode):
                result = self.generator(mode)
                self.assertEqual(result.returncode, 0, result.stderr)
                text = self.fragment.read_text()
                self.assertIn('listen unix:/run/vkarmani-selfsteal/nginx.sock proxy_protocol;', text)
                self.assertIn('ssl_preread on;', text)
                self.assertIn('proxy_pass $vkarmani_hybrid_upstream;', text)
                self.assertIn('node.example.test unix:/run/vkarmani-selfsteal/cover.sock;', text)
                self.assertIn(f'    {mode} {mode}:443;', text)
                self.assertIn('default unix:/run/vkarmani-selfsteal/cover.sock;', text)
                self.assertIn('resolver 1.1.1.1 1.0.0.1 ipv6=off', text)
                self.assertNotIn('proxy_protocol on;', text)
                self.assertNotIn('proxy_pass $ssl_preread_server_name;', text)
                for other in set(MODES) - {mode}:
                    self.assertNotIn(f'    {other} {other}:443;', text)
                self.assertIn('# VKARMANI_HYBRID_STREAM_V1', self.conf.read_text())
                self.assertTrue(self.conf.read_text().startswith(self.original))
                self.assertEqual(self.generator(mode).returncode, 1)  # refuse overwrite
                self.fragment.unlink()
                self.conf.write_text(self.original)

    def test_fail_closed_on_malformed_or_foreign_config(self):
        for name, domain, mode in (
            ('unreviewed-mode', 'node.example.test', 'example.com'),
            ('domain-injection', 'node.example.test;proxy_pass', 'max.ru'),
            ('uppercase-mode', 'node.example.test', 'MAX.RU'),
        ):
            with self.subTest(name=name):
                self.assertNotEqual(self.generator(mode, domain).returncode, 0)
                self.assertEqual(self.conf.read_text(), self.original)
                self.assertFalse(self.fragment.exists())
        self.conf.write_text(self.original + '\nstream { server { listen 8888; } }\n')
        self.assertNotEqual(self.generator('max.ru').returncode, 0)
        self.assertFalse(self.fragment.exists())

    def test_socket_prepare_executes_for_both_modes_without_touching_host(self):
        import json
        for mode in ('local', 'max.ru'):
            with self.subTest(mode=mode):
                root = self.root / mode
                root.mkdir()
                config = root / 'config.json'
                main_sock = root / 'nginx.sock'
                cover_sock = root / 'cover.sock'
                lock = root / 'prepare.lock'
                config.write_text(json.dumps({
                    'reality_mode': mode,
                    'selfsteal_host_socket': str(main_sock)
                }))
                source = payload('VK_SOCKET_PREPARE')
                source = source.replace("Path('/etc/vkarmani-node/config.json')", f'Path({str(config)!r})')
                source = source.replace("'/run/vkarmani-selfsteal/nginx.sock'", repr(str(main_sock)))
                source = source.replace("'/run/vkarmani-selfsteal/cover.sock'", repr(str(cover_sock)))
                source = source.replace("'/run/lock/vkarmani-selfsteal-socket.lock'", repr(str(lock)))
                result = subprocess.run([sys.executable, '-B', '-c', source],
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('SELFSTEAL_SOCKET_PREPARE=ABSENT', result.stdout)
                if mode == 'max.ru':
                    self.assertIn('SELFSTEAL_COVER_SOCKET_PREPARE=ABSENT', result.stdout)
                else:
                    self.assertNotIn('SELFSTEAL_COVER_SOCKET_PREPARE', result.stdout)

    def test_ssl_socket_split_and_signed_package_gate(self):
        https = template('/etc/nginx/conf.d/20-vkarmani-selfsteal.conf')
        self.assertEqual(https.count('listen unix:$NGINX_SELFSTEAL_HTTPS_SOCKET'), 2)
        self.assertEqual(https.count('$NGINX_SELFSTEAL_HTTPS_PROXY'), 2)
        self.assertIn('NGINX_SELFSTEAL_HTTPS_SOCKET=/run/vkarmani-selfsteal/nginx.sock', SCRIPT)
        self.assertIn('NGINX_SELFSTEAL_HTTPS_SOCKET=/run/vkarmani-selfsteal/cover.sock', SCRIPT)
        self.assertIn('NGINX_SELFSTEAL_HTTPS_PROXY=\'\'', SCRIPT)
        self.assertIn('NODE_PACKAGES+=(libnginx-mod-stream)', SCRIPT)
        self.assertLess(SCRIPT.index('NODE_PACKAGES+=(libnginx-mod-stream)'),
                        SCRIPT.index('vk_apt_run "${APT[@]}" --simulate install'))
        self.assertLess(SCRIPT.index('PY_NGINX_HYBRID_STREAM'),
                        SCRIPT.index('nginx -t\nsystemctl reload nginx', SCRIPT.index('PY_NGINX_HYBRID_STREAM')))

    def test_socket_preparer_checks_cover_socket_and_rejects_live_stale(self):
        script = payload('VK_SOCKET_PREPARE')
        self.assertIn("prepare('/run/vkarmani-selfsteal/cover.sock')", script)
        self.assertIn("c.get('reality_mode', 'local') != 'local'", script)
        self.assertNotIn("cfg.get('reality_mode', 'local') != 'local'", script)
        self.assertIn('LIVE_SOCKET_UNCHANGED', script)
        self.assertIn('PARENT_SYMLINK', script)


class HybridProfilesAndPorts(unittest.TestCase):
    def test_every_mode_has_single_xray_listener_local_target_proxy_v1(self):
        # Also checked deeply by test_2513_r13_reality_modes and test_profile_policy.
        self.assertIn("target = '/dev/shm/nginx.sock'", payload('PY_HELPER'))
        self.assertIn("target = '/dev/shm/nginx.sock'", payload('VK_XHTTP_PROFILE_PY'))
        self.assertIn('xver = 1', payload('PY_HELPER'))
        self.assertIn('xver = 1', payload('VK_XHTTP_PROFILE_PY'))
        self.assertIn("REMOTE_TLS_OK=0", SCRIPT)
        self.assertIn('[[ "$PUBLIC_TLS_OK" -eq 1 && "$REMOTE_TLS_OK" -eq 1 ]] && XRAY_COVER_OK=1', SCRIPT)

    def test_scoped_node_port_only_for_new_ordinary(self):
        self.assertIn('NODE_PORT_ARG=', SCRIPT)
        self.assertIn('NODE_PORT_DEFAULT=$((10#$NODE_PORT_ARG))', SCRIPT)
        self.assertIn('NODE_PORT_ARG" ]] || { echo "STOP: --node-port cannot migrate', SCRIPT)
        self.assertIn('NODE_PACKAGES+=(libnginx-mod-stream)', SCRIPT)
        self.assertIn('NODE_PORT={c["node_port"]}', payload('PY_HELPER'))
        self.assertIn('ufw allow proto tcp from "$panel" to any port "$NODE_PORT"', SCRIPT)
        start=SCRIPT.index('if [[ -n "$NODE_PORT_ARG" ]]; then',SCRIPT.index('--version)'))
        finish=SCRIPT.index('# Three inputs before any',start)
        snippet=SCRIPT[start:finish]
        for port in ('32443', '24433', '2222'):
            command=f'NODE_PORT_ARG={port}; NODE_PORT_DEFAULT=2222; '+snippet+'\necho "$NODE_PORT_DEFAULT"'
            r=subprocess.run(['bash','-c',command],capture_output=True,text=True,timeout=5)
            self.assertEqual(r.returncode,0,r.stderr)
            self.assertEqual(r.stdout.strip(),port)
        for port in ('61001','0','22','443','99999','-1','32443;touch /tmp/danger'):
            command=f'NODE_PORT_ARG={port!r}; NODE_PORT_DEFAULT=2222; '+snippet+'\necho UNEXPECTED'
            r=subprocess.run(['bash','-c',command],capture_output=True,text=True,timeout=5)
            self.assertEqual(r.returncode,2,r.stderr)
            self.assertNotIn('UNEXPECTED',r.stdout)


if __name__=='__main__':
    unittest.main()
