"""2.5.4: independent offline XHTTP + REALITY profile and switching contract.

No Docker daemon, network, systemd, UFW or installed-node modification.
Raw mode must stay byte-compatible; switching only changes Panel's active inbound.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from common import ROOT, SCRIPT, module, payload, template


class XHTTPProfileTests(unittest.TestCase):
    def setUp(self):
        self.h = module('PY_HELPER')
        spec = importlib.util.spec_from_file_location('vkarmani_test_xhttp_profile',
                                                     ROOT / 'integrations/xhttp_profile.py')
        self.x = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.x)
        self.temp = tempfile.TemporaryDirectory(prefix='vk-xhttp-test-')
        self.addCleanup(self.temp.cleanup)
        self.etc = Path(self.temp.name) / 'etc'
        self.h.ETC = self.etc
        self.h.REALITY_EXPORT = Path(self.temp.name) / 'keys.txt'
        self.c = {'domain': 'node.example.test', 'public_ipv4': '8.8.4.4',
                  'panel_ipv4': ['1.1.1.1'], 'node_port': 2222}
        patcher = patch.object(self.h, 'detect_local_public_ipv4s',
                               return_value={'8.8.4.4': 'eth0'})
        patcher.start()
        self.addCleanup(patcher.stop)
        _, _, self.raw = self.h.make_keys_profile(self.c)
        self.h.atomic_json(self.etc / 'config.json', self.c)

    def test_embedded_helper_is_exact_same_source(self):
        self.assertEqual(payload('VK_XHTTP_PROFILE_PY'), (ROOT / 'integrations/xhttp_profile.py').read_text().rstrip('\n') + '\n')

    def test_raw_is_unchanged_and_xhttp_is_one_alternative(self):
        keys_before = (self.etc / 'reality.json').read_bytes()
        raw_before = (self.etc / 'profile.json').read_bytes()
        x = self.x.build_xhttp(self.etc)
        self.assertTrue(self.h.validate_profile(x, self.c))
        self.assertTrue(self.h.validate_profile(self.raw, self.c))
        self.assertEqual(self.raw['inbounds'][0]['settings']['flow'], 'xtls-rprx-vision')
        self.assertEqual(x['inbounds'][0]['settings']['flow'], '')
        self.assertEqual(x['inbounds'][0]['streamSettings']['network'], 'xhttp')
        self.assertEqual(len(x['inbounds']), 1)
        self.assertEqual(x['inbounds'][0]['tag'], self.raw['inbounds'][0]['tag'])
        self.assertEqual(x['inbounds'][0]['port'], 443)
        self.assertEqual(x['inbounds'][0]['streamSettings']['realitySettings'],
                         self.raw['inbounds'][0]['streamSettings']['realitySettings'])
        self.assertEqual(x['inbounds'][0]['sniffing'], self.raw['inbounds'][0]['sniffing'])
        self.assertEqual(x['outbounds'], self.raw['outbounds'])
        self.assertEqual(x['dns'], self.raw['dns'])
        self.assertEqual(x['routing'], self.raw['routing'])
        self.assertEqual((self.etc / 'reality.json').read_bytes(), keys_before)
        self.assertEqual((self.etc / 'profile.json').read_bytes(), raw_before)

    def test_xhttp_path_stable_private_distinct_from_shortid(self):
        first = self.x.build_xhttp(self.etc)
        second = self.x.build_xhttp(self.etc)
        self.assertEqual(first, second)
        settings = first['inbounds'][0]['streamSettings']['xhttpSettings']
        self.assertEqual(set(settings), {'mode', 'host', 'path'})
        self.assertEqual(settings['mode'], 'auto')
        self.assertEqual(settings['host'], self.c['domain'])
        self.assertRegex(settings['path'], r'^/[0-9a-f]{32}$')
        self.assertNotIn(json.loads((self.etc / 'reality.json').read_text())['short_id'], settings['path'])

    def check_error(self, new, expected):
        before = copy.deepcopy(new)
        with self.assertRaises(self.h.Failure) as ctx:
            self.h.validate_profile(new, self.c)
        self.assertEqual(str(ctx.exception), expected)
        self.assertEqual(before, new)

    def test_xhttp_vision_and_alias_conflicts_refused(self):
        base = self.x.build_xhttp(self.etc)
        samples = [
            ('flow', lambda p: p['inbounds'][0]['settings'].update(flow='xtls-rprx-vision'),
             'PROFILE_XHTTP_REQUIRES_NO_VISION_FLOW'),
            ('client', lambda p: p['inbounds'][0]['settings'].update(clients=[{'id': 'synthetic', 'flow': 'xtls-rprx-vision'}]),
             'PROFILE_XHTTP_CLIENT_REQUIRES_NO_VISION_FLOW'),
            ('missing_x', lambda p: p['inbounds'][0]['streamSettings'].pop('xhttpSettings'),
             'PROFILE_XHTTP_SETTINGS_UNREVIEWED'),
            ('wrong_mode', lambda p: p['inbounds'][0]['streamSettings']['xhttpSettings'].update(mode='stream-one'),
             'PROFILE_XHTTP_SETTINGS_UNREVIEWED'),
            ('wrong_host', lambda p: p['inbounds'][0]['streamSettings']['xhttpSettings'].update(host='other.example.com'),
             'PROFILE_XHTTP_SETTINGS_UNREVIEWED'),
            ('wrong_path', lambda p: p['inbounds'][0]['streamSettings']['xhttpSettings'].update(path='/../secret'),
             'PROFILE_XHTTP_SETTINGS_UNREVIEWED'),
            ('proxy', lambda p: p['inbounds'][0]['streamSettings'].update(sockopt={'acceptProxyProtocol': True}),
             'PROFILE_DIRECT_INBOUND_MUST_NOT_REQUIRE_PROXY_PROTOCOL'),
            ('method_alias', lambda p: p['inbounds'][0]['streamSettings'].update(method='raw'),
             'PROFILE_REQUIRES_REVIEWED_REALITY_TRANSPORT'),
            ('second_443', lambda p: p['inbounds'].append(copy.deepcopy(p['inbounds'][0])),
             'PROFILE_REQUIRES_ONE_VLESS_INBOUND'),
        ]
        for label, change, expected in samples:
            with self.subTest(label=label):
                value = copy.deepcopy(base)
                change(value)
                self.check_error(value, expected)

    def test_raw_rejects_xhttp_settings_and_key_routing_drift(self):
        p = copy.deepcopy(self.raw)
        p['inbounds'][0]['streamSettings']['xhttpSettings'] = {'mode': 'auto', 'path': '/test'}
        self.check_error(p, 'PROFILE_RAW_MUST_NOT_HAVE_XHTTP_SETTINGS')
        p = copy.deepcopy(self.x.build_xhttp(self.etc))
        p['inbounds'][0]['streamSettings']['realitySettings']['target'] = 'example.com:443'
        self.check_error(p, 'PROFILE_TARGET_MUST_BE_LOCAL_SELFSTEAL_SOCKET')
        p = copy.deepcopy(self.x.build_xhttp(self.etc))
        p['inbounds'][0]['streamSettings']['realitySettings']['xver'] = 0
        self.check_error(p, 'PROFILE_SELFSTEAL_REQUIRES_PROXY_V1')

    def test_render_compare_idempotency_and_symlink_refusal(self):
        dest = self.etc / 'profile-xhttp.json'
        self.x.atomic_write_json(dest, self.x.build_xhttp(self.etc))
        self.assertEqual(dest.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.x.read_private_json(dest), self.x.build_xhttp(self.etc))
        keys_before = (self.etc / 'reality.json').read_bytes()
        src_before = (self.etc / 'profile.json').read_bytes()
        self.assertEqual(subprocess.run(['python3', '-I', '-B', str(ROOT / 'integrations/xhttp_profile.py'),
                                         'compare', '--root', str(self.etc), '--output', str(dest)],
                                        capture_output=True, text=True, timeout=10).returncode, 0)
        dest.write_text('{}')
        old_bytes = dest.read_bytes()
        reject = subprocess.run(['python3', '-I', '-B', str(ROOT / 'integrations/xhttp_profile.py'),
                                 'compare', '--root', str(self.etc), '--output', str(dest)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(reject.returncode, 1)
        self.assertIn('EXISTING_XHTTP_TEMPLATE_DIFFERS_REFUSE_OVERWRITE', reject.stderr)
        self.assertEqual(dest.read_bytes(), old_bytes)
        dest.unlink()
        outside = self.etc / 'outside.json'
        outside.write_text('FOREIGN')
        dest.symlink_to(outside)
        with self.assertRaises(self.x.Invalid):
            self.x.atomic_write_json(dest, self.x.build_xhttp(self.etc))
        self.assertEqual(outside.read_text(), 'FOREIGN')
        self.assertEqual((self.etc / 'reality.json').read_bytes(), keys_before)
        self.assertEqual((self.etc / 'profile.json').read_bytes(), src_before)

    def test_xhttp_with_remnawave_service_api_inbound_still_audits(self):
        import contextlib
        import io
        x = self.x.build_xhttp(self.etc)
        x['api'] = {'tag': 'REMNAWAVE_API', 'services': ['StatsService']}
        x['inbounds'].insert(0, {
            'tag': 'REMNAWAVE_API_INBOUND', 'protocol': 'tunnel',
            'listen': '@xtls-api-ISOLATED'})
        x['routing']['rules'].insert(0, {
            'type': 'field', 'inboundTag': ['REMNAWAVE_API_INBOUND'],
            'outboundTag': 'REMNAWAVE_API'})
        p = self.etc / 'with-api.json'
        self.h.atomic_json(p, x)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.h.audit_profile(p, self.c)
        self.assertIn('PROFILE_XHTTP_REALITY_SELFSTEAL_POLICY=PASS', buf.getvalue())
        self.assertIn('LIVE_NODE_AND_HOST_OVERRIDES=NOT_VERIFIED', buf.getvalue())
        self.assertNotIn(x['inbounds'][1]['streamSettings']['realitySettings']['privateKey'],
                         buf.getvalue())

    def test_bad_source_perms_and_reality_key_do_not_overwrite(self):
        cfg = self.etc / 'config.json'
        cfg.chmod(0o644)
        with self.assertRaises(self.x.Invalid):
            self.x.build_xhttp(self.etc)
        cfg.chmod(0o600)
        keys = json.loads((self.etc / 'reality.json').read_text())
        keys['public_key'] = 'A' * 43
        self.h.atomic_json(self.etc / 'reality.json', keys)
        with self.assertRaises(self.x.Invalid):
            self.x.build_xhttp(self.etc)

    def test_nginx_selfsteal_same_h2_proxy_v1_and_no_extra_443(self):
        conf = template('/etc/nginx/conf.d/20-vkarmani-selfsteal.conf')
        self.assertIn('listen unix:/run/vkarmani-selfsteal/nginx.sock ssl', conf)
        self.assertIn('proxy_protocol', conf)
        self.assertIn('$NGINX_HTTP2_DIRECTIVE', conf)
        self.assertNotRegex(conf, r'(?m)^\s*listen\s+(?:0\.0\.0\.0|\*|\$PUBLIC_IP):443')
        self.assertIn('/dev/shm/nginx.sock', SCRIPT)
        self.assertIn("network_mode: host", SCRIPT)
        self.assertIn("NO_REBOOT=0", SCRIPT)

    def test_isolated_prepare_function_runtime_gate_and_idempotency(self):
        # Execute real preparation function with a fake Docker CLI.
        # No writes to host /etc, systemd, firewall, or actual Docker socket.
        import os
        import re
        match = re.search(r'(?ms)^vk_xhttp_prepare_template\(\) \{\n.*?^\}', SCRIPT)
        self.assertIsNotNone(match)
        state = Path(self.temp.name) / 'state'
        state.mkdir(mode=0o700)
        output = self.etc / 'profile-xhttp.json'
        helper = ROOT / 'integrations/xhttp_profile.py'
        source_before = (self.etc / 'profile.json').read_bytes()
        keys_before = (self.etc / 'reality.json').read_bytes()
        shell = match.group() + r'''
        # A non-root offline fixture cannot create a uid-0 file. Model just
        # the production root:0600 output ownership, not its network services.
        stat() {
            if [[ "$1" == '-c' && "$2" == '%u:%a' && "$3" == "$XETC/profile-xhttp.json" ]]; then
                printf '0:600\n'
                return 0
            fi
            command stat "$@"
        }
        docker() {
            case "$1" in
                cp) printf 'DOCKER_CP\n' >> "$TRACE"; return 0 ;;
                exec)
                    if [[ "$3" == 'rm' ]]; then
                        printf 'DOCKER_TMP_REMOVE\n' >> "$TRACE"
                        return 0
                    elif [[ "$3" == '/fake/rw-core' && "$4" == 'run' && "$5" == '-test' ]]; then
                        printf 'CORE_SYNTAX_CHECK\n' >> "$TRACE"
                        [[ "${FAKE_CORE_FAIL:-0}" == 0 ]]
                        return
                    fi ;;
            esac
            return 99
        }
        vk_xhttp_prepare_template "$XHELPER" "$XETC" /fake/rw-core "$XSTATE"
        '''
        env = {**os.environ, 'XHELPER': str(helper), 'XETC': str(self.etc),
               'XSTATE': str(state), 'TRACE': str(Path(self.temp.name) / 'trace')}
        for label in ('first', 'second'):
            with self.subTest(label=label):
                r = subprocess.run(['bash', '-c', shell], env=env, text=True,
                                   capture_output=True, timeout=12)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn('XHTTP_TEMPLATE=PASS', r.stdout)
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                self.assertEqual((self.etc / 'profile.json').read_bytes(), source_before)
                self.assertEqual((self.etc / 'reality.json').read_bytes(), keys_before)
        trace = (Path(self.temp.name) / 'trace').read_text()
        self.assertEqual(trace.count('CORE_SYNTAX_CHECK'), 2)
        self.assertEqual(trace.count('DOCKER_TMP_REMOVE'), 2)
        output.unlink()
        env['FAKE_CORE_FAIL'] = '1'
        r = subprocess.run(['bash', '-c', shell], env=env, text=True,
                           capture_output=True, timeout=12)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('CORE_XHTTP_CONFIG_REJECTED', r.stderr)
        self.assertFalse(output.exists())
        self.assertEqual((self.etc / 'profile.json').read_bytes(), source_before)
        self.assertEqual((self.etc / 'reality.json').read_bytes(), keys_before)

    def test_explicit_mode_has_no_service_mutation_by_design(self):
        self.assertIn('--prepare-xhttp) shift; vkarmani_prepare_xhttp_main', SCRIPT)
        self.assertIn('vk_xhttp_prepare_template "$tmp/xhttp_profile.py"', SCRIPT)
        self.assertIn('docker exec remnanode "$core" run -test', SCRIPT)
        self.assertIn('vk_write_xhttp_profile_helper "$LIB/xhttp_profile.py"', SCRIPT)
        self.assertIn('XHTTP_IMPORT_PROFILE_POLICY', payload('VK_PAYLOAD_VK_WRITE_ACCEPTANCE'))


if __name__ == '__main__':
    unittest.main()
