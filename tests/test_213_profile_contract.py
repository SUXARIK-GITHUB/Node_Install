"""2.1.3 contract regressions using real embedded code and synthetic credentials.

No Docker, panel, host configuration writes or network requests. The generated
profile retains DNS/routing defaults; 2.3.0 also adopts the agreed common Vision flow.
"""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from common import module, payload


class Profile213Tests(unittest.TestCase):
    def setUp(self):
        self.h = module('PY_HELPER')
        self.tmp = tempfile.TemporaryDirectory(prefix='vk-profile-213-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.h.ETC = self.root / 'etc'
        self.h.REALITY_EXPORT = self.root / 'keys.txt'
        self.c = {'domain': 'node.example.test', 'public_ipv4': '8.8.4.4',
                  'panel_ipv4': ['1.1.1.1'], 'node_port': 2222}
        self.local = patch.object(self.h, 'detect_local_public_ipv4s',
                                  return_value={'8.8.4.4': 'eth0'})
        self.local.start()
        self.addCleanup(self.local.stop)
        _, _, self.p = self.h.make_keys_profile(self.c)
        self.i = self.p['inbounds'][0]
        self.r = self.i['streamSettings']['realitySettings']

    def reject(self, code=None):
        before = copy.deepcopy(self.p)
        with self.assertRaises(self.h.Failure) as exc:
            self.h.validate_profile(self.p, self.c)
        if code:
            self.assertEqual(str(exc.exception), code)
        self.assertEqual(self.p, before)

    def api(self, listen='@xtls-api-SYNTHETIC'):
        self.p['api'] = {'tag': 'REMNAWAVE_API', 'services': ['HandlerService', 'StatsService']}
        self.p['inbounds'].insert(0, {
            'tag': 'REMNAWAVE_API_INBOUND', 'protocol': 'tunnel', 'listen': listen})
        self.p['routing']['rules'].insert(0, {
            'inboundTag': ['REMNAWAVE_API_INBOUND'], 'outboundTag': 'REMNAWAVE_API'})

    def test_exact_minimum_string_required_no_silent_coercion(self):
        self.assertEqual(self.r['minClientVer'], '0.0.0')
        for value in ('1.0.0', '0', '0.0', 0, None, False, ['0.0.0']):
            with self.subTest(value=value):
                self.r['minClientVer'] = value
                self.reject('PROFILE_MIN_CLIENT_VER_MUST_BE_0_0_0')
        self.r.pop('minClientVer')
        self.reject('PROFILE_MIN_CLIENT_VER_MUST_BE_0_0_0')

    def test_generator_other_policy_bytes_semantics_preserved(self):
        self.assertEqual(self.i['settings'].get('flow'), 'xtls-rprx-vision')  # New 2.3.0 template only
        self.assertEqual(self.i['settings'], {'clients': [], 'decryption': 'none', 'flow': 'xtls-rprx-vision'})
        self.assertEqual(self.p['dns'], {'servers': ['1.1.1.1', '8.8.8.8'], 'queryStrategy': 'UseIPv4'})
        self.assertEqual(self.p['outbounds'], [
            {'tag': 'DIRECT', 'protocol': 'freedom', 'settings': {'domainStrategy': 'UseIPv4'}},
            {'tag': 'BLOCK', 'protocol': 'blackhole'}])
        self.assertEqual(self.p['routing'], {'domainStrategy': 'IPOnDemand', 'rules': [{
            'type': 'field', 'outboundTag': 'BLOCK', 'ip': [
                '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
                '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16',
                '224.0.0.0/4', '240.0.0.0/4', '8.8.4.4/32', '::/0',
                '1.1.1.1/32']}]})

    def test_guide_and_export_use_same_min_without_key_rotation(self):
        keys = (self.h.ETC / 'reality.json').read_bytes()
        self.h.write_panel_guide(self.c)
        self.h.export_reality_keys_file(self.c)
        guide = (self.h.ETC / 'PANEL-SETUP.txt').read_text()
        self.assertIn('minClientVer=0.0.0', guide)
        self.assertIn('RemnaNode 2.5.6', guide)
        self.assertIn('minClientVer: 0.0.0', self.h.REALITY_EXPORT.read_text())
        self.assertEqual((self.h.ETC / 'reality.json').read_bytes(), keys)

    def test_dns_bad_strategy_rejected_not_confused_with_routing(self):
        for strategy in ('IPIfNonMatch', 'UseIPv6', 'UseIP', '', None):
            with self.subTest(strategy=strategy):
                self.p['dns']['queryStrategy'] = strategy
                self.reject('PROFILE_DNS_REQUIRES_USE_IPV4')

    def test_missing_or_malformed_dns_rejected(self):
        for value in (None, {}, [], 'UseIPv4'):
            with self.subTest(value=value):
                self.p['dns'] = value
                self.reject()

    def test_dns_server_override_cannot_weaken_ipv4_policy(self):
        self.p['dns']['servers'] = [{'address': '1.1.1.1', 'queryStrategy': 'UseIPv6'}]
        self.reject('PROFILE_DNS_SERVER_REQUIRES_USE_IPV4')
        self.p['dns']['servers'][0]['queryStrategy'] = 'UseIPv4'
        self.assertTrue(self.h.validate_profile(self.p, self.c))

    def test_dns_server_shapes(self):
        for value in ([], '1.1.1.1', [None], [{}], [{'address': ''}]):
            with self.subTest(value=value):
                self.p['dns']['servers'] = value
                self.reject()

    def test_dns_boolean_and_ttl_types(self):
        original = copy.deepcopy(self.p['dns'])
        for key, value in [('serveStale', 'true'), ('disableCache', 0),
                           ('enableParallelQuery', None), ('serveExpiredTTL', True),
                           ('serveExpiredTTL', -1), ('serveExpiredTTL', '3600')]:
            with self.subTest(key=key, value=value):
                self.p['dns'] = dict(original, **{key: value})
                self.reject()

    def test_common_vision_with_empty_client_flow_is_read_only(self):
        self.i['settings'].update(flow='xtls-rprx-vision', clients=[
            {'id': '00000000-0000-4000-8000-000000000001', 'flow': ''},
            {'id': '00000000-0000-4000-8000-000000000002'},
            {'id': '00000000-0000-4000-8000-000000000003', 'flow': 'xtls-rprx-vision'}])
        before = copy.deepcopy(self.p)
        self.assertTrue(self.h.validate_profile(self.p, self.c))
        self.assertEqual(self.p, before)

    def test_user_alias_is_supported_without_modification(self):
        self.i['settings']['users'] = self.i['settings'].pop('clients')
        self.i['settings']['flow'] = 'xtls-rprx-vision'
        self.assertTrue(self.h.validate_profile(self.p, self.c))

    def test_invalid_common_and_client_flows_rejected(self):
        self.i['settings']['flow'] = 'xtls-rprx-direct'
        self.reject('PROFILE_VLESS_FLOW_INVALID')
        self.i['settings']['flow'] = 'xtls-rprx-vision'
        self.i['settings']['clients'] = [{'flow': 'xtls-rprx-vision-udp443'}]
        self.reject('PROFILE_VLESS_CLIENT_FLOW_INVALID')

    def test_malformed_clients_rejected(self):
        for value in (None, {}, ['secret-not-a-client']):
            with self.subTest(value=value):
                self.i['settings']['clients'] = value
                self.reject('PROFILE_VLESS_USERS_INVALID')

    def test_public_direct_listener_must_not_expect_proxy_header(self):
        stream = self.i['streamSettings']
        for value in (True, 'true', 'false', None, 0, 1):
            with self.subTest(value=value):
                stream['sockopt'] = {'acceptProxyProtocol': value}
                self.reject('PROFILE_DIRECT_INBOUND_MUST_NOT_REQUIRE_PROXY_PROTOCOL')
        stream['sockopt'] = {'acceptProxyProtocol': False}
        self.assertTrue(self.h.validate_profile(self.p, self.c))
        self.assertEqual(self.r['xver'], 1)  # outbound header to Nginx is unchanged

    def test_torrent_sniffing_contract_is_strict_and_generated_profile_passes(self):
        self.assertTrue(self.h.validate_profile(self.p, self.c))
        original = copy.deepcopy(self.i['sniffing'])
        for value in (None, {}, [], {'enabled': False, 'routeOnly': True, 'destOverride': ['http','tls','quic']},
                      {'enabled': True, 'routeOnly': False, 'destOverride': ['http','tls','quic']}):
            with self.subTest(value=value):
                self.i['sniffing'] = value
                self.reject('PROFILE_TORRENT_SNIFFING_POLICY_INVALID')
        for dest in (['http', 'tls'], ['http', 'tls', 'quic', 'fakedns'], 'http,tls,quic', [1, 'tls', 'quic']):
            with self.subTest(dest=dest):
                self.i['sniffing'] = {'enabled': True, 'routeOnly': True, 'destOverride': dest}
                self.reject('PROFILE_TORRENT_SNIFFING_POLICY_INVALID')
        self.i['sniffing'] = original
        self.assertTrue(self.h.validate_profile(self.p, self.c))

    def test_public_listener_ipv4_only(self):
        for value in ('::', '127.0.0.1', None, 'unrelated.example.test'):
            with self.subTest(value=value):
                self.i['listen'] = value
                self.reject('PROFILE_REQUIRES_NODE_IPV4_LISTENER')
        self.i['listen'] = self.c['public_ipv4']
        self.assertTrue(self.h.validate_profile(self.p, self.c))

    def test_freedom_must_resolve_ipv4(self):
        for value in (None, {}, {'domainStrategy': 'AsIs'}, {'domainStrategy': 'UseIPv6'}):
            with self.subTest(value=value):
                self.p['outbounds'][0]['settings'] = value
                self.reject('PROFILE_FREEDOM_REQUIRES_USE_IPV4')

    def test_outbound_reference_and_duplicate_tags(self):
        self.p['outbounds'][1]['tag'] = 'DIRECT'
        self.reject('PROFILE_OUTBOUND_TAGS_INVALID_OR_DUPLICATE')
        self.p['outbounds'][1]['tag'] = 'BLOCK'
        self.p['routing']['rules'][0]['outboundTag'] = 'UNKNOWN'
        self.reject('PROFILE_ROUTING_OUTBOUND_REFERENCE_INVALID')

    def test_routing_required(self):
        for value in (None, {}, {'domainStrategy': 'AsIs', 'rules': []}):
            with self.subTest(value=value):
                self.p['routing'] = value
                self.reject()

    def test_rule_requires_match_and_target(self):
        for value in ({'outboundTag': 'DIRECT'}, {'network': 'tcp,udp'},
                      {'network': 'tcp,udp', 'outboundTag': 'DIRECT', 'balancerTag': 'X'}):
            with self.subTest(value=value):
                self.p['routing']['rules'] = [value]
                self.reject()

    def test_rule_list_types_and_known_inbounds(self):
        for value in ([], 'private', [None], ['does-not-exist']):
            with self.subTest(value=value):
                self.p['routing']['rules'] = [{'inboundTag': value, 'outboundTag': 'DIRECT'}]
                self.reject()

    def test_synthetic_live_policy_is_supported_not_rewritten(self):
        self.api()
        self.i['settings']['flow'] = 'xtls-rprx-vision'
        self.i['settings']['clients'] = [
            {'id': f'00000000-0000-4000-8000-{n:012d}'} for n in range(1, 151)]
        self.p['dns'].update(servers=['1.1.1.1', '1.0.0.1', '8.8.8.8'],
                             serveStale=True, serveExpiredTTL=3600,
                             disableCache=False, enableParallelQuery=True)
        self.p['outbounds'][0]['tag'] = 'internet'
        self.p['outbounds'][1]['tag'] = 'block'
        self.p['routing'] = {'domainStrategy': 'AsIs', 'rules': [
            self.p['routing']['rules'][0],
            {'type': 'field', 'protocol': ['bittorrent'], 'outboundTag': 'block'},
            {'type': 'field', 'domain': ['geosite:private'], 'outboundTag': 'block'},
            {'type': 'field', 'ip': ['geoip:private'], 'outboundTag': 'block'},
            {'type': 'field', 'domain': [r'regexp:.*\.ru$'], 'outboundTag': 'internet'},
            {'type': 'field', 'ip': ['geoip:ru'], 'outboundTag': 'internet'}]}
        before = copy.deepcopy(self.p)
        self.assertTrue(self.h.validate_profile(self.p, self.c))
        self.assertEqual(self.p, before)

    def test_service_api_outbound_is_not_required_in_normal_array(self):
        self.api()
        self.assertNotIn('REMNAWAVE_API', [x['tag'] for x in self.p['outbounds']])
        self.assertTrue(self.h.validate_profile(self.p, self.c))

    def test_service_api_loopback_and_legacy_protocol(self):
        self.api('127.0.0.1')
        self.p['inbounds'][0].update(protocol='dokodemo-door', port=61000)
        self.assertTrue(self.h.validate_profile(self.p, self.c))

    def test_service_api_requires_declaration(self):
        self.api()
        self.p.pop('api')
        self.reject('PROFILE_SERVICE_API_REQUIRES_VALID_API_TAG')

    def test_service_api_must_not_be_public(self):
        self.api('0.0.0.0')
        self.reject('PROFILE_UNREVIEWED_EXTRA_INBOUND')

    def test_service_api_direct_listen_requires_manual_review(self):
        self.api()
        self.p['api']['listen'] = '0.0.0.0:61000'
        self.reject('PROFILE_SERVICE_API_REQUIRES_ONE_LOCAL_INBOUND')

    def test_service_api_route_cannot_accept_vpn_users(self):
        self.api()
        self.p['routing']['rules'][0]['inboundTag'] = [self.i['tag']]
        self.reject('PROFILE_SERVICE_API_ROUTE_MUST_BE_LOCAL_ONLY')

    def test_service_api_route_must_precede_general_routing(self):
        self.api()
        self.p['routing']['rules'].reverse()
        self.reject('PROFILE_SERVICE_API_ROUTE_MISSING_OR_NOT_FIRST')

    def test_service_api_must_not_collide_with_real_outbound(self):
        self.api()
        self.p['outbounds'][0]['tag'] = 'REMNAWAVE_API'
        self.reject('PROFILE_OUTBOUND_TAGS_INVALID_OR_DUPLICATE')

    def test_second_user_inbound_still_refused(self):
        self.api()
        self.p['inbounds'].append(copy.deepcopy(self.i))
        self.reject('PROFILE_REQUIRES_ONE_VLESS_INBOUND')

    def test_audit_is_read_only_and_does_not_print_secret_values(self):
        self.api()
        path = self.root / 'profile.json'
        path.write_text(json.dumps(self.p))
        before = path.read_bytes()
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            self.h.audit_profile(path, self.c)
        output = stream.getvalue()
        self.assertIn('PROFILE_IPV4_ROUTING_STRUCTURE=PASS', output)
        self.assertIn('EGRESS_ENFORCEMENT=NOT_VERIFIED', output)
        self.assertIn('LIVE_NODE_AND_HOST_OVERRIDES=NOT_VERIFIED', output)
        self.assertNotIn(self.r['privateKey'], output)
        self.assertNotIn(self.r['shortIds'][0], output)
        self.assertNotIn('@xtls-api-', output)
        self.assertEqual(path.read_bytes(), before)

    def test_duplicate_json_fields_and_nan_fail_without_details(self):
        path = self.root / 'bad.json'
        for text in ('{"secret":"SENSITIVE","secret":"SENSITIVE"}',
                     '{"dns":{"queryStrategy":"UseIPv6","queryStrategy":"UseIPv4"}}',
                     '{"log":{"value":NaN}}', '{"value":Infinity}',
                     '{"privateKey":BROKEN_SECRET}'):
            with self.subTest(text=text):
                path.write_text(text)
                with self.assertRaises(self.h.Failure) as exc:
                    self.h.audit_profile(path, self.c)
                self.assertNotIn('SENSITIVE', str(exc.exception))
                self.assertNotIn('BROKEN_SECRET', str(exc.exception))

    def test_audit_rejects_symlink_fifo_directory_and_oversize(self):
        path = self.root / 'bad'
        target = self.root / 'target'
        target.write_text(json.dumps(self.p))
        path.symlink_to(target)
        with self.assertRaises(self.h.Failure):
            self.h.audit_profile(path, self.c)
        self.assertTrue(path.is_symlink())
        path.unlink()
        os.mkfifo(path, 0o600)
        with self.assertRaises(self.h.Failure):
            self.h.audit_profile(path, self.c)
        path.unlink()
        path.mkdir()
        with self.assertRaises(self.h.Failure):
            self.h.audit_profile(path, self.c)
        path.rmdir()
        path.write_bytes(b' ' * (2 * 1024 * 1024 + 1))
        with self.assertRaisesRegex(self.h.Failure, 'PROFILE_TOO_LARGE'):
            self.h.audit_profile(path, self.c)


class AcceptanceGate213Tests(unittest.TestCase):
    def gate(self, version, helper_rc=0):
        text = payload('VK_PAYLOAD_VK_WRITE_ACCEPTANCE')
        start = text.index('installed_contract_class() {')
        end = text.index('\nif [[ "$INSTALLED_CONTRACT_CLASS" == modern ]]; then\n    if KERNEL_PLUGIN_STATUS=', start)
        snippet = text[start:end]
        with tempfile.TemporaryDirectory(prefix='vk-gate-213-') as tmp:
            if version is not None:
                (Path(tmp) / 'install-version').write_text(version + '\n')
            prelude = '''set -uo pipefail
STATE=$1
ETC=$STATE
F=0
helper() { printf 'HELPER_CALLED=%s\\n' "$*"; return ''' + str(helper_rc) + '''; }
pass() { printf 'PASS %s\\n' "$1"; }
fail() { printf 'FAIL %s\\n' "$1"; F=1; }
warn() { printf 'NOTE %s %s\\n' "$1" "$2"; }
'''
            return subprocess.run(['bash', '-c', prelude + snippet + '\nexit "$F"', '_', tmp],
                                  capture_output=True, text=True, timeout=5)

    def test_all_reviewed_versions_execute_expected_profile_contract(self):
        validated = ('2.1.0', '2.1.1', '2.1.2', '2.1.3', '2.2.0',
                     '2.3.0', '2.4.0', '2.4.1', '2.4.2', '2.4.3', '2.5.0', '2.5.1', '2.5.2', '2.5.3', '2.5.4', '2.5.5', '2.5.6')
        for version in validated:
            with self.subTest(version=version):
                result = self.gate(version)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('HELPER_CALLED=profile-check', result.stdout)
                self.assertIn('PASS IMPORT_PROFILE_POLICY', result.stdout)
                if version.startswith(('2.3.', '2.4.', '2.5.')):
                    self.assertIn('PASS INSTALLER_CONTRACT_MODERN', result.stdout)
                else:
                    self.assertIn('PASS INSTALLER_CONTRACT_LEGACY', result.stdout)

    def test_helper_failure_not_masked(self):
        result = self.gate('2.5.2', 1)
        self.assertEqual(result.returncode, 1)
        self.assertIn('FAIL IMPORT_PROFILE_POLICY', result.stdout)
        self.assertNotIn('PASS IMPORT_PROFILE_POLICY', result.stdout)

    def test_future_malformed_versions_do_not_silently_pass(self):
        for version in ('2.1.4', '2.1.20', '2.1.3-extra', '2.2.1', '2.3.1',
                        '2.4.4', '2.5.7', '2.6.0', '3.0.0', 'broken', ''):
            with self.subTest(version=version):
                result = self.gate(version)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertNotIn('HELPER_CALLED=', result.stdout)
                self.assertIn('FAIL INSTALLER_CONTRACT', result.stdout)
                self.assertIn('FAIL IMPORT_PROFILE_POLICY', result.stdout)

    def test_missing_install_version_is_fail_closed(self):
        result = self.gate(None)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('FAIL INSTALLER_CONTRACT', result.stdout)
        self.assertIn('FAIL IMPORT_PROFILE_POLICY', result.stdout)

    def test_historical_legacy_is_explicitly_not_verified(self):
        for version in ('2.0.3', '1.3.0'):
            with self.subTest(version=version):
                result = self.gate(version)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn('HELPER_CALLED=', result.stdout)
                self.assertIn('NOTE IMPORT_PROFILE_POLICY NOT_VERIFIED', result.stdout)

    def test_maintenance_and_cover_keep_all_previous_supported_versions(self):
        maintenance = payload('VK_PAYLOAD_VK_WRITE_MAINTENANCE')
        site = payload('VK_SITE_TOOL_PY')
        for version in ('2.1.0', '2.1.1', '2.1.2', '2.1.3', '2.2.0', '2.3.0',
                        '2.4.0', '2.4.1', '2.4.2', '2.4.3', '2.5.0', '2.5.1', '2.5.2'):
            self.assertIn("'version=" + version + "'", maintenance)
            self.assertIn("'" + version + "'", site)


if __name__ == '__main__':
    unittest.main()
