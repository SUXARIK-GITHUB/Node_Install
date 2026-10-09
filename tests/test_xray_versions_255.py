"""2.5.5 read-only upstream Xray version checker and full example configs."""
import json
from pathlib import Path
import importlib.util
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from common import ROOT, SCRIPT, payload

SPEC = importlib.util.spec_from_file_location('vk_xray_versions_test', ROOT / 'integrations/xray_versions.py')
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)


class XrayVersionReportTests(unittest.TestCase):
    def test_embedded_is_verbatim_and_self_contained(self):
        self.assertEqual(payload('VK_XRAY_VERSIONS_PY'),
                         (ROOT / 'integrations/xray_versions.py').read_text().rstrip('\n') + '\n')
        self.assertIn('--xray-versions) shift; vkarmani_xray_versions_main', SCRIPT)
        self.assertIn('XRAY_UPDATE_ACTION=NONE', payload('VK_XRAY_VERSIONS_PY'))
        self.assertNotIn('docker cp', payload('VK_XRAY_VERSIONS_PY'))
        self.assertNotIn('docker restart', payload('VK_XRAY_VERSIONS_PY'))
        self.assertNotIn('docker compose', payload('VK_XRAY_VERSIONS_PY'))

    def test_offline_cli_is_inert_without_docker_or_network(self):
        result = subprocess.run(['bash', str(ROOT / 'install.sh'), '--xray-versions', '--offline'],
                                capture_output=True, text=True, timeout=12)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('XRAY_UPSTREAM=NOT_QUERIED_OFFLINE', result.stdout)
        self.assertIn('XRAY_UPDATE_ACTION=NONE', result.stdout)
        self.assertNotIn('SECRET_KEY', result.stdout)
        result = subprocess.run(['bash', str(ROOT / 'install.sh'), '--xray-versions', '--change-core'],
                                capture_output=True, text=True, timeout=12)
        self.assertEqual(result.returncode, 2)

    def test_version_and_tag_validation(self):
        self.assertEqual(check.parse_version('v26.9.30'), (26,9,30))
        self.assertEqual(check.parse_version('26.3.27'), (26,3,27))
        for v in ('v99', 'v26.09.30', 'v26.9.30-alpha', '../../evil', 'v1000.9.9', 1, None):
            with self.subTest(v=v):
                self.assertIsNone(check.parse_version(v))

    def test_feed_parsing_sorts_versions_not_only_dates(self):
        items = [{'tag_name':'v26.7.28','prerelease':True,'draft':False},
                 {'tag_name':'v26.9.30','prerelease':True,'draft':False},
                 {'tag_name':'v26.9.99','prerelease':False,'draft':True},
                 {'tag_name':'untrusted','prerelease':False,'draft':False}]
        stable = {'tag_name':'v26.3.27','prerelease':False,'draft':False}
        got = check.get_upstream(lambda url: items if url == check.FEED else stable)
        self.assertEqual(got, (((26,9,30),True),(26,3,27)))

    def test_fails_closed_on_invalid_release(self):
        with self.assertRaises(check.UpstreamError):
            check.get_upstream(lambda url: [] if url == check.FEED else {})
        with self.assertRaises(check.UpstreamError):
            check.load_metadata('https://example.com/fake')

    def test_read_only_installed_probe(self):
        import subprocess as sp
        good = lambda *args,**kwargs:sp.CompletedProcess(args[0],0,stdout='Xray 26.7.28 (Go)\n',stderr='')
        with patch.object(check.shutil,'which',return_value='/usr/bin/docker'):
            self.assertEqual(check.installed_version(runner=good),(26,7,28))
            invalid = lambda *args,**kwargs:sp.CompletedProcess(args[0],0,stdout='v26.9.30\n',stderr='')
            self.assertIsNone(check.installed_version(runner=invalid))
            bad = lambda *args,**kwargs:sp.CompletedProcess(args[0],1,stdout='',stderr='')
            self.assertIsNone(check.installed_version(runner=bad))

    def test_examples_are_complete_and_secret_free(self):
        examples={k:json.loads((ROOT / 'examples' / f'inbound-{k}-full.example.json').read_text())
                  for k in ('raw','xhttp')}
        for name, obj in examples.items():
            self.assertEqual(set(('log','dns','inbounds','outbounds','routing')) - set(obj),set())
            self.assertEqual(len(obj['inbounds']),1)
            node=obj['inbounds'][0]
            self.assertEqual(node['port'],443)
            self.assertEqual(node['listen'],'0.0.0.0')
            self.assertEqual(node['streamSettings']['security'],'reality')
            self.assertEqual(node['streamSettings']['realitySettings']['target'],'/dev/shm/nginx.sock')
            self.assertEqual(node['streamSettings']['realitySettings']['xver'],1)
            self.assertEqual(node['streamSettings']['realitySettings']['privateKey'],
                             'REPLACE_WITH_PRIVATE_KEY_FROM_NODE')
            self.assertNotIn('INSERT_SECRET_KEY',json.dumps(obj))
            self.assertEqual(node['sniffing']['routeOnly'],True)
            self.assertEqual(obj['dns']['queryStrategy'],'UseIPv4')
            self.assertEqual(obj['outbounds'][0]['settings']['domainStrategy'],'UseIPv4')
            # Extra documented rules precede the original CIDR block.
            route_ip_rules=[r for r in obj['routing']['rules'] if 'ip' in r]
            self.assertEqual(len(route_ip_rules), 1)
            ip_rules=route_ip_rules[0]['ip']
            self.assertIn('::/0',ip_rules)
            self.assertIn('geoip:private',ip_rules)
            self.assertEqual(len(ip_rules),len(set(ip_rules)), 'duplicate route CIDR')
            self.assertEqual(obj['routing']['rules'][0]['protocol'],['bittorrent'])
            self.assertEqual(obj['routing']['rules'][1]['domain'],['geosite:private'])
            self.assertTrue(obj['dns']['serveStale'])
            self.assertEqual(obj['dns']['serveExpiredTTL'],3600)
            self.assertTrue(obj['dns']['enableParallelQuery'])
            self.assertEqual(obj['dns']['servers'],['1.1.1.1','1.0.0.1','8.8.8.8'])
            self.assertEqual(obj['outbounds'][0]['settings']['finalRules'],
                             [{'ip':['geoip:private','::/0'],'action':'block'}])
        raw=examples['raw']['inbounds'][0]
        xhttp=examples['xhttp']['inbounds'][0]
        self.assertEqual(raw['tag'],xhttp['tag'])
        self.assertEqual(raw['streamSettings']['network'],'raw')
        self.assertEqual(raw['settings']['flow'],'xtls-rprx-vision')
        self.assertEqual(xhttp['streamSettings']['network'],'xhttp')
        self.assertEqual(xhttp['settings']['flow'],'')
        self.assertEqual(xhttp['streamSettings']['xhttpSettings']['mode'],'auto')
        self.assertEqual(xhttp['streamSettings']['xhttpSettings']['host'],'node.example.com')
        self.assertNotIn('xhttpSettings',raw['streamSettings'])
        self.assertEqual(examples['raw']['routing'],examples['xhttp']['routing'])

    def test_readme_copies_full_examples_verbatim(self):
        readme=(ROOT/'README.md').read_text()
        for k in ('raw','xhttp'):
            start=f'<!-- BEGIN {k.upper()} FULL EXAMPLE -->'
            end=f'<!-- END {k.upper()} FULL EXAMPLE -->'
            part=readme.split(start)[1].split(end)[0].strip()
            assert part.startswith('```json\n') and part.endswith('\n```')
            self.assertEqual(part[8:-4].strip(),(ROOT/'examples'/f'inbound-{k}-full.example.json').read_text().strip())
        self.assertIn('docs/history/README_2.5.4.md',readme)
        self.assertIn('docs/XRAY_CORE_UPDATES_2.5.5.md',readme)

if __name__ == '__main__':
    unittest.main()
