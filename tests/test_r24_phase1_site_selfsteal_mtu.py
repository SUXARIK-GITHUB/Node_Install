"""R24 phase 1: site manager, safe first-install choice, selfsteal and MTU.

All test fixtures are local. Never execute the installer, systemctl, sysctl,
network changes, public scanners, or a remote VPN connection.
"""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from common import ROOT
sys.path[:0] = [str(ROOT/'scripts'),str(ROOT/'integrations')]
import site_manager
import staging_web_deploy
import selfsteal_chain
import path_mtu_diagnostics as pathmtu
import test_r20_rich_site as oldfixture


class SiteManager(unittest.TestCase):
    def test_catalog_contains_120_distinct_theme_ids(self):
        self.assertEqual(len(site_manager.THEMES),120)
        self.assertEqual(len(set(site_manager.THEMES)),120)
        out=subprocess.run(['bash',str(ROOT/'install.sh'),'--site-manager','list'],
                           text=True,capture_output=True,timeout=16)
        self.assertEqual(out.returncode,0,out.stderr)
        self.assertEqual(len(out.stdout.splitlines()),120)
        self.assertIn('111-atlas-docs',out.stdout)

    def test_preview_is_direct_and_does_not_modify_node(self):
        with tempfile.TemporaryDirectory() as td:
            dest=Path(td)/'preview'
            args=site_manager.translated('preview',theme='116-vinyl-room',output=str(dest))
            self.assertEqual(args[0],'site-preview')
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(site_manager.main(['preview','--theme','116-vinyl-room',
                                                   '--output',str(dest)]),0)
            self.assertTrue((dest/'questions.html').is_file())
            self.assertTrue((dest/'index.html').is_file())
            self.assertEqual(len(list(dest.iterdir())),9)

    def test_mutations_require_explicit_confirmation_and_known_theme(self):
        for a in ('deploy','change','rollback'):
            with self.subTest(action=a),self.assertRaises(SystemExit) as result:
                site_manager.main([a])
            self.assertEqual(result.exception.code,2)
        with self.assertRaises(ValueError):
            site_manager.translated('deploy',theme='../etc/passwd',domain='node.example.test',confirm=True)
        actual=site_manager.translated('deploy',theme='111-atlas-docs',
                        domain='node.example.test',confirm=True)
        self.assertEqual(actual[0],'site-deploy')
        self.assertIn('--rich-pages',actual)
        self.assertIn('--confirm-staging',actual)
        change=site_manager.translated('change',theme='116-vinyl-room',
                        domain='node.example.test',confirm=True)
        self.assertEqual(change[0],'site-change')
        self.assertNotIn('--rich-pages',change)

    def test_staging_manager_uses_existing_transactional_engine(self):
        with tempfile.TemporaryDirectory() as td:
            f=oldfixture.RichCover();site,old,conf=f.setup_fixture(Path(td))
            app=staging_web_deploy.NodeWeb(Path(td),run=f.runner(site),css_check=lambda *_:None)
            out=app.site_install('111-atlas-docs','site.example.test',rich_pages=True)
            self.assertIn('SITE_DEPLOY=PASS',out)
            self.assertEqual(app.receipt('site')['metadata']['theme'],'111-atlas-docs')
            app.site_install('116-vinyl-room','site.example.test',rich_pages=True,switch=True)
            self.assertEqual(app.receipt('site')['metadata']['theme'],'116-vinyl-room')
            self.assertEqual(app.site_rollback(),'SITE_CHANGE_ROLLBACK=PASS PREVIOUS_THEME_RESTORED')
            self.assertEqual(app.receipt('site')['metadata']['theme'],'111-atlas-docs')
            self.assertEqual(app.site_rollback(),'SITE_ROLLBACK=PASS')
            self.assertEqual(app.webconf.read_bytes(),conf)
            for filename,payload in old.items():
                self.assertEqual((site/filename).read_bytes(),payload)

    def test_menu_rejects_bad_confirmation_without_changing_host(self):
        class FakeNode:
            def ready(self):return {'domain':'node.example.test'}
            def receipt(self,_):return None
        fakeinput=iter(['3','111-atlas-docs','STAGING','wrong.example.test','0'])
        out=[]
        with patch.object(site_manager,'NodeWeb',return_value=FakeNode()), \
             patch.object(site_manager,'deploy_main') as deploy:
            self.assertEqual(site_manager.menu(input_fn=lambda _:next(fakeinput),output_fn=out.append),0)
            deploy.assert_not_called()
        self.assertTrue(any('Домен не совпадает' in s for s in out))

    def test_installer_first_install_site_is_opt_in_no_password_policy_change(self):
        source=(ROOT/'install.sh').read_text()
        self.assertIn('--site-theme)',source)
        self.assertIn('VK_INITIAL_SITE_THEME',source)
        self.assertIn('scripts/staging_web_deploy.py',source)
        self.assertIn('scripts/verify_release.py',source)
        self.assertIn('--rich-pages --confirm-staging',source)
        self.assertIn('AUTO_REBOOT=DISABLED_AFTER_OPTIONAL_SITE_FAILURE',source)
        self.assertIn('if [[ $VK_CASCADE_ACTIVE -eq 1 && -n "$VK_INITIAL_SITE_THEME" ]]',source)
        self.assertIn('PubkeyAuthentication no',source)
        self.assertIn('PasswordAuthentication yes',source)
        version=subprocess.run(['bash',str(ROOT/'install.sh'),'--version'],
                    capture_output=True,text=True,timeout=5)
        self.assertEqual(version.returncode,0)
        self.assertEqual(version.stdout.strip(),'2.5.18')


class ReadOnlySelfsteal(unittest.TestCase):
    def test_local_pipeline_returns_only_aggregated_pass(self):
        private='SUPER_SECRET_VALUE_NEVER_PRINT'
        conf=json.dumps({'domain':'site.example.test','secret':private}).encode()
        valid={'status':'STATIC_CHECKS_OK','mode':'local','observations':[]}
        def tls(domain,socket,**kwargs):
            self.assertEqual(domain,'site.example.test')
            self.assertTrue(kwargs['proxy_v1'])
            return {'status':'PASS','tls_version':'TLSv1.3','alpn':'http/1.1','http_code':200}
        with tempfile.TemporaryDirectory() as td:
            with patch.object(selfsteal_chain,'static_snapshot',return_value=valid), \
                 patch.object(selfsteal_chain,'regular_bytes',return_value=conf):
                result=selfsteal_chain.verify(Path(td),tls_probe=tls)
                self.assertEqual(result['status'],'PASS')
                self.assertEqual(result['checks']['local_unix_tls_https'],'PASS')
                self.assertNotIn(private,json.dumps(result))
                self.assertNotIn('site.example.test',json.dumps(result))
                reviewed=selfsteal_chain.verify(Path(td),tls_probe=lambda *a,**k:{'status':'REVIEW'})
                self.assertEqual(reviewed['status'],'REVIEW')

    def test_uninstalled_node_does_not_report_success(self):
        with tempfile.TemporaryDirectory() as td:
            result=selfsteal_chain.verify(Path(td))
            self.assertEqual(result['status'],'REVIEW')
            self.assertEqual(result['actions_performed'],'NONE')
            self.assertEqual(result['checks']['local_unix_tls_https'],'NOT_CHECKED')
        p=subprocess.run(['bash',str(ROOT/'install.sh'),'--selfsteal-verify'],
                         capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(p.stdout)['status'],'REVIEW')


class PathMTU(unittest.TestCase):
    def test_ipv4_target_validation_and_no_implicit_probes(self):
        for ip in ('localhost','2001:db8::1','0.0.0.0','224.0.0.1','127.0.0.1'):
            with self.subTest(target=ip),self.assertRaises(pathmtu.DiagnosticError):
                pathmtu.validate_target(ip)
        self.assertEqual(pathmtu.validate_target('127.0.0.1',True),'127.0.0.1')
        self.assertEqual(pathmtu.validate_target('1.1.1.1'),'1.1.1.1')

    def test_route_and_icmp_are_bounded_and_redacted(self):
        calls=[]
        def fake(argv,timeout=5):
            calls.append(argv)
            if argv[:4]==['ip','-4','-j','route']:
                return json.dumps([{'dev':'eth0','gateway':'198.51.100.12','prefsrc':'203.0.113.11'}])
            if argv[:4]==['ip','-j','link','show']:
                return json.dumps([{'ifname':'eth0','mtu':1500,'address':'de:ad:be:ef:01:02'}])
            if argv[0]=='ping':
                return 'PING OK' if int(argv[-2])<1472 else None
            raise AssertionError(argv)
        out=pathmtu.inspect('1.1.1.1',run=fake)
        self.assertFalse(out['probe_sent'])
        self.assertEqual(len(calls),2)
        self.assertEqual(out['interface_mtu'],1500)
        self.assertNotIn('198.51.100',json.dumps(out))
        self.assertNotIn('1.1.1.1',json.dumps(out))
        out=pathmtu.inspect('1.1.1.1',probe=True,run=fake)
        self.assertEqual(len([c for c in calls if c[0]=='ping']),4)
        self.assertEqual(out['probe_status'],'INCONCLUSIVE')
        self.assertEqual(out['status'],'REVIEW')
        self.assertEqual(out['system_changes'],'NONE')

    def test_rejects_ambiguous_route_or_malformed_mtu(self):
        self.assertIsNone(pathmtu.parse_route('[{},{}]'))
        self.assertIsNone(pathmtu.parse_route('[{"dev":"../bad"}]'))
        self.assertIsNone(pathmtu.parse_route('[{"dev":"eth0","mtu":0}]'))
        self.assertIsNone(pathmtu.parse_link('[{"ifname":"eth0","mtu":true}]','eth0'))
        self.assertEqual(pathmtu.parse_link('[{"ifname":"lo","mtu":65536}]','lo'),65536)
        status=subprocess.run(['bash',str(ROOT/'install.sh'),'--path-mtu','--target','127.0.0.1'],
                              capture_output=True,text=True,timeout=10)
        self.assertEqual(status.returncode,2)
        self.assertEqual(json.loads(status.stdout)['status'],'STOP')


if __name__ == '__main__':unittest.main()
