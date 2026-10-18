"""R7 site and local TCP deployment; fake root, no host/service writes."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from common import ROOT
sys.path.insert(0,str(ROOT/'scripts'))
import staging_web_deploy as deploy


class DeployerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        for name in ('var/lib/vkarmani-node', 'etc/vkarmani-node',
                     'var/www/vkarmani-node/site/assets', 'etc/nginx/conf.d','etc/nginx'):
            (self.root/name).mkdir(parents=True,exist_ok=True)
        state=self.root/'var/lib/vkarmani-node'
        (state/'owned-installation').touch()  # installer creates a zero-byte marker
        (state/'install-version').write_text('2.5.11\n')
        (state/'INSTALL_COMPLETE').write_text('version=2.5.11\n')
        (self.root/'etc/vkarmani-node/config.json').write_text(json.dumps({
            'installation_mode':'secret-key-only','domain':'entry.example.com',
            'public_ipv4':'8.8.8.8'}))
        self.old=b'<!doctype html>old site'
        site=self.root/'var/www/vkarmani-node/site'
        (site/'index.html').write_bytes(self.old)
        self.original_conf=b'''server {
 listen unix:/run/vkarmani-selfsteal/nginx.sock ssl proxy_protocol;
 root /var/www/vkarmani-node/site;
    location = /index.html { try_files $uri =404; }
    location ~ "^/assets/(style-[0-9a-f]{20}[.]css|icon-[0-9a-f]{20}[.]svg)$" { try_files $uri =404; }
}
'''
        (self.root/'etc/nginx/conf.d/20-vkarmani-selfsteal.conf').write_bytes(self.original_conf)
        self.original_nginx=b'worker_processes auto;\nevents { worker_connections 2048; }\nhttp { include conf.d/*.conf; }\n'
        (self.root/'etc/nginx/nginx.conf').write_bytes(self.original_nginx)
        self.calls=[]
        self.app=deploy.NodeWeb(self.root,run=lambda argv:self.calls.append(argv),
                                css_check=self.check_css)
        self.css_urls=[]

    def check_css(self, config, css, css_name):
        self.assertGreater(len(css),0)
        self.css_urls.append(css_name)

    def test_all_twelve_sites_install_and_rollback_preserve_original(self):
        for name in deploy.NAMES:
            with self.subTest(name=name):
                a=self.app.site_install(name,'entry.example.com')
                self.assertIn('SITE_DEPLOY=PASS',a)
                site=self.app.site
                css=deploy.render(name,'entry.example.com')['style.css']
                css_name=deploy.NodeWeb.css_name(css)
                html=(site/'index.html').read_bytes()
                self.assertIn(('href="/'+css_name+'"').encode(),html)
                self.assertNotIn(b'href="style.css"',html)
                self.assertEqual((site/css_name).read_bytes(),css)
                self.assertIn(b'href=\"/assets/style-', (site/'404.html').read_bytes())
                self.assertIn(b'<svg', (site/'favicon.svg').read_bytes())
                self.assertFalse((site/'style.css').exists())
                self.assertEqual(self.css_urls[-1],css_name)
                # Selfsteal Nginx must not be edited at all.
                self.assertEqual(self.app.webconf.read_bytes(),self.original_conf)
                self.assertIn('nginx',str(self.calls))
                self.assertEqual(self.app.site_rollback(),'SITE_ROLLBACK=PASS')
                self.assertEqual((site/'index.html').read_bytes(),self.old)
                self.assertFalse((site/css_name).exists())
                self.assertFalse((site/'404.html').exists())
                self.assertFalse((site/'favicon.svg').exists())
                self.assertEqual(self.app.webconf.read_bytes(),self.original_conf)
        self.assertEqual(self.app.status()['site'],'rolled_back')

    def test_deploy_and_rollback_preserve_original_modes(self):
        import stat
        index=self.app.site/'index.html'
        index.chmod(0o640)
        self.app.webconf.chmod(0o600)
        self.app.site_install(deploy.NAMES[0],'entry.example.com')
        self.assertEqual(stat.S_IMODE(index.stat().st_mode),0o640)
        self.assertEqual(stat.S_IMODE(self.app.webconf.stat().st_mode),0o600)
        self.app.site_rollback()
        self.assertEqual(stat.S_IMODE(index.stat().st_mode),0o640)
        self.assertEqual(stat.S_IMODE(self.app.webconf.stat().st_mode),0o600)
        self.app.mainconf.chmod(0o600)
        self.app.tcp_install(9200,9300,portcheck=False)
        self.assertEqual(stat.S_IMODE(self.app.mainconf.stat().st_mode),0o600)
        self.app.tcp_rollback()
        self.assertEqual(stat.S_IMODE(self.app.mainconf.stat().st_mode),0o600)

    def test_site_rejects_foreign_changes_and_symlinks(self):
        with self.assertRaisesRegex(deploy.DeployError,'DOMAIN_CONFIRMATION'):
            self.app.site_install(deploy.NAMES[0],'fake.example.com')
        self.app.site_install(deploy.NAMES[0],'entry.example.com')
        with self.assertRaisesRegex(deploy.DeployError,'PREVIOUS_DEPLOY'):
            self.app.site_install(deploy.NAMES[1],'entry.example.com')
        self.app.site.joinpath('index.html').write_text('external change')
        with self.assertRaisesRegex(deploy.DeployError,'THIRD_PARTY_CHANGE'):
            self.app.site_rollback()

    def test_corrupt_backup_refuses_rollback(self):
        self.app.site_install(deploy.NAMES[0],'entry.example.com')
        r=self.app.receipt('site')
        (self.app.journal/r['backup']/'index.before').write_text('different')
        with self.assertRaisesRegex(deploy.DeployError,'BACKUP_HASH'):
            self.app.site_rollback()

    def test_pending_recover_after_interrupted_publishing(self):
        # Inject an error after the new CSS and Nginx fragments are written.
        orig=deploy.atomic
        def break_on_index(path,data,root=deploy.ROOT,mode=0o644):
            if path==self.app.site/'index.html' and b'Atelier' in data:
                raise OSError('synthetic disk failure')
            return orig(path,data,root,mode)
        # Select theme index actually ASCII/L10n; fail based on deployed hash not content.
        def stop_on_index(path,data,root=deploy.ROOT,mode=0o644):
            if path==self.app.site/'index.html' and data!=self.old:
                raise OSError('synthetic write failure')
            return orig(path,data,root,mode)
        with patch.object(deploy,'atomic',side_effect=stop_on_index):
            with self.assertRaises(OSError):
                self.app.site_install(deploy.NAMES[0],'entry.example.com')
        self.assertEqual(self.app.site.joinpath('index.html').read_bytes(),self.old)
        self.assertFalse(self.app.site.joinpath('style.css').exists())
        self.assertEqual(self.app.webconf.read_bytes(),self.original_conf)
        self.assertEqual(self.app.status()['site'],'rolled_back')

    def test_refuse_foreign_pending_transactions_and_wrong_install(self):
        bad=self.app.state/'image-update-pending'
        bad.write_text('unfinished')
        with self.assertRaisesRegex(deploy.DeployError,'TRANSACTION_PENDING'):
            self.app.site_install(deploy.NAMES[0],'entry.example.com')
        bad.unlink()
        (self.app.state/'install-version').write_text('2.5.9')
        with self.assertRaisesRegex(deploy.DeployError,'UNSUPPORTED_STAGING'):
            self.app.tcp_install(9200,9300,portcheck=False)

    def test_empty_installer_ownership_marker_and_missing_marker(self):
        self.assertEqual((self.app.state/'owned-installation').stat().st_size,0)
        self.assertEqual(self.app.ready()['installation_mode'],'secret-key-only')
        marker=self.app.state/'owned-installation'
        marker.unlink()
        with self.assertRaisesRegex(deploy.DeployError,'REQUIRED_PATH_MISSING'):
            self.app.ready()
        marker.write_text('legacy-nonempty\n')
        self.assertEqual(self.app.ready()['installation_mode'],'secret-key-only')

    def test_tcp_fragment_top_level_no_443(self):
        out=self.app.tcp_install(9200,9300,portcheck=False)
        self.assertIn('PASS',out)
        main=self.app.mainconf.read_text()
        fragment=self.app.streamconf.read_text()
        self.assertIn('stream {',main)
        self.assertNotIn('stream {',fragment)
        self.assertIn('listen 127.0.0.1:9200;',fragment)
        self.assertIn('proxy_pass 127.0.0.1:9300;',fragment)
        self.assertNotIn('listen 443;',main+fragment)
        self.assertEqual(self.app.tcp_rollback(),'TCP_ROLLBACK=PASS')
        self.assertEqual(self.app.mainconf.read_bytes(),self.original_nginx)
        self.assertFalse(self.app.streamconf.exists())
        with self.assertRaisesRegex(deploy.DeployError,'NO_TCP_ROLLBACK'):
            self.app.tcp_rollback()

    def test_tcp_refuses_existing_stream_or_conf_change(self):
        self.app.mainconf.write_bytes(self.original_nginx+b'\nstream { server {} }\n')
        with self.assertRaisesRegex(deploy.DeployError,'EXISTING_OR_NONSTANDARD'):
            self.app.tcp_install(9200,9300,portcheck=False)
        self.app.mainconf.write_bytes(self.original_nginx)
        self.app.tcp_install(9200,9300,portcheck=False)
        self.app.mainconf.write_text('changed externally')
        with self.assertRaisesRegex(deploy.DeployError,'THIRD_PARTY_CHANGE'):
            self.app.tcp_rollback()

    def test_tcp_failed_nginx_test_auto_rollback(self):
        count={'n':0}
        def mock_run(args):
            if args==['nginx','-t']:
                count['n']+=1
                if count['n']==2:raise deploy.DeployError('NGINX_T_SYNTAX_FAIL')
        self.app.run=mock_run
        with self.assertRaisesRegex(deploy.DeployError,'NGINX_T_SYNTAX_FAIL'):
            self.app.tcp_install(9200,9300,portcheck=False)
        self.assertEqual(self.app.mainconf.read_bytes(),self.original_nginx)
        self.assertFalse(self.app.streamconf.exists())
        self.assertEqual(self.app.status()['tcp'],'rolled_back')

    def test_port_policy(self):
        for l,b in ((443,9300),(2222,9300),(9200,2222),(9200,9200),(80,9080)):
            with self.subTest(l=l,b=b),self.assertRaises((ValueError,deploy.DeployError)):
                self.app.tcp_install(l,b,portcheck=False)


if __name__=='__main__':unittest.main()
