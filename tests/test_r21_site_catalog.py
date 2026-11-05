"""R21: 96 new thematic sites, deterministic source, checked staging deployment."""
from html.parser import HTMLParser
from html import escape
from pathlib import Path
import hashlib
import json
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
import urllib.error
import shutil

from common import ROOT
sys.path.insert(0, str(ROOT/'scripts'))
import site_catalog as cat
import cover_variants as original
import cover_rich as rich
import site_audit as audit
import staging_web_deploy as deploy
import test_r20_rich_site as r20


class Catalog(unittest.TestCase):
    DOMAIN='review.example.test'

    def test_108_unique_topics_16_distinct_visual_families(self):
        self.assertEqual(len(original.NAMES),12)
        self.assertEqual(len(cat.BASE_NAMES),96)
        self.assertEqual(len(cat.NAMES),108)
        self.assertEqual(len(set(original.NAMES+cat.NAMES)),120)
        self.assertGreaterEqual(len(set(x.layout for x in cat.THEMES.values())),28)
        self.assertEqual(len(set(x.category for x in cat.THEMES.values())),len(set(x.category for x in cat.THEMES.values())))
        self.assertEqual({x.name for x in (ROOT/'site-catalog').iterdir() if x.is_dir()},set(cat.NAMES))
        self.assertEqual({x.name for x in (ROOT/'cover-variants').iterdir() if x.is_dir()},set(original.NAMES))

    def test_every_site_is_independent_five_page_bundle_and_exact_source(self):
        homes=set();csses=set();icons=set()
        for name in cat.NAMES:
            with self.subTest(name=name):
                spec=cat.THEMES[name]
                bundle=cat.render(name,self.DOMAIN)
                self.assertEqual(len(bundle),9)
                self.assertEqual(audit.audit_bundle(bundle,self.DOMAIN,rich=True)['pages'],5)
                self.assertEqual(bundle,rich.render_rich(name,self.DOMAIN))
                for filename in bundle:
                    p=ROOT/'site-catalog'/name/filename
                    self.assertTrue(p.is_file(),str(p))
                    self.assertEqual(p.read_bytes(),cat.render(name,'preview.example.test')[filename])
                html=bundle['index.html'].decode()
                self.assertIn('lang="'+spec.language+'"',html)
                self.assertIn(escape(spec.title),html)
                for topic in spec.subjects:self.assertIn(topic,html)
                self.assertIn('layout-'+spec.layout,html)
                self.assertNotIn('<script',html.lower())
                self.assertNotIn('src="http',html.lower())
                homes.add(hashlib.sha256(bundle['index.html']).digest())
                csses.add(hashlib.sha256(bundle['style.css']).digest())
                icons.add(hashlib.sha256(bundle['favicon.svg']).digest())
        self.assertEqual(len(homes),len(cat.NAMES))
        self.assertEqual(len(csses),len(cat.NAMES))
        self.assertEqual(len(icons),len(cat.NAMES))

    def test_domain_consistency_and_invalid_domain(self):
        for name in cat.NAMES:
            content=cat.render(name,'one.example.test')
            other=cat.render(name,'two.example.test')
            self.assertNotEqual(content['robots.txt'],other['robots.txt'])
            self.assertIn(b'https://one.example.test/',content['sitemap.xml'])
            self.assertNotIn(b'https://two.example.test/',content['sitemap.xml'])
        for bad in ('', 'x', 'https://my.example.com','../example.com','test.local/../.env',
                    'site.example.com\nInjected','1.2.3.4','xn--example--.com'):
            with self.subTest(value=bad),self.assertRaises(ValueError):
                cat.render(cat.NAMES[0],bad)
        with self.assertRaises(ValueError):
            cat.render('../etc',self.DOMAIN)

    def test_all_new_templates_fail_audit_on_bad_links_and_script(self):
        data=cat.render(cat.NAMES[0],self.DOMAIN)
        broken=dict(data);broken['journal.html']=broken['journal.html'].replace(
            b'href="about.html"',b'href="admin.html"')
        with self.assertRaisesRegex(ValueError,'BROKEN_REFERENCE'):
            audit.audit_bundle(broken,self.DOMAIN,rich=True)
        tampered=dict(data);tampered['index.html']+=b'<script src="/evil.js"></script>'
        with self.assertRaisesRegex(ValueError,'UNSAFE_HTML'):
            audit.audit_bundle(tampered,self.DOMAIN,rich=True)
        tampered=dict(data);tampered['style.css']+=b'@import "https://remote";'
        with self.assertRaisesRegex(ValueError,'REMOTE_OR_EXECUTABLE_CSS'):
            audit.audit_bundle(tampered,self.DOMAIN,rich=True)

    def test_catalog_and_offline_preview_cli_without_root_side_effects(self):
        cmd=[sys.executable,str(ROOT/'scripts/staging_web_deploy.py')]
        listed=subprocess.run(cmd+['site-catalog'],capture_output=True,text=True,timeout=10)
        self.assertEqual(listed.returncode,0,listed.stderr)
        self.assertEqual(len(listed.stdout.splitlines()),120)
        self.assertIn('108-volunteer-journal',listed.stdout)
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp)/'generated'
            run=subprocess.run(cmd+['site-preview','--theme','79-glass-workshop',
                            '--domain',self.DOMAIN,'--output',str(output)],capture_output=True,text=True,timeout=12)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertEqual(set(x.name for x in output.iterdir()),set(cat.render('79-glass-workshop',self.DOMAIN)))
            again=subprocess.run(cmd+['site-preview','--theme','79-glass-workshop',
                            '--domain',self.DOMAIN,'--output',str(output)],capture_output=True,text=True,timeout=12)
            self.assertNotEqual(again.returncode,0)
            self.assertIn('PREVIEW_DESTINATION_EXISTS',again.stderr)
            self.assertEqual(output.joinpath('index.html').read_bytes(),cat.render('79-glass-workshop',self.DOMAIN)['index.html'])

    def make_app(self,temp,failed=None):
        fixture=r20.RichCover()
        root=Path(temp)
        site, originals, nginx=fixture.setup_fixture(root)
        return deploy.NodeWeb(root,run=fixture.runner(site,fail=failed),css_check=lambda *args:None),site,originals,nginx

    def test_new_catalog_is_transactional_with_full_rollback(self):
        with tempfile.TemporaryDirectory() as t:
            app,site,originals,conf=self.make_app(t)
            with self.assertRaisesRegex(deploy.DeployError,'CATALOG_REQUIRES_RICH_PAGES'):
                app.site_install('79-glass-workshop','site.example.test')
            self.assertIsNone(app.receipt('site'))
            result=app.site_install('79-glass-workshop','site.example.test',rich_pages=True)
            self.assertIn('RICH_PAGES=VERIFIED',result)
            self.assertEqual(app.receipt('site')['metadata']['theme'],'79-glass-workshop')
            self.assertIn(deploy.RICH_MARKER,app.webconf.read_bytes())
            self.assertIn('Прозрачная форма'.encode(),(site/'index.html').read_bytes())
            self.assertIn(b'/assets/style-', (site/'about.html').read_bytes())
            self.assertEqual(app.site_rollback(),'SITE_ROLLBACK=PASS')
            self.assertEqual(app.webconf.read_bytes(),conf)
            for name,bytes_ in originals.items():self.assertEqual((site/name).read_bytes(),bytes_)
            for filename in ('journal.html','about.html','questions.html','sitemap.xml'):
                self.assertFalse((site/filename).exists())

    def test_failed_new_site_publish_does_not_leave_public_files(self):
        with tempfile.TemporaryDirectory() as t:
            app,site,originals,conf=self.make_app(t,failed='questions.html')
            with self.assertRaisesRegex(deploy.DeployError,'RICH_LIVE_ROUTE_NOT_VERIFIED'):
                app.site_install('86-herbal-tea','site.example.test',rich_pages=True)
            self.assertEqual(app.receipt('site')['stage'],'rolled_back')
            self.assertEqual(app.webconf.read_bytes(),conf)
            for name,bytes_ in originals.items():self.assertEqual((site/name).read_bytes(),bytes_)
            self.assertFalse((site/'journal.html').exists())

    def test_new_site_nginx_real_local_routes_and_denies_unknown(self):
        if not shutil.which('nginx'):self.skipTest('nginx not available')
        with tempfile.TemporaryDirectory(prefix='vk-catalog-r21-') as t:
            root=Path(t);root.chmod(0o755)
            site=root/'site';site.mkdir(mode=0o755)
            assets=site/'assets';assets.mkdir(mode=0o755)
            b=cat.render('13-cloud-ledger',self.DOMAIN)
            css_name=deploy.NodeWeb.css_name(b['style.css'])
            (site/css_name).write_bytes(b['style.css'])
            for name, content in b.items():
                if name=='style.css':continue
                if name.endswith('.html'):
                    content=content.replace(b'href="style.css"',b'href="/'+css_name.encode()+b'"')
                    content=content.replace(b'href="/style.css"',b'href="/'+css_name.encode()+b'"')
                (site/name).write_bytes(content)
            with socket.socket() as sock:
                sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
            conf=root/'nginx.conf'
            conf.write_text('worker_processes 1;\npid '+str(root/'nginx.pid')+';\n'
              'error_log '+str(root/'error.log')+' warn;\n'
              'events { worker_connections 64; }\nhttp { include /etc/nginx/mime.types; server { '
              'listen 127.0.0.1:'+str(port)+'; server_name '+self.DOMAIN+'; root '+str(site)+'; access_log off; '
              'location = / { try_files /index.html =404; } '
              'location = /index.html { try_files $uri =404; } '
              'location = /robots.txt { try_files $uri =404; } '
              'location = /favicon.svg { try_files $uri =404; } '
              +deploy.RICH_LOCATIONS.decode() +
              'location = /404.html { internal; try_files $uri =404; } '
              'location ~ "^/assets/style-[0-9a-f]{20}[.]css$" { try_files $uri =404; } '
              'error_page 404 /404.html; location / { return 404; } } }\n')
            v=subprocess.run(['nginx','-t','-c',str(conf)],capture_output=True,text=True,timeout=8)
            self.assertEqual(v.returncode,0,v.stderr)
            proc=subprocess.Popen(['nginx','-c',str(conf),'-g','daemon off;'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                def get(path):
                    request=urllib.request.Request('http://127.0.0.1:'+str(port)+path,headers={'Host':self.DOMAIN})
                    try:
                        with urllib.request.urlopen(request,timeout=3) as response:
                            return response.status,response.read(),response.headers
                    except urllib.error.HTTPError as err:
                        return err.code,err.read(),err.headers
                for _ in range(40):
                    try:get('/');break
                    except OSError:time.sleep(.05)
                for fn in ('','journal.html','about.html','questions.html','robots.txt','sitemap.xml',css_name,'favicon.svg'):
                    code,payload,headers=get('/'+fn)
                    self.assertEqual(code,200,fn)
                    self.assertTrue(payload,fn)
                self.assertIn('xml',get('/sitemap.xml')[2].get('Content-Type',''))
                for forbidden in ('/.env','/.git/config','/admin','/backup.zip','/nonexistent','/style.css'):
                    self.assertEqual(get(forbidden)[0],404,forbidden)
            finally:
                proc.terminate()
                try:proc.wait(timeout=3)
                except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=3)


if __name__=='__main__':unittest.main()
