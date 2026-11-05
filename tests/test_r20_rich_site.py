"""R20 optional rich covers: offline contract and transactional staging rollback."""
import json
from pathlib import Path
import tempfile
import unittest
import sys

from common import ROOT
sys.path.insert(0, str(ROOT/'scripts'))
import cover_variants as cv
import cover_rich as cr
import site_audit as aud
import staging_web_deploy as web


class RichCover(unittest.TestCase):
    def test_all_twelve_domains_and_pages(self):
        for theme in cv.NAMES:
            with self.subTest(theme=theme):
                content=cr.render_rich(theme,'site.example.test')
                result=aud.audit_bundle(content,'site.example.test',rich=True)
                self.assertEqual(result['files'],9)
                self.assertEqual(result['pages'],5)
                self.assertEqual(content,cr.render_rich(theme,'site.example.test'))
                self.assertNotEqual(content['index.html'],cr.render_rich(theme,'other.example.test')['index.html'])
                self.assertIn(b'href="/journal.html"',content['index.html'])
                self.assertEqual(cv.render(theme,'site.example.test'),{k:v for k,v in cv.render(theme,'site.example.test').items()})
                for k,v in content.items():
                    if k.endswith('.html'):
                        self.assertNotIn(b'<script',v)
                        self.assertNotIn(b'<form',v)

    def test_rejects_broken_links_and_unexpected_files(self):
        content=cr.render_rich(cv.NAMES[0],'site.example.test')
        corrupt=dict(content);corrupt['index.html']=corrupt['index.html'].replace(b'/journal.html',b'/missing.html')
        with self.assertRaisesRegex(ValueError,'BROKEN_REFERENCE'):
            aud.audit_bundle(corrupt,'site.example.test',rich=True)
        corrupt=dict(content);corrupt['index.html']+=b'<script>alert(1)</script>'
        with self.assertRaisesRegex(ValueError,'UNSAFE_HTML'):
            aud.audit_bundle(corrupt,'site.example.test',rich=True)
        corrupt=dict(content);corrupt['robots.txt']=b'User-agent: *\nDisallow: /'
        with self.assertRaisesRegex(ValueError,'ROBOTS_SITEMAP'):
            aud.audit_bundle(corrupt,'site.example.test',rich=True)
        corrupt=dict(content);corrupt['.env']=b'secret'
        with self.assertRaisesRegex(ValueError,'INVALID_BUNDLE_FILESET'):
            aud.audit_bundle(corrupt,'site.example.test',rich=True)

    def setup_fixture(self, root):
        for name in ('var/lib/vkarmani-node','etc/vkarmani-node',
                     'var/www/vkarmani-node/site/assets','etc/nginx/conf.d'):
            (root/name).mkdir(parents=True,exist_ok=True)
        state=root/'var/lib/vkarmani-node'
        (state/'owned-installation').touch()
        (state/'install-version').write_text('2.5.18\n')
        (state/'INSTALL_COMPLETE').write_text('version=2.5.18\n')
        (root/'etc/vkarmani-node/config.json').write_text(json.dumps({
            'domain':'site.example.test','public_ipv4':'8.8.8.8',
            'installation_mode':'secret-key-only','reality_mode':'local'}))
        site=root/'var/www/vkarmani-node/site'
        original={'index.html':b'BEFORE_INDEX','404.html':b'BEFORE_404',
                  'favicon.svg':b'BEFORE_FAVICON', 'robots.txt':b'User-agent: *\nDisallow:\n'}
        for name,content in original.items():
            (site/name).write_bytes(content)
        conf=(b'listen unix:/run/vkarmani-selfsteal/nginx.sock;\n'
              b'    root /var/www/vkarmani-node/site;\n'
              b'    # style-[0-9a-f]{20}[.]css\n'
              b'    location = /index.html { try_files $uri =404; expires -1; }\n'
              b'    location = /robots.txt { try_files $uri =404; expires -1; }\n'
              b'    location / { return 404; }\n')
        (root/'etc/nginx/conf.d/20-vkarmani-selfsteal.conf').write_bytes(conf)
        return site, original, conf

    def runner(self, site, fail=None):
        def mock(argv):
            if argv[0]=='curl':
                filename=argv[-1].rsplit('/',1)[-1]
                if filename==fail:return b'WRONG_LIVE_CONTENT'
                return (site/filename).read_bytes()
            return b''
        return mock

    def test_rich_staging_publish_and_full_rollback(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            site,original,conf=self.setup_fixture(root)
            app=web.NodeWeb(root,run=self.runner(site),css_check=lambda *_:None)
            result=app.site_install('01-atelier','site.example.test',rich_pages=True)
            self.assertIn('RICH_PAGES=VERIFIED',result)
            self.assertEqual(app.receipt('site')['metadata']['theme_bundle'],3)
            self.assertIn(web.RICH_MARKER,app.webconf.read_bytes())
            self.assertIn(b'/journal.html', (site/'index.html').read_bytes())
            self.assertIn(b'href="/assets/style-', (site/'about.html').read_bytes())
            self.assertEqual(app.site_rollback(),'SITE_ROLLBACK=PASS')
            self.assertEqual(app.webconf.read_bytes(),conf)
            for name,data in original.items():
                self.assertEqual((site/name).read_bytes(),data)
            for name in ('journal.html','about.html','questions.html','sitemap.xml'):
                self.assertFalse((site/name).exists(),name)

    def test_live_failure_rolls_back_all_owned_files(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            site,original,conf=self.setup_fixture(root)
            app=web.NodeWeb(root,run=self.runner(site,fail='journal.html'),
                            css_check=lambda *_:None)
            with self.assertRaisesRegex(web.DeployError,'RICH_LIVE_ROUTE_NOT_VERIFIED'):
                app.site_install('01-atelier','site.example.test',rich_pages=True)
            self.assertEqual(app.receipt('site')['stage'],'rolled_back')
            self.assertEqual(app.webconf.read_bytes(),conf)
            for name,data in original.items():
                self.assertEqual((site/name).read_bytes(),data)
            self.assertFalse((site/'journal.html').exists())

    def test_unowned_path_and_nginx_conf_not_overwritten(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            site,_,conf=self.setup_fixture(root)
            (site/'journal.html').write_bytes(b'UNRELATED_EXTERNAL')
            app=web.NodeWeb(root,run=self.runner(site),css_check=lambda *_:None)
            with self.assertRaisesRegex(web.DeployError,'RICH_PATH_ALREADY_OWNED'):
                app.site_install('01-atelier','site.example.test',rich_pages=True)
            self.assertEqual((site/'journal.html').read_bytes(),b'UNRELATED_EXTERNAL')
            self.assertEqual(app.webconf.read_bytes(),conf)
            self.assertIsNone(app.receipt('site'))


    def test_rich_site_isolated_real_nginx_routes_and_404(self):
        import shutil, socket, subprocess, time, urllib.error, urllib.request
        if not shutil.which('nginx'):
            self.skipTest('nginx binary unavailable; tested in Linux CI')
        with tempfile.TemporaryDirectory(prefix='vk-rich-r20-') as td:
            root=Path(td); root.chmod(0o755)
            site=root/'site'; site.mkdir(mode=0o755)
            (site/'assets').mkdir(mode=0o755)
            data=cr.render_rich('07-botanica','site.example.test')
            css=web.NodeWeb.css_name(data['style.css'])
            (site/css).write_bytes(data['style.css'])
            for filename,content in data.items():
                if filename=='style.css':continue
                if filename.endswith('.html'):
                    content=content.replace(b'href="style.css"',('href="/'+css+'"').encode()).replace(
                        b'href="/style.css"',('href="/'+css+'"').encode())
                (site/filename).write_bytes(content)
            with socket.socket() as sock:
                sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
            conf=root/'nginx.conf'
            conf.write_text('worker_processes 1;\npid '+str(root/'nginx.pid')+';\n'
                'error_log '+str(root/'error.log')+' warn;\n'
                'events { worker_connections 64; }\n'
                'http { include /etc/nginx/mime.types; server { '
                'listen 127.0.0.1:'+str(port)+'; server_name site.example.test; '
                'root '+str(site)+'; access_log off; '
                'location = / { try_files /index.html =404; } '
                'location = /index.html { try_files $uri =404; } '
                'location = /robots.txt { try_files $uri =404; } '
                'location = /favicon.svg { try_files $uri =404; } '
                +web.RICH_LOCATIONS.decode() +
                'location = /404.html { internal; try_files $uri =404; } '
                'location ~ "^/assets/style-[0-9a-f]{20}[.]css$" { try_files $uri =404; } '
                'error_page 404 /404.html; location / { return 404; } } }\n')
            valid=subprocess.run(['nginx','-t','-c',str(conf)],
                                 capture_output=True,text=True,timeout=6)
            self.assertEqual(valid.returncode,0,valid.stderr)
            p=subprocess.Popen(['nginx','-c',str(conf),'-g','daemon off;'],
                               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                def req(uri):
                    request=urllib.request.Request('http://127.0.0.1:'+str(port)+uri,
                                                   headers={'Host':'site.example.test'})
                    try:
                        with urllib.request.urlopen(request,timeout=3) as response:
                            return response.status,response.read(),response.headers
                    except urllib.error.HTTPError as exc:
                        return exc.code,exc.read(),exc.headers
                for _ in range(40):
                    try:req('/');break
                    except (ConnectionRefusedError,OSError):time.sleep(.05)
                for filename in ('journal.html','about.html','questions.html','robots.txt','sitemap.xml'):
                    status,body,_=req('/'+filename)
                    self.assertEqual(status,200,filename)
                    self.assertEqual(body,(site/filename).read_bytes(),filename)
                self.assertIn('xml',req('/sitemap.xml')[2].get('Content-Type',''))
                self.assertEqual(req('/not-a-real-route')[0],404)
                self.assertEqual(req('/404.html')[0],404)
                self.assertEqual(req('/.env')[0],404)
            finally:
                p.terminate()
                try:p.wait(timeout=3)
                except subprocess.TimeoutExpired:p.kill();p.wait(timeout=3)


if __name__ == '__main__':unittest.main()
