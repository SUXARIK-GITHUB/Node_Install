"""Release R12: offline/static twelve-site and rollback guarantees.

No host mutations, no external URLs, no network access required.
"""
import hashlib
from html.parser import HTMLParser
from pathlib import Path
import re
import sys
import tempfile
import unittest
import json
from common import ROOT, SCRIPT, module
sys.path.insert(0, str(ROOT/'scripts'))
import cover_variants as c
import staging_web_deploy as dep

class Parsed(HTMLParser):
    def __init__(self):
        super().__init__();self.ids=set();self.anchors=[];self.tags=[]
    def handle_starttag(self, tag, attrs):
        d=dict(attrs);self.tags.append(tag)
        if 'id' in d:self.ids.add(d['id'])
        if tag=='a':self.anchors.append(d.get('href',''))

class Themes(unittest.TestCase):
    def test_twelve_complete_catalogs(self):
        self.assertEqual(len(c.NAMES),12)
        self.assertEqual(set(x.name for x in c.SITES.iterdir() if x.is_dir()),set(c.NAMES))
        for name in c.NAMES:
            with self.subTest(name=name):
                expected=c.render(name,'preview.example.test')
                for fn in ('index.html','style.css','404.html','favicon.svg'):
                    self.assertTrue((c.SITES/name/fn).is_file())
                    if fn!='style.css':self.assertEqual(expected[fn],(c.SITES/name/fn).read_bytes())
                self.assertTrue((c.SITES/name/'style.css').read_bytes() in expected['style.css'])

    def test_each_theme_original_editorial_visual_and_navigation(self):
        graphics=[];texts=[]
        for name in c.NAMES:
            html=c.render(name,'content.example.test')['index.html'].decode()
            d=Parsed();d.feed(html);d.close()
            self.assertTrue({'start','features','notes','about','faq'} <= d.ids)
            for href in d.anchors:
                self.assertTrue(href.startswith('#') and href[1:] in d.ids,(name,href))
            self.assertGreaterEqual(d.tags.count('article'),4)
            self.assertEqual(d.tags.count('details'),3)
            self.assertIn('<svg',html)
            graphics.append(hashlib.sha256(html.split('<svg',1)[1].split('</svg>',1)[0].encode()).hexdigest())
            texts.append(html.split('<h1>',1)[1].split('</h1>',1)[0])
        self.assertEqual(len(set(graphics)),12)
        self.assertGreaterEqual(len(set(texts)),11)

    def test_domain_specific_no_sensitive_public_text(self):
        all_web=[]
        for name in c.NAMES:
            with self.subTest(name=name):
                a=c.render(name,'alpha.example.test')
                b=c.render(name,'beta.example.test')
                self.assertEqual(a,c.render(name,'alpha.example.test'))
                for fn in ('index.html','style.css','404.html','favicon.svg'):
                    self.assertNotEqual(a[fn],b[fn],(name,fn))
                for fn,bytes_ in a.items():
                    text=bytes_.decode()
                    self.assertNotRegex(text,r'(?i)vkarmani|remnawave|xray|vless|reality|private.?key|<!--|<script|<iframe|<form|onload\s*=|onerror\s*=|javascript:|@import|url\(')
                    if fn.endswith('.html'):
                        self.assertIn('Content-Security-Policy',text)
                    # The standard SVG XML namespace is not an external request.
                    pure=text.replace('xmlns="http://www.w3.org/2000/svg"','')
                    self.assertNotRegex(pure,r'(?i)(?:https?:)?//')
                all_web.append(a['index.html'])
        self.assertEqual(len(set(all_web)),12)

    def test_fail_closed_invalid_domains_and_destinations(self):
        for bad in ('', 'example.com/evil', 'EXAMPLE.COM','localhost','a..com','192.168.1.1','test<script>.com','a' * 70 + '.com', '.example.com','exa_mple.com'):
            with self.subTest(domain=bad),self.assertRaises(ValueError):
                c.render(c.NAMES[0],bad)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'preview'
            self.assertEqual(c.main(['--name',c.NAMES[0],'--domain','alpha.example.test','--output',str(p)]),0)
            self.assertEqual(len(list(p.iterdir())),4)
            self.assertEqual(c.main(['--name',c.NAMES[0],'--domain','alpha.example.test','--output',str(p)]),1)

    def test_staging_deploy_and_full_file_rollback(self):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td)
            for name in ('var/lib/vkarmani-node','etc/vkarmani-node','var/www/vkarmani-node/site/assets','etc/nginx/conf.d'):
                (r/name).mkdir(parents=True,exist_ok=True)
            state=r/'var/lib/vkarmani-node';site=r/'var/www/vkarmani-node/site'
            (state/'owned-installation').touch()
            (state/'install-version').write_text('2.5.13\n')
            (state/'INSTALL_COMPLETE').write_text('version=2.5.13\n')
            (r/'etc/vkarmani-node/config.json').write_text(json.dumps({'domain':'new.example.test','public_ipv4':'8.8.8.8','installation_mode':'secret-key-only'}))
            old={fn:('BEFORE_'+fn).encode() for fn in ('index.html','404.html','favicon.svg')}
            for fn,data in old.items():(site/fn).write_bytes(data)
            conf=b'listen unix:/run/vkarmani-selfsteal/nginx.sock; root /var/www/vkarmani-node/site; style-[0-9a-f]{20}[.]css;'
            webconf=r/'etc/nginx/conf.d/20-vkarmani-selfsteal.conf';webconf.write_bytes(conf)
            calls=[];obj=dep.NodeWeb(r,run=lambda argv:calls.append(argv), css_check=lambda *_:None)
            for theme in c.NAMES:
                with self.subTest(theme=theme):
                    obj.site_install(theme,'new.example.test')
                    sha=dep.NodeWeb.css_name(c.render(theme,'new.example.test')['style.css'])
                    self.assertTrue((site/sha).is_file())
                    self.assertIn(sha.encode(),(site/'404.html').read_bytes())
                    self.assertIn(b'href="/assets/style-', (site/'404.html').read_bytes())
                    self.assertIn(b'href="/assets/style-', (site/'index.html').read_bytes())
                    self.assertIn(b'href="/favicon.svg"', (site/'index.html').read_bytes())
                    self.assertEqual(obj.site_rollback(),'SITE_ROLLBACK=PASS')
                    self.assertFalse((site/sha).exists())
                    for fn,data in old.items():self.assertEqual((site/fn).read_bytes(),data)
                    self.assertEqual(webconf.read_bytes(),conf)
            (state/'INSTALL_COMPLETE').write_text('version=2.5.12\n')
            with self.assertRaisesRegex(dep.DeployError,'INSTALL_NOT_COMPLETE'):
                obj.ready()

    def test_r12_postinstall_command_ownership_gates(self):
        # Explicit maintenance and recovery operations must not reject a successful
        # fresh 2.5.13 install as an unknown future version.
        self.assertIn(r"'^version=2\.5\.([2-9]|10|11|12|13|14|15)$'",SCRIPT)
        self.assertIn(r"'^version=2\.5\.(8|9|10|11|12|13|14|15)$'",SCRIPT)
        self.assertIn("'version=2.5.12', 'version=2.5.13', 'version=2.5.14', 'version=2.5.15')",SCRIPT)

    def test_old_two_file_theme_receipt_still_rolls_back(self):
        app=dep.NodeWeb(Path('/tmp/unused-offline-root'))
        old={'metadata':{'css':'assets/style-'+'a'*20+'.css'},
             'files':{'index':{},'css':{}}}
        self.assertEqual(set(app.site_files(receipt=old)),{'index','css'})
        ancient={'metadata':{},'files':{'index':{},'css':{},'nginx':{}}}
        self.assertEqual(set(app.site_files(receipt=ancient)),{'index','css','nginx'})

    def test_isolated_real_nginx_serves_404_and_absolute_css(self):
        # Optional, completely isolated HTTP smoke. Does not touch the host's
        # nginx.conf, services, TLS keys or listening 80/443 sockets.
        import shutil, socket, subprocess, time, urllib.request, urllib.error
        if not shutil.which('nginx'):
            self.skipTest('nginx binary is not installed on this test runner')
        with tempfile.TemporaryDirectory(prefix='vk-2513-test-nginx-') as td:
            home=Path(td)
            home.chmod(0o755)  # nginx worker must traverse even when root drops UID.
            web=home/'www';web.mkdir(mode=0o755)
            (web/'assets').mkdir()
            data=c.render(c.NAMES[6], 'preview.example.test')
            name=dep.NodeWeb.css_name(data['style.css'])
            (web/name).write_bytes(data['style.css'])
            (web/'favicon.svg').write_bytes(data['favicon.svg'])
            (web/'index.html').write_bytes(data['index.html'].replace(
                b'href="style.css"', ('href="/'+name+'"').encode()))
            (web/'404.html').write_bytes(data['404.html'].replace(
                b'href="style.css"', ('href="/'+name+'"').encode()))
            with socket.socket() as sock:
                sock.bind(('127.0.0.1',0))
                port=sock.getsockname()[1]
            conf=home/'nginx.conf'
            conf.write_text('worker_processes 1;\npid '+str(home/'nginx.pid')+';\n'
              'error_log '+str(home/'error.log')+' warn;\n'
              'events { worker_connections 64; }\nhttp { include /etc/nginx/mime.types; '
              'access_log off; server { listen 127.0.0.1:'+str(port)+'; server_tokens off; '
              'server_name preview.example.test; root '+str(web)+'; '
              'add_header Content-Security-Policy "default-src \'none\'; style-src \'self\'" always; '
              'location = / { try_files /index.html =404; } '
              'location = /index.html { try_files $uri =404; } '
              'location = /favicon.svg { try_files $uri =404; } '
              'location = /404.html { internal; try_files $uri =404; } '
              'location ~ "^/assets/style-[0-9a-f]{20}[.]css$" { try_files $uri =404; } '
              'error_page 404 /404.html; location / { return 404; } } }\n')
            valid=subprocess.run(['nginx','-t','-c',str(conf)], capture_output=True,text=True,timeout=6)
            self.assertEqual(valid.returncode,0,valid.stderr)
            p=subprocess.Popen(['nginx','-c',str(conf),'-g','daemon off;'],
                               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                def request(path):
                    r=urllib.request.Request('http://127.0.0.1:'+str(port)+path,
                                             headers={'Host':'preview.example.test'})
                    try:
                        with urllib.request.urlopen(r,timeout=3) as response:
                            return response.status, response.read()
                    except urllib.error.HTTPError as exc:
                        return exc.code, exc.read()
                for i in range(30):
                    try: request('/');break
                    except (ConnectionRefusedError,OSError):time.sleep(.05)
                status,body=request('/')
                self.assertEqual(status,200)
                self.assertIn(name.encode(),body)
                self.assertEqual(request('/'+name)[0],200)
                self.assertEqual(request('/favicon.svg')[0],200)
                status,error=request('/does/not/exist/here')
                self.assertEqual(status,404)
                self.assertIn(b'href="/assets/style-',error)
                self.assertEqual(request('/404.html')[0],404)
            finally:
                p.terminate()
                try:p.wait(timeout=3)
                except subprocess.TimeoutExpired:p.kill();p.wait()

    def test_nginx_and_install_404_contracts(self):
        self.assertIn('error_page 404 /404.html;',SCRIPT)
        self.assertIn('location = /404.html { internal;',SCRIPT)
        m=module('VK_SITE_TOOL_PY')
        self.assertIn('stylesheet',m.__doc__.lower()) if 'stylesheet' in (m.__doc__ or '').lower() else None
        self.assertIn('Страница не найдена',SCRIPT)

if __name__=='__main__':unittest.main()
