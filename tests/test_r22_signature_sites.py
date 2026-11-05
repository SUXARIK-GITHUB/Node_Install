"""R22: independent composed site designs, safety audit and staged rollback."""
from html.parser import HTMLParser
from pathlib import Path
from html import escape
import hashlib
import tempfile
import unittest
import sys
from common import ROOT
sys.path.insert(0,str(ROOT/'scripts'))
import site_catalog as catalog
import signature_sites as original
import site_audit
import staging_web_deploy as web
import test_r20_rich_site as r20


class Structure(HTMLParser):
    def __init__(self):
        super().__init__()
        self.classes = set()
        self.headings = []
        self.links = []
        self.n_scripts = 0
        self.nav = 0
        self.details = 0
    def handle_starttag(self, name, attrs):
        data=dict(attrs)
        self.classes.update(data.get('class','').split())
        if name=='nav':self.nav+=1
        if name=='details':self.details+=1
        if name=='script':self.n_scripts+=1
        if name=='a':self.links.append(data.get('href'))


class SignatureSites(unittest.TestCase):
    def test_preserves_96_old_generated_sites_12_classics_and_adds_12_signatures(self):
        self.assertEqual(len(catalog.BASE_NAMES),96)
        self.assertEqual(len(original.SIGNATURES),12)
        self.assertEqual(len(catalog.NAMES),108)
        self.assertEqual(len({p.name for p in (ROOT/'site-catalog').iterdir() if p.is_dir()}),108)
        self.assertEqual(len({s.mode for s in original.SIGNATURES.values()}),12)
        self.assertTrue(set(original.SIGNATURES).isdisjoint(catalog.BASE_NAMES))

    def test_signature_design_is_not_just_same_markup_hue_and_headline(self):
        unique_classes=[];csses=set();htmls=set();svg=set()
        for name, spec in original.SIGNATURES.items():
            with self.subTest(name=name):
                bundle=catalog.render(name,'node.example.test')
                self.assertEqual(bundle,original.render_signature(name,'node.example.test'))
                self.assertEqual(site_audit.audit_bundle(bundle,'node.example.test',rich=True)['pages'],5)
                self.assertEqual(len(bundle),9)
                self.assertEqual(bundle['robots.txt'].decode().splitlines()[-1],
                                 'Sitemap: https://node.example.test/sitemap.xml')
                for fn, data in bundle.items():
                    self.assertEqual((ROOT/'site-catalog'/name/fn).read_bytes(),
                                     catalog.render(name,'preview.example.test')[fn] if fn in ('robots.txt','sitemap.xml') else data)
                doc=bundle['index.html'].decode()
                self.assertIn('layout-signature-'+spec.mode,doc)
                self.assertIn(escape(spec.headline),doc)
                self.assertIn(escape(spec.title),doc)
                for title,text in spec.cards:
                    self.assertIn(escape(title),doc)
                    self.assertIn(escape(text),doc)
                tree=Structure();tree.feed(doc)
                self.assertFalse(tree.n_scripts)
                self.assertGreaterEqual(tree.nav,1)
                self.assertTrue(set(('index.html','journal.html','about.html','questions.html')) <= set(tree.links))
                special=[cl for cl in tree.classes if cl in ('docs-layout','record-stage','gallery-grid','library-plate',
                    'kitchen-title','hotel-hero','botanical-top','type-head','sky-hero','trail-hero','archive-masthead',
                    'workshop-hero')]
                self.assertEqual(len(special),1)
                unique_classes.append(special[0])
                for page in ('journal.html','about.html','questions.html'):
                    self.assertGreater(len(bundle[page]),1100)
                    self.assertIn(b'href="style.css"',bundle[page])
                csses.add(hashlib.sha256(bundle['style.css']).digest())
                htmls.add(hashlib.sha256(bundle['index.html']).digest())
                svg.add(hashlib.sha256(bundle['favicon.svg']).digest())
        self.assertEqual(len(set(unique_classes)),12)
        self.assertEqual(len(csses),12)
        self.assertEqual(len(htmls),12)
        self.assertEqual(len(svg),12)

    def test_about_and_faq_are_site_specific_and_local(self):
        faq=set();about=set()
        for name,spec in original.SIGNATURES.items():
            bundle=catalog.render(name)
            doc=bundle['questions.html'].decode()
            structure=Structure();structure.feed(doc)
            self.assertEqual(structure.details,3)
            for question,answer in spec.questions:
                self.assertIn(escape(question),doc)
                self.assertIn(escape(answer),doc)
            faq.add(hashlib.sha256(bundle['questions.html']).digest())
            about.add(hashlib.sha256(bundle['about.html']).digest())
        self.assertEqual(len(faq),12)
        self.assertEqual(len(about),12)

    def test_rejects_injected_urls_scripts_css_and_extra_file(self):
        name='111-atlas-docs';bundle=catalog.render(name,'site.example.test')
        tampered=dict(bundle)
        tampered['index.html']=tampered['index.html'].replace(b'href="journal.html"',b'href="../../secret.env"')
        with self.assertRaises(ValueError):site_audit.audit_bundle(tampered,'site.example.test',rich=True)
        tampered=dict(bundle);tampered['index.html']+=b'<script>alert(1)</script>'
        with self.assertRaises(ValueError):site_audit.audit_bundle(tampered,'site.example.test',rich=True)
        tampered=dict(bundle);tampered['style.css']+=b'@import url("https://example.com/style.css");'
        with self.assertRaises(ValueError):site_audit.audit_bundle(tampered,'site.example.test',rich=True)
        tampered=dict(bundle);tampered['admin.php']=b'not allowed'
        with self.assertRaises(ValueError):site_audit.audit_bundle(tampered,'site.example.test',rich=True)

    def test_signature_staging_switch_and_failure_restore_previous(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            fixture=r20.RichCover();site, originals, nginx=fixture.setup_fixture(root)
            app=web.NodeWeb(root,run=fixture.runner(site),css_check=lambda *_:None)
            initial=app.site_install('110-blue-harbor','site.example.test',rich_pages=True)
            self.assertIn('SITE_DEPLOY=PASS',initial)
            self.assertIn(b'Blue Harbor',(site/'index.html').read_bytes())
            before=(site/'index.html').read_bytes()
            previous=app.receipt('site')
            app.run=fixture.runner(site,fail='questions.html')
            with self.assertRaisesRegex(web.DeployError,'RICH_LIVE_ROUTE_NOT_VERIFIED'):
                app.site_install('119-type-lab','site.example.test',rich_pages=True,switch=True)
            self.assertEqual((site/'index.html').read_bytes(),before)
            self.assertEqual(app.receipt('site'),previous)
            app.run=fixture.runner(site)
            result=app.site_install('119-type-lab','site.example.test',rich_pages=True,switch=True)
            self.assertIn('SITE_DEPLOY=PASS',result)
            self.assertIn('119-type-lab',app.status()['site_theme'])
            self.assertEqual(app.site_rollback(),'SITE_CHANGE_ROLLBACK=PASS PREVIOUS_THEME_RESTORED')
            self.assertEqual((site/'index.html').read_bytes(),before)
            self.assertEqual(app.site_rollback(),'SITE_ROLLBACK=PASS')
            self.assertEqual(app.webconf.read_bytes(),nginx)
            for k,v in originals.items():self.assertEqual((site/k).read_bytes(),v)


if __name__ == '__main__':unittest.main()
