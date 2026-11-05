"""R21 immutable catalog/gallery contract and release packaging QA."""
import hashlib
from html.parser import HTMLParser
from pathlib import Path
import re
import sys
import unittest

from common import ROOT
sys.path.insert(0, str(ROOT/'scripts'))
import build_site_gallery as gallery
import cover_variants
import site_catalog


class GalleryHTML(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links=[]
        self.images=[]
        self.bad=[]

    def handle_starttag(self, tag, attrs):
        d=dict(attrs)
        if tag == 'a' and d.get('href'):
            self.links.append(d['href'])
        if tag == 'img' and d.get('src'):
            self.images.append(d['src'])
        if tag in ('script', 'iframe', 'form', 'object', 'embed'):
            self.bad.append(tag)


class Gallery(unittest.TestCase):
    def test_gallery_exact_links_and_file_backing(self):
        html=gallery.generate()
        self.assertEqual(html, (ROOT/'preview/site-gallery/index.html').read_bytes())
        page=GalleryHTML()
        page.feed(html.decode('utf-8'))
        self.assertFalse(page.bad)
        self.assertEqual(len(page.links),123)  # 120 site cards plus 3 reviewed visual QA links
        self.assertEqual(len(page.images),120)
        self.assertEqual(len(set(page.links)),123)
        self.assertEqual(len(set(page.images)),120)
        here=ROOT/'preview/site-gallery'
        for link in page.links[:3]:
            self.assertIn(link,('visual-review-desktop.jpg','visual-review-mobile.jpg','visual-review-r23.json'))
            self.assertTrue((here/link).is_file(),link)
        for link in page.links[3:]+page.images:
            self.assertRegex(link,r'^\.\./\.\./(?:site-catalog|cover-variants)/[a-z0-9-]+/(?:index\.html|favicon\.svg)$')
            file=(here/link).resolve()
            self.assertTrue(file.is_relative_to(ROOT))
            self.assertTrue(file.is_file(),link)
        self.assertNotIn(b'http://',html)
        self.assertNotIn(b'https://',html)

    def test_new_previews_have_relative_styles_and_navigation(self):
        for name in site_catalog.NAMES:
            src=ROOT/'site-catalog'/name
            generated=site_catalog.render(name)
            self.assertEqual(set(x.name for x in src.iterdir()),set(generated))
            for filename in ('index.html','journal.html','about.html','questions.html','404.html'):
                body=(src/filename).read_bytes()
                self.assertEqual(body,generated[filename])
                self.assertIn(b'href="style.css"',body)
                self.assertNotIn(b'href="/style.css"',body)
                self.assertIn(b'href="journal.html"',body)
                self.assertIn(b'href="index.html"',body)
                self.assertNotIn(b'<script',body)
            self.assertGreater((src/'style.css').stat().st_size,500)

    def test_independent_catalog_sizes_and_layout_families(self):
        self.assertEqual(len(cover_variants.NAMES),12)
        self.assertEqual(len(site_catalog.BASE_NAMES),96)
        self.assertEqual(len(site_catalog.NAMES),108)
        self.assertEqual(len(set(cover_variants.NAMES+site_catalog.NAMES)),120)
        self.assertGreaterEqual(len({site_catalog.THEMES[n].layout for n in site_catalog.NAMES}),16)
        self.assertEqual(sum(len(site_catalog.render(name)) for name in site_catalog.NAMES),972)

    def test_offline_gallery_check_and_release_notes(self):
        self.assertEqual(gallery.main(['--check']),0)
        notes=(ROOT/'docs/RELEASE_2.5.18_R21_CATALOG_AND_SAFETY.md').read_text()
        self.assertIn('INCOMPLETE_STAGING_ONLY',notes)
        self.assertIn('96',notes)
        self.assertIn('108',notes)
        self.assertIn('НЕ',notes)

if __name__=='__main__':unittest.main()
