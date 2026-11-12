"""r45 sites-only regression suite: editorial quality, navigation and filesets.

Offline and read-only; does not call Xray, nginx, DNS, or any public network.
"""
from pathlib import Path
import colorsys
import hashlib
import re
from html import escape
import sys
import unittest

from common import ROOT
sys.path.insert(0, str(ROOT / 'scripts'))
import site_catalog as catalog
import cover_variants as classics
import cover_rich
import site_audit
from site_editorial import EDITORIAL_NOTES


class EditorialSiteCatalog(unittest.TestCase):
    DOMAIN = 'review.example.test'

    def test_complete_curated_notes_and_six_compositions(self):
        self.assertEqual(set(EDITORIAL_NOTES), set(catalog.BASE_NAMES))
        notes = [paragraph for name in catalog.BASE_NAMES for paragraph in EDITORIAL_NOTES[name]]
        self.assertEqual(len(notes), 384)
        self.assertEqual(len(set(notes)), 384)
        self.assertTrue(all(len(note) >= 30 for note in notes))
        self.assertEqual({catalog.composition(catalog.THEMES[name]) for name in catalog.BASE_NAMES},
                         set(catalog.COMPOSITIONS))
        self.assertGreaterEqual(len({catalog.THEMES[name].layout for name in catalog.BASE_NAMES}),16)

    def test_all_cards_link_to_their_own_story_with_three_paragraphs(self):
        for name in catalog.BASE_NAMES:
            with self.subTest(theme=name):
                bundle = catalog.render(name, self.DOMAIN)
                home = bundle['index.html'].decode()
                journal = bundle['journal.html'].decode()
                self.assertIn('composition-' + catalog.composition(catalog.THEMES[name]), home)
                self.assertIn('<section class="feature">', home)
                self.assertIn('<blockquote>', home)
                for index in range(4):
                    anchor = f'story-{index + 1}'
                    self.assertIn(f'href="journal.html#{anchor}"', home)
                    self.assertEqual(journal.count(f'id="{anchor}"'), 1)
                    section = re.search(r'<article class="article" id="' + anchor + r'">(.*?)</article>',journal)
                    self.assertIsNotNone(section)
                    self.assertEqual(section.group(1).count('<p>'), 4)  # 3 paragraphs + next story
                    self.assertIn(escape(EDITORIAL_NOTES[name][index], quote=True), section.group(1))
                site_audit.audit_bundle(bundle, self.DOMAIN, rich=True)

    def test_every_one_of_120_sites_is_locally_self_contained_and_undated(self):
        names = classics.NAMES + catalog.NAMES
        self.assertEqual(len(names), 120)
        for name in names:
            with self.subTest(theme=name):
                bundle = cover_rich.render_rich(name, self.DOMAIN)
                self.assertEqual(set(bundle), site_audit.RICH)
                self.assertEqual(site_audit.audit_bundle(bundle,self.DOMAIN,rich=True)['status'],'PASS')
                for path,data in bundle.items():
                    if path.endswith('.html'):
                        self.assertNotIn(b'2026',data)
                        self.assertNotIn(b'<script',data.lower())
                self.assertEqual(bundle['robots.txt'],
                                 f'User-agent: *\nAllow: /\nSitemap: https://{self.DOMAIN}/sitemap.xml\n'.encode())

    def test_all_snapshot_files_match_generator_and_no_missing_files(self):
        for name in catalog.NAMES:
            with self.subTest(theme=name):
                folder=ROOT/'site-catalog'/name
                generated=catalog.render(name,'preview.example.test')
                self.assertEqual({f.name for f in folder.iterdir()},set(generated))
                for path,body in generated.items():
                    self.assertEqual((folder/path).read_bytes(),body)
        for name in classics.NAMES:
            with self.subTest(theme=name):
                folder=ROOT/'cover-variants'/name
                generated=classics.render(name,'preview.example.test')
                self.assertEqual({f.name for f in folder.iterdir()},set(generated))
                for path,body in generated.items():
                    # R55 removes historical, redundant variable overrides.
                    # The canonical preview CSS is now exactly reproducible.
                    self.assertEqual((folder/path).read_bytes(),body)

    def test_accent_contrast_meets_aa_for_text_on_theme_paper(self):
        def luminance(rgb):
            result=[]
            for value in rgb:
                result.append(value/12.92 if value<=0.04045 else ((value+0.055)/1.055)**2.4)
            return sum(a*b for a,b in zip((0.2126,0.7152,0.0722),result))
        dark_families={'terminal','dashboard','gallery','luxury','museum'}
        for name in catalog.BASE_NAMES:
            with self.subTest(theme=name):
                seed=hashlib.sha256(name.encode('ascii')).digest()
                h=(seed[0]+seed[1]//2)%360
                dark=catalog.THEMES[name].layout in dark_families
                text=colorsys.hls_to_rgb(h/360,(65 if dark else 30)/100,.72 if dark else .58)
                paper=tuple(int(('101a25' if dark else 'fcfaf5')[i:i+2],16)/255 for i in (0,2,4))
                x,y=sorted((luminance(text),luminance(paper)),reverse=True)
                self.assertGreaterEqual((x+.05)/(y+.05),4.5)
                stylesheet=catalog.render(name)['style.css'].decode()
                self.assertIn(f'--highlight:hsl({h} {72 if dark else 58}% {65 if dark else 30}%)',stylesheet)

    def test_requested_theme_stays_constant_across_domains(self):
        for name in catalog.BASE_NAMES:
            a = catalog.render(name,'one.example.test')
            b = catalog.render(name,'two.example.test')
            # r47 adds domain-bound canonical and OpenGraph URLs to *each* page.
            # Rendered editorial copy remains identical for a selected catalog theme.
            for page in ('index.html', 'journal.html', 'about.html', 'questions.html'):
                self.assertNotEqual(a[page], b[page])
                self.assertEqual(a[page].replace(b'https://one.example.test/',
                                                 b'https://two.example.test/'), b[page])
            self.assertNotEqual(a['robots.txt'], b['robots.txt'])
            self.assertNotEqual(a['sitemap.xml'], b['sitemap.xml'])


if __name__ == '__main__': unittest.main()
