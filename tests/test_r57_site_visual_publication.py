"""r57: visual direction, 120-site publication contract and responsive QA gates.

No production writes, DNS lookups, remote requests or browser dependency.
Full Chromium viewport acceptance runs separately on the sealed ZIP.
"""
from collections import Counter
import re
import sys
import unittest
from pathlib import Path
from common import ROOT

sys.path.insert(0, str(ROOT / 'scripts'))
import cover_rich
import cover_variants
import site_art_direction as visual
import site_catalog
import site_publication_review
import site_visual_review
import site_audit


class VisualIdentityR57(unittest.TestCase):
    DOMAIN = 'preview.example.test'

    def test_all_96_have_curated_icon_and_editorial_direction(self):
        self.assertTrue(visual.validate(site_catalog.BASE_NAMES))
        self.assertEqual(len(visual.DIRECTIONS), 96)
        self.assertEqual(len(visual.DIRECTION_CSS), 11)
        icons = {d.subject_art for d in visual.DIRECTIONS.values()}
        self.assertGreaterEqual(len(icons), 65)
        self.assertGreaterEqual(len({(d.subject_art, d.editorial, d.canvas)
                              for d in visual.DIRECTIONS.values()}), 80)
        self.assertEqual(len({visual.illustration(site_catalog.THEMES[name])
                              for name in site_catalog.BASE_NAMES}), 96)
        for name in site_catalog.BASE_NAMES:
            with self.subTest(theme=name):
                spec = site_catalog.THEMES[name]
                body = site_catalog.render(name,self.DOMAIN)
                home = body['index.html'].decode()
                css = body['style.css'].decode()
                direction = visual.DIRECTIONS[name]
                self.assertIn('direction-' + direction.editorial, home)
                self.assertIn('role="img"', home)
                self.assertIn('Авторская иллюстрация:' if spec.language == 'ru' else 'Original illustration:', home)
                self.assertNotIn('text-anchor="end" font-size="14"', home.split('class="hero-art"',1)[1].split('</svg>',1)[0])
                self.assertIn('class="hero-art"', home)
                self.assertIn('<text x="55" y="442"', home)
                self.assertIn(site_catalog.e(spec.subjects[0]) + '</text>', home)
                self.assertIn('body.direction-' + direction.editorial + ' .hero', css)
                self.assertIn('@media(max-width:760px){body.direction-', css)
                self.assertNotRegex(css, r'(?i)@import\b|url\s*\(|expression\s*\(')
                self.assertFalse(site_audit.PUBLIC_TECH.search(home))
                self.assertEqual(site_audit.audit_bundle(body,self.DOMAIN,True)['status'],'PASS')

    def test_color_css_and_illustration_are_hostname_independent(self):
        for name in site_catalog.BASE_NAMES:
            with self.subTest(name=name):
                a=site_catalog.render(name,'preview.example.test')
                b=site_catalog.render(name,'journal.example.org')
                self.assertEqual(a['style.css'],b['style.css'])
                # The drawing is authored for the topic, not the hostname.
                start=b'class="hero-art"'
                self.assertEqual(a['index.html'].split(start,1)[1].split(b'</svg>',1)[0],
                                 b['index.html'].split(start,1)[1].split(b'</svg>',1)[0])

    def test_catalog_static_publication_and_handcrafted_classics(self):
        result=site_publication_review.scan(self.DOMAIN)
        self.assertEqual(result['status'],'OFFLINE_PASS')
        self.assertEqual(result['checks']['audited_bundles'],120)
        self.assertEqual(result['checks']['audited_pages'],600)
        self.assertEqual(result['checks']['audited_resources'],1080)
        self.assertEqual(result['checks']['static_site_copies_checked'],108)
        self.assertEqual(result['checks']['original_cover_contracts_checked'],12)
        self.assertEqual(len(result['sites']),120)
        self.assertIn('No real public HTTPS/TLS',result['limitations'][0])

    def test_site_source_linking_css_and_local_assets(self):
        for name in cover_variants.NAMES+site_catalog.NAMES:
            with self.subTest(theme=name):
                b=cover_rich.render_rich(name,self.DOMAIN)
                self.assertEqual(set(b),site_audit.RICH)
                self.assertEqual(site_audit.audit_bundle(b,self.DOMAIN,True)['status'],'PASS')
                for page in ('index.html','journal.html','about.html','questions.html'):
                    self.assertIn(b'<main',b[page]); self.assertIn(b'</main>',b[page])
                    self.assertIn(b'viewport',b[page]); self.assertIn(b'Content-Security-Policy',b[page])
                    self.assertNotIn(b'<script',b[page].lower())
                    self.assertNotIn(b'<form',b[page].lower())

    def test_browser_qa_runner_has_phone_tablet_desktop_dimensions(self):
        self.assertEqual(site_visual_review.SIZES['narrow'][0],320)
        self.assertEqual(site_visual_review.SIZES['mobile'][0],390)
        self.assertEqual(site_visual_review.SIZES['tablet'][0],768)
        self.assertEqual(site_visual_review.SIZES['desktop'][0],1280)
        original=cover_rich.render_rich(site_catalog.BASE_NAMES[0],self.DOMAIN)
        before={k:v for k,v in original.items()}
        screenshot_source=site_visual_review.offline_html(original,'journal.html')
        self.assertIn('<style>',screenshot_source)
        self.assertNotIn('http-equiv="Content-Security-Policy"',screenshot_source)
        self.assertEqual(before,original)
        # The in-memory CSP adjustment never touches the actual publication.
        self.assertIn(b'Content-Security-Policy',original['journal.html'])


if __name__ == '__main__':
    unittest.main()
