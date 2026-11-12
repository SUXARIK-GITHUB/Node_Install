"""r49: offline public-surface and native-reading usability checks only."""
from pathlib import Path
import sys
import unittest

from common import ROOT
sys.path.insert(0, str(ROOT / 'scripts'))
import cover_rich
import cover_variants
import site_audit
import site_catalog


class PublicSiteSurface(unittest.TestCase):
    DOMAIN = 'owned.example.test'

    def test_all_120_published_bundles_have_clean_source_and_print_styles(self):
        names = cover_variants.NAMES + site_catalog.NAMES
        self.assertEqual(len(names), 120)
        for name in names:
            with self.subTest(name=name):
                bundle = cover_rich.render_rich(name, self.DOMAIN)
                self.assertEqual(site_audit.audit_bundle(bundle, self.DOMAIN, rich=True)['status'], 'PASS')
                css = bundle['style.css'].decode('utf-8')
                self.assertIn('@media print', css)
                self.assertNotIn('/*', css)
                for path, contents in bundle.items():
                    text = contents.decode('utf-8')
                    self.assertIsNone(site_audit.PUBLIC_TECH.search(text), (name, path))
                    self.assertNotIn('<!--', text, (name, path))
                    if path.endswith('.css'):
                        self.assertNotIn('/*', text, (name, path))

    def test_catalog_statics_match_runtime_generators(self):
        for name in site_catalog.NAMES:
            with self.subTest(name=name):
                compiled = site_catalog.render(name, 'preview.example.test')
                disk = ROOT / 'site-catalog' / name
                self.assertEqual({p.name for p in disk.iterdir()}, set(compiled))
                for filename, contents in compiled.items():
                    self.assertEqual((disk / filename).read_bytes(), contents, (name, filename))

    def test_editorial_article_links_back_to_real_contents_anchor(self):
        self.assertEqual(len(site_catalog.BASE_NAMES), 96)
        for name in site_catalog.BASE_NAMES:
            with self.subTest(name=name):
                bundle = site_catalog.render(name, self.DOMAIN)
                journal = bundle['journal.html'].decode('utf-8')
                self.assertIn('id="reading-top"', journal)
                self.assertEqual(journal.count('href="#reading-top"'), 4)
                label = 'К содержанию' if site_catalog.THEMES[name].language == 'ru' else 'Back to contents'
                self.assertEqual(journal.count('>' + label + '</a>'), 4)
                self.assertIn('.article:target', bundle['style.css'].decode('utf-8'))
                self.assertEqual(site_audit.audit_bundle(bundle, self.DOMAIN, rich=True)['status'], 'PASS')

    def test_technical_reference_in_body_is_blocked(self):
        bundle = site_catalog.render('79-glass-workshop', self.DOMAIN)
        for filename, injected in (
            ('index.html', b'VPN / VLESS / Remnawave'),
            ('about.html', b'ASN 12345'),
            ('robots.txt', b'# internal xray'),
            ('style.css', b'/* asn provider */'),
        ):
            with self.subTest(filename=filename):
                changed = dict(bundle)
                changed[filename] += injected
                with self.assertRaisesRegex(ValueError, 'PUBLIC_TECHNICAL_REFERENCE'):
                    site_audit.audit_bundle(changed, self.DOMAIN, rich=True)

    def test_internal_comments_in_html_and_css_are_blocked(self):
        bundle = cover_rich.render_rich('01-atelier', self.DOMAIN)
        for filename, marker in (('index.html', b'<!-- internal build marker -->'),
                                 ('style.css', b'/* design generator marker */')):
            with self.subTest(filename=filename):
                changed = dict(bundle)
                changed[filename] += marker
                with self.assertRaisesRegex(ValueError, 'PUBLIC_SOURCE_COMMENT'):
                    site_audit.audit_bundle(changed, self.DOMAIN, rich=True)

    def test_existing_nginx_version_hiding_and_route_allowlist_preserved(self):
        installer = (ROOT / 'install.sh').read_text('utf-8')
        self.assertIn('server_tokens off;', installer)
        self.assertIn('location / { return 404; }', installer)
        self.assertIn('location = /404.html { internal;', installer)
        # No direct server/network modifications in this release.


if __name__ == '__main__':
    unittest.main()
