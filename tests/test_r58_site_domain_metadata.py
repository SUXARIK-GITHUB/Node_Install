"""r58 regression: owned domain may contain a technical-looking brand token."""
import sys
from pathlib import Path
import unittest

from common import ROOT
sys.path.insert(0, str(ROOT / 'scripts'))
import cover_rich
import cover_variants
import site_audit
import site_catalog


class OwnedDomainMetadata(unittest.TestCase):
    DOMAIN = 'site.vkarmani.example.test'
    THEME = '97-design-museum'

    def bundle(self):
        return cover_rich.render_rich(self.THEME, self.DOMAIN)

    def test_all_120_sites_accept_owned_domain_in_exact_metadata_only(self):
        names = cover_variants.NAMES + site_catalog.NAMES
        self.assertEqual(len(names), 120)
        for name in names:
            with self.subTest(name=name):
                b = cover_rich.render_rich(name, self.DOMAIN)
                self.assertEqual(site_audit.audit_bundle(b, self.DOMAIN, rich=True)['status'], 'PASS')

    def test_mismatched_canonical_is_still_rejected(self):
        b = self.bundle()
        b['index.html'] = b['index.html'].replace(
            b'https://site.vkarmani.example.test/', b'https://foreign.example.test/', 1)
        with self.assertRaises(ValueError):
            site_audit.audit_bundle(b, self.DOMAIN, rich=True)

    def test_mismatched_og_url_is_still_rejected(self):
        b = self.bundle()
        own = b'<meta property="og:url" content="https://site.vkarmani.example.test/">'
        assert own in b['index.html']
        b['index.html'] = b['index.html'].replace(own, b'<meta property="og:url" content="https://foreign.example.test/">')
        with self.assertRaises(ValueError):
            site_audit.audit_bundle(b, self.DOMAIN, rich=True)

    def test_public_technical_copy_still_denied(self):
        cases = (
            ('index.html', b'<p>Remnawave VPN internal</p>'),
            ('about.html', b'<p>vkarmani configuration</p>'),
            ('journal.html', b'<p>ASN network edge</p>'),
            ('questions.html', b'<p>server Xray</p>'),
            ('robots.txt', b'\n# vpn technical\n'),
            ('style.css', b'/* VPN proxy */'),
        )
        for name, text in cases:
            with self.subTest(name=name):
                b = self.bundle()
                b[name] += text
                with self.assertRaisesRegex(ValueError, 'PUBLIC_TECHNICAL_REFERENCE'):
                    site_audit.audit_bundle(b, self.DOMAIN, rich=True)

    def test_owned_url_in_visible_content_is_not_whitelisted(self):
        b = self.bundle()
        b['journal.html'] += b'<p>https://site.vkarmani.example.test/journal.html</p>'
        with self.assertRaisesRegex(ValueError, 'PUBLIC_TECHNICAL_REFERENCE'):
            site_audit.audit_bundle(b, self.DOMAIN, rich=True)

    def test_non_metadata_url_and_sitemap_tamper_are_rejected(self):
        for name, old, new in (
            ('robots.txt', b'https://site.vkarmani.example.test/sitemap.xml', b'https://other.test/sitemap.xml'),
            ('sitemap.xml', b'https://site.vkarmani.example.test/about.html', b'https://other.test/about.html'),
        ):
            with self.subTest(name=name):
                b = self.bundle()
                b[name] = b[name].replace(old, new)
                with self.assertRaises(ValueError):
                    site_audit.audit_bundle(b, self.DOMAIN, rich=True)


if __name__ == '__main__':
    unittest.main()
