"""R48: article navigation and live fallback response checks, without host changes."""
from html import escape
from pathlib import Path
import sys
import tempfile
import unittest

from common import ROOT
sys.path.insert(0, str(ROOT / 'scripts'))
import site_catalog
import site_audit
import staging_web_deploy as deploy
import test_r20_rich_site as fixture_module


class SiteNavigationAndFallback(unittest.TestCase):
    DOMAIN = 'site.example.test'

    def test_all_96_editorial_journals_have_real_in_page_reading_index(self):
        names = [n for n in site_catalog.NAMES if n not in site_catalog.SIGNATURES]
        self.assertEqual(len(names), 96)
        for name in names:
            with self.subTest(name=name):
                theme = site_catalog.THEMES[name]
                bundle = site_catalog.render(name, self.DOMAIN)
                journal = bundle['journal.html'].decode('utf-8')
                self.assertEqual(journal.count('class="reading-index"'), 1)
                self.assertIn('aria-label="', journal)
                self.assertIn('grid-template-columns:1fr', bundle['style.css'].decode())
                for i, subject in enumerate(theme.subjects):
                    self.assertIn('href="#story-' + str(i + 1) + '">' + escape(subject, quote=True) + '</a>', journal)
                    self.assertEqual(journal.count('id="story-' + str(i + 1) + '"'), 1)
                self.assertEqual(site_audit.audit_bundle(bundle, self.DOMAIN, rich=True)['status'], 'PASS')

    def test_reading_index_rejects_broken_anchor(self):
        bundle = site_catalog.render('79-glass-workshop', self.DOMAIN)
        bad = dict(bundle)
        bad['journal.html'] = bad['journal.html'].replace(
            b'href="#story-1"', b'href="#story-9000"', 1)
        with self.assertRaisesRegex(ValueError, 'UNKNOWN_ANCHOR'):
            site_audit.audit_bundle(bad, self.DOMAIN, rich=True)

    def _app(self, root, *, fail=None):
        fixture = fixture_module.RichCover()
        site, original, conf = fixture.setup_fixture(Path(root))
        app = deploy.NodeWeb(Path(root), run=fixture.runner(site, fail=fail),
                             css_check=lambda *_: None)
        return app, site, original, conf

    def test_404_and_favicon_are_verified_during_staging_publish(self):
        with tempfile.TemporaryDirectory() as td:
            app, site, _, _ = self._app(td)
            self.assertIn('RICH_PAGES=VERIFIED',
                          app.site_install('79-glass-workshop', self.DOMAIN, rich_pages=True))
            self.assertEqual(site_audit.audit_bundle(
                site_catalog.render('79-glass-workshop', self.DOMAIN), self.DOMAIN,
                rich=True)['status'], 'PASS')
            self.assertEqual(app.site_rollback(), 'SITE_ROLLBACK=PASS')

    def test_wrong_404_response_triggers_transactional_recovery(self):
        with tempfile.TemporaryDirectory() as td:
            app, site, original, nginx = self._app(td, fail='node-install-nonexistent.html')
            with self.assertRaisesRegex(deploy.DeployError, 'RICH_LIVE_404_BODY_OR_STATUS_MISMATCH'):
                app.site_install('79-glass-workshop', self.DOMAIN, rich_pages=True)
            self.assertEqual(app.receipt('site')['stage'], 'rolled_back')
            self.assertEqual(app.webconf.read_bytes(), nginx)
            for name, content in original.items():
                self.assertEqual((site / name).read_bytes(), content)

    def test_wrong_favicon_response_triggers_transactional_recovery(self):
        with tempfile.TemporaryDirectory() as td:
            app, site, original, nginx = self._app(td, fail='favicon.svg')
            with self.assertRaisesRegex(deploy.DeployError, 'RICH_LIVE_ROUTE_NOT_VERIFIED_favicon.svg'):
                app.site_install('79-glass-workshop', self.DOMAIN, rich_pages=True)
            self.assertEqual(app.receipt('site')['stage'], 'rolled_back')
            self.assertEqual(app.webconf.read_bytes(), nginx)
            for name, content in original.items():
                self.assertEqual((site / name).read_bytes(), content)


if __name__ == '__main__':
    unittest.main()
