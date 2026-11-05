"""Switching installed rich sites must preserve previous version on every failure."""
from pathlib import Path
import tempfile
import unittest
import sys
from common import ROOT
sys.path.insert(0,str(ROOT/'scripts'))
import staging_web_deploy as web
import test_r20_rich_site as r20


class SiteChange(unittest.TestCase):
    def make_app(self,td):
        root=Path(td)
        fixture=r20.RichCover()
        site,original,conf=fixture.setup_fixture(root)
        app=web.NodeWeb(root,run=fixture.runner(site),css_check=lambda *a:None)
        return app,site,original,conf,fixture

    def test_first_change_rollback_then_original_rollback(self):
        with tempfile.TemporaryDirectory() as td:
            app,site,original,conf,_=self.make_app(td)
            app.site_install('01-atelier','site.example.test',rich_pages=True)
            old_receipt=app.receipt('site')
            old_index=(site/'index.html').read_bytes()
            old_css=app.site/old_receipt['metadata']['css']
            result=app.site_install('13-cloud-ledger','site.example.test',rich_pages=True,switch=True)
            self.assertIn('SITE_DEPLOY=PASS',result)
            self.assertEqual(app.status()['site_theme'],'13-cloud-ledger')
            self.assertFalse(old_css.exists())
            self.assertIn(b'Northbound Cloud',(site/'index.html').read_bytes())
            new_css=app.site/app.receipt('site')['metadata']['css']
            self.assertTrue(new_css.is_file())
            self.assertEqual(app.site_rollback(),'SITE_CHANGE_ROLLBACK=PASS PREVIOUS_THEME_RESTORED')
            self.assertEqual(app.status()['site_theme'],'01-atelier')
            self.assertEqual(app.receipt('site'),old_receipt)
            self.assertEqual((site/'index.html').read_bytes(),old_index)
            self.assertTrue(old_css.exists())
            self.assertFalse(new_css.exists())
            self.assertEqual(app.site_rollback(),'SITE_ROLLBACK=PASS')
            self.assertEqual(app.webconf.read_bytes(),conf)
            for name,content in original.items():self.assertEqual((site/name).read_bytes(),content)

    def test_switch_failure_restores_previous_active(self):
        with tempfile.TemporaryDirectory() as td:
            app,site,_,conf,fixture=self.make_app(td)
            app.site_install('79-glass-workshop','site.example.test',rich_pages=True)
            previous=app.receipt('site')
            content=(site/'index.html').read_bytes()
            app.run=fixture.runner(site,fail='questions.html')
            with self.assertRaisesRegex(web.DeployError,'RICH_LIVE_ROUTE_NOT_VERIFIED'):
                app.site_install('85-bread-journal','site.example.test',rich_pages=True,switch=True)
            self.assertEqual(app.receipt('site'),previous)
            self.assertEqual(app.status()['site_theme'],'79-glass-workshop')
            self.assertEqual((site/'index.html').read_bytes(),content)
            self.assertIn(web.RICH_MARKER,app.webconf.read_bytes())
            self.assertTrue((site/previous['metadata']['css']).exists())

    def test_rollback_rejects_tampered_previous_journal_before_changing_site(self):
        with tempfile.TemporaryDirectory() as td:
            app,site,_,_,_=self.make_app(td)
            app.site_install('01-atelier','site.example.test',rich_pages=True)
            app.site_install('94-mountain-weather','site.example.test',rich_pages=True,switch=True)
            data=(site/'index.html').read_bytes()
            r=app.receipt('site')
            prev=app.journal/r['metadata']['previous_receipt']
            prev.write_bytes(b'ATTACKER_REPLACED_JOURNAL')
            with self.assertRaisesRegex(web.DeployError,'PREVIOUS_RECEIPT_HASH_MISMATCH'):
                app.site_rollback()
            self.assertEqual((site/'index.html').read_bytes(),data)
            self.assertEqual(app.receipt('site'),r)

    def test_chained_changes_restore_step_by_step(self):
        with tempfile.TemporaryDirectory() as td:
            app,site,_,_,_=self.make_app(td)
            app.site_install('01-atelier','site.example.test',rich_pages=True)
            app.site_install('34-slow-bakery','site.example.test',rich_pages=True,switch=True)
            app.site_install('73-quiet-storage','site.example.test',rich_pages=True,switch=True)
            self.assertEqual(app.status()['site_theme'],'73-quiet-storage')
            self.assertEqual(app.site_rollback(),'SITE_CHANGE_ROLLBACK=PASS PREVIOUS_THEME_RESTORED')
            self.assertEqual(app.status()['site_theme'],'34-slow-bakery')
            self.assertEqual(app.site_rollback(),'SITE_CHANGE_ROLLBACK=PASS PREVIOUS_THEME_RESTORED')
            self.assertEqual(app.status()['site_theme'],'01-atelier')
            self.assertEqual(app.site_rollback(),'SITE_ROLLBACK=PASS')
            self.assertEqual(app.status()['site'],'rolled_back')


if __name__=='__main__':unittest.main()
