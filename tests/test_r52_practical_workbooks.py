"""r52: authored practical worksheets render across all three existing design paths."""
from html.parser import HTMLParser
from pathlib import Path
from html import escape
import re
import sys
import unittest

from common import ROOT
sys.path.insert(0, str(ROOT/'scripts'))
import site_catalog
import cover_rich
import cover_variants
import signature_sites
import site_workbooks
import site_quality_review
import site_audit
from site_identity import EXHIBITS


class GuideParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.section = 0
        self.rows = 0
        self.col_headers = 0
        self.row_headers = 0
        self.steps = 0
        self.inside_steps = False
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'section' and a.get('id') == 'practical-guide':
            self.section += 1
        if tag == 'th':
            if a.get('scope') == 'col': self.col_headers += 1
            if a.get('scope') == 'row': self.row_headers += 1
        if tag == 'ol' and a.get('class') == 'workbook-steps':
            self.inside_steps = True
        if tag == 'li' and self.inside_steps:
            self.steps += 1
    def handle_endtag(self, tag):
        if tag == 'ol':
            self.inside_steps = False


class WorkbooksR52(unittest.TestCase):
    DOMAIN = 'review.example.test'

    def test_authored_sections_match_all_104_target_sites(self):
        w = site_workbooks
        self.assertEqual(len(w.CATALOG_WORKBOOKS), 80)
        self.assertEqual(len(w.CLASSIC_WORKBOOKS), 12)
        self.assertEqual(len(w.SIGNATURE_WORKBOOKS), 12)
        self.assertEqual(len(w.WORKBOOKS), 104)
        self.assertFalse(set(w.WORKBOOKS) & set(EXHIBITS))
        self.assertEqual(set(w.CLASSIC_WORKBOOKS),set(cover_variants.NAMES))
        self.assertEqual(set(w.SIGNATURE_WORKBOOKS),set(signature_sites.SIGNATURES))
        self.assertTrue(set(w.CATALOG_WORKBOOKS) <= set(site_catalog.BASE_NAMES))
        titles = [v.title for v in w.WORKBOOKS.values()]
        self.assertEqual(len(titles),len(set(titles)))
        paragraphs = [text for entry in w.WORKBOOKS.values() for text in (*entry.steps, entry.introduction, entry.limitations)]
        self.assertEqual(len(paragraphs),len(set(paragraphs)))
        for name, entry in w.WORKBOOKS.items():
            lang = ('ru' if name in w.CLASSIC_WORKBOOKS else
                    site_catalog.THEMES[name].language)
            for text in (entry.title,entry.introduction,*entry.steps,entry.limitations):
                cyr = len(re.findall('[А-Яа-яЁё]+',text))
                latin = len(re.findall('[A-Za-z]+',text))
                self.assertGreater(cyr,latin,name) if lang == 'ru' else self.assertGreater(latin,cyr,name)

    def test_each_guide_is_printable_and_has_accessible_table_and_navigation(self):
        for name, entry in site_workbooks.WORKBOOKS.items():
            with self.subTest(site=name):
                bundle = cover_rich.render_rich(name,self.DOMAIN)
                page = bundle['journal.html'].decode()
                homepage = bundle['index.html'].decode()
                parser = GuideParser();parser.feed(page)
                self.assertEqual(parser.section,1)
                self.assertEqual(parser.steps,3)
                self.assertEqual(parser.col_headers,2)
                self.assertEqual(parser.row_headers,3)
                self.assertIn(escape(entry.title,quote=True),page)
                self.assertIn(escape(entry.limitations,quote=True),page)
                self.assertIn('href="journal.html#practical-guide"',homepage) if name not in site_workbooks.CLASSIC_WORKBOOKS else self.assertIn('href="/journal.html#practical-guide"',homepage)
                self.assertIn('.workbook-table',bundle['style.css'].decode())
                self.assertIn('@media print',bundle['style.css'].decode())
                self.assertEqual(site_audit.audit_bundle(bundle,self.DOMAIN,True)['status'],'PASS')
                self.assertLessEqual(max(map(len,bundle.values())),128*1024)

    def test_unmodified_themes_do_not_accidentally_gain_workbooks(self):
        for name in site_catalog.BASE_NAMES:
            if name not in site_workbooks.CATALOG_WORKBOOKS:
                bundle = site_catalog.render(name,self.DOMAIN)
                self.assertNotIn(b'id="practical-guide"',bundle['journal.html'])
                self.assertNotIn(b'.workbook-table',bundle['style.css'])

    def test_preview_snapshots_are_generator_exact_for_catalog(self):
        for name in site_catalog.NAMES:
            if name not in site_workbooks.WORKBOOKS:
                continue
            bundle = site_catalog.render(name,'preview.example.test')
            for filename, content in bundle.items():
                self.assertEqual((ROOT/'site-catalog'/name/filename).read_bytes(),content,
                                 f'{name}/{filename}')

    def test_content_review_reports_incomplete_collection_honestly(self):
        review = site_quality_review.scan()
        self.assertEqual(review['total_sites'],120)
        self.assertEqual(review['sites_with_r51_hand_edited_exhibit'],16)
        self.assertEqual(review['sites_with_r52_practical_workbook'],40)
        self.assertEqual(review['sites_with_new_curated_longform'],120)
        self.assertEqual(review['sites_requiring_independent_editorial_review'],120)
        incomplete = [x for x in review['sites'] if 'NO_CURATED_DEEP_DIVE' in x['flags']]
        self.assertEqual(len(incomplete),0)

if __name__ == '__main__':
    unittest.main()
