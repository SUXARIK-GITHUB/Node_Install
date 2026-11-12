"""Verify 64 new guides without treating a passing test as editorial certification."""
import re
import sys
import unittest
from pathlib import Path
from common import ROOT
sys.path.insert(0, str(ROOT / 'scripts'))
from site_catalog import THEMES, BASE_NAMES, render
from site_workbooks import WORKBOOKS
from site_workbooks_r53 import RECORDS, ENGLISH
from site_identity import EXHIBITS
from site_quality_review import scan


class SiteGuideR53(unittest.TestCase):
    def test_exact_64_missing_themes_have_authored_records(self):
        rows = [line.split('|') for line in RECORDS.strip().splitlines()]
        names = [row[0] for row in rows]
        self.assertEqual(len(names), 64)
        self.assertEqual(len(set(names)), 64)
        self.assertFalse(set(names) & set(EXHIBITS))
        self.assertEqual(set(names), set(BASE_NAMES) - set(EXHIBITS) - (set(WORKBOOKS) - set(names)))
        self.assertEqual(len(WORKBOOKS), 104)
        self.assertEqual(len(set(w.title for w in WORKBOOKS.values())), 104)
        for row in rows:
            self.assertEqual(len(row), 13)
            name = row[0]
            self.assertEqual(THEMES[name].language, 'en' if name in ENGLISH else 'ru')
            for item in (row[1], row[2], *row[3:6], row[12]):
                cyr = len(re.findall('[А-Яа-яЁё]', item))
                latin = len(re.findall('[A-Za-z]', item))
                if name in ENGLISH:
                    self.assertGreater(latin, cyr, name)
                else:
                    self.assertGreater(cyr, latin, name)

    def test_guides_render_into_existing_static_pages(self):
        names = [line.split('|', 1)[0] for line in RECORDS.strip().splitlines()]
        for name in names:
            with self.subTest(name=name):
                bundle = render(name, 'preview.example.test', rich=True)
                journal = bundle['journal.html'].decode('utf-8')
                homepage = bundle['index.html'].decode('utf-8')
                self.assertEqual(journal.count('id="practical-guide"'), 1)
                self.assertEqual(journal.count('class="workbook-table"'), 1)
                self.assertIn('journal.html#practical-guide', homepage)
                self.assertIn(WORKBOOKS[name].title, journal)
                self.assertEqual(len(bundle), 9)
                for fname, contents in bundle.items():
                    self.assertEqual((ROOT/'site-catalog'/name/fname).read_bytes(), contents)

    def test_inventory_is_transparent_not_editorial_approval(self):
        review = scan()
        self.assertEqual(review['total_sites'], 120)
        self.assertEqual(review['sites_with_r51_hand_edited_exhibit'], 16)
        self.assertEqual(review['sites_with_r52_practical_workbook'], 40)
        self.assertEqual(review['sites_with_r53_practical_workbook'], 64)
        self.assertEqual(review['sites_with_new_curated_longform'], 120)
        self.assertEqual(review['sites_requiring_independent_editorial_review'], 120)
        self.assertTrue(all(row['editorial_review'] == 'REQUIRED' for row in review['sites']))


if __name__ == '__main__':
    unittest.main()
