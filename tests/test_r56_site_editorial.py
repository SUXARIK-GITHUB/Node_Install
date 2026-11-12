"""r56: editorial content coverage without claiming human publication approval."""
import re
import sys
import unittest
from html import escape
from pathlib import Path

from common import ROOT
sys.path.insert(0, str(ROOT / 'scripts'))
from cover_variants import NAMES as CLASSICS, render as render_classic
from cover_rich import render_rich
from site_catalog import NAMES as CATALOG, THEMES, render as render_catalog
from site_focus_notes import FOCUS_NOTES
from site_editorial_expansion import audit_data_integrity
from site_quality_review import scan
from site_audit import audit_bundle
from site_workbooks import WORKBOOKS
from site_identity import EXHIBITS


class EditorialExpansionR56(unittest.TestCase):
    DOMAIN = 'preview.example.test'

    def test_exactly_120_original_site_specific_notes_and_language(self):
        names = CLASSICS + CATALOG
        self.assertEqual(len(names), 120)
        languages = {name: 'ru' for name in CLASSICS}
        languages.update({name: spec.language for name, spec in THEMES.items()})
        self.assertTrue(audit_data_integrity(names, languages))
        self.assertEqual(len(set(FOCUS_NOTES.values())), 120)
        self.assertEqual(len(EXHIBITS), 16)
        self.assertEqual(len(WORKBOOKS), 104)
        for name, note in FOCUS_NOTES.items():
            with self.subTest(site=name):
                self.assertGreaterEqual(len(re.findall(r'\w+', note)), 35)
                self.assertFalse(re.search(r'(?i)\b(?:lorem|ipsum|test vpn|placeholder|sample business)\b', note))
                russian = len(re.findall('[А-Яа-яЁё]{2,}', note))
                english = len(re.findall('[A-Za-z]{2,}', note))
                if languages[name] == 'ru':
                    self.assertGreater(russian, english)
                else:
                    self.assertGreater(english, russian)

    def test_all_120_sites_have_substantive_page_content_without_auto_certification(self):
        report = scan(self.DOMAIN)
        self.assertEqual(report['total_sites'], 120)
        self.assertFalse([row for row in report['sites'] if row['flags']])
        self.assertEqual(report['sites_requiring_independent_editorial_review'], 120)
        self.assertTrue(all(row['editorial_review'] == 'REQUIRED' for row in report['sites']))
        for row in report['sites']:
            words = row['words']
            self.assertGreaterEqual(words['index.html'], 250, row['site'])
            self.assertGreaterEqual(words['journal.html'], 450, row['site'])
            self.assertGreaterEqual(words['about.html'], 140, row['site'])

    def test_rendered_notes_only_on_related_journals(self):
        allnames = CLASSICS + CATALOG
        for name in allnames:
            with self.subTest(name=name):
                bundle = render_rich(name, self.DOMAIN)
                self.assertEqual(audit_bundle(bundle, self.DOMAIN, True)['status'], 'PASS')
                journal = bundle['journal.html'].decode('utf-8')
                self.assertEqual(journal.count(escape(FOCUS_NOTES[name], quote=True)), 1)
                for page in ('index.html', 'journal.html', 'about.html', 'questions.html'):
                    text = bundle[page].decode('utf-8')
                    self.assertNotIn('<!--', text)
                    self.assertEqual(text.count('<main'), 1)
                    self.assertEqual(text.count('</main>'), 1)
                self.assertIn('id="reading-companion"', journal)
                self.assertIn('editorial-scope', bundle['about.html'].decode('utf-8'))
                self.assertIn('editorial-start', bundle['index.html'].decode('utf-8'))
                self.assertGreaterEqual(bundle['questions.html'].count(b'<details'), 7)

    def test_static_catalog_matches_generator_without_changing_other_files(self):
        for name in CATALOG:
            with self.subTest(name=name):
                generated = render_catalog(name, self.DOMAIN)
                directory = ROOT / 'site-catalog' / name
                self.assertEqual(set(generated), {p.name for p in directory.iterdir()})
                for filename, content in generated.items():
                    self.assertEqual((directory / filename).read_bytes(), content)
        # The original 12 single-page classic bundles remain as they were.
        for name in CLASSICS:
            original = render_classic(name, self.DOMAIN)
            for filename in original:
                self.assertEqual((ROOT / 'cover-variants' / name / filename).read_bytes(), original[filename])

    def test_generation_deterministic_on_two_domains(self):
        for name in (CLASSICS[0], CATALOG[0], CATALOG[-1]):
            a = render_rich(name, self.DOMAIN)
            self.assertEqual(a, render_rich(name, self.DOMAIN))
            b = render_rich(name, 'news.example.org')
            if name not in CLASSICS:
                self.assertEqual(a['style.css'], b['style.css'])
            self.assertEqual(a['journal.html'].count(FOCUS_NOTES[name].encode()), 1)
            self.assertEqual(b['journal.html'].count(FOCUS_NOTES[name].encode()), 1)


if __name__ == '__main__':
    unittest.main()
