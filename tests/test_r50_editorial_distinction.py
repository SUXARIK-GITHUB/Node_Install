"""r50: authored subject copy, independent FAQs and reading layouts, offline.

No network access, server writes, browser state or production dependencies.
"""
import re
import sys
import unittest
from html import escape
from pathlib import Path

from common import ROOT

sys.path.insert(0, str(ROOT / 'scripts'))
import cover_rich
import cover_rich_details
import cover_variants
import site_audit
import site_catalog
import site_practice


class EditorialIdentityR50(unittest.TestCase):
    DOMAIN = 'staging.example.test'

    def test_96_publications_have_384_curated_tasks_and_288_unique_questions(self):
        self.assertEqual(set(site_catalog.BASE_NAMES), set(site_practice.SITE_PRACTICE))
        self.assertEqual(set(site_catalog.BASE_NAMES), set(site_practice.SITE_QUESTIONS))
        tasks = [p for row in site_practice.SITE_PRACTICE.values() for p in row]
        questions = [q for row in site_practice.SITE_QUESTIONS.values() for q in row]
        self.assertEqual(len(tasks), 384)
        self.assertEqual(len(set(tasks)), 384)
        self.assertTrue(all(len(p) >= 120 for p in tasks))
        self.assertEqual(len(questions), 288)
        self.assertEqual(len(set(questions)), 288)
        self.assertTrue(all(q.endswith('?') for q in questions))
        for name in site_catalog.BASE_NAMES:
            spec = site_catalog.THEMES[name]
            for paragraph in site_practice.SITE_PRACTICE[name]:
                ru = len(re.findall(r'[А-Яа-яЁё]{3,}', paragraph))
                en = len(re.findall(r'[A-Za-z]{3,}', paragraph))
                if spec.language == 'ru':
                    self.assertGreater(ru, en, name)
                else:
                    self.assertGreater(en, ru, name)
            for question in site_practice.SITE_QUESTIONS[name]:
                ru = len(re.findall(r'[А-Яа-яЁё]{3,}', question))
                en = len(re.findall(r'[A-Za-z]{3,}', question))
                if spec.language == 'ru':
                    self.assertGreater(ru, en, name)
                else:
                    self.assertGreater(en, ru, name)

    def test_catalog_journals_and_questions_use_authored_copy(self):
        for name in site_catalog.BASE_NAMES:
            spec = site_catalog.THEMES[name]
            bundle = site_catalog.render(name, self.DOMAIN)
            journal = bundle['journal.html'].decode('utf-8')
            questions = bundle['questions.html'].decode('utf-8')
            about = bundle['about.html'].decode('utf-8')
            self.assertNotIn('If you want to explore ', journal)
            self.assertNotIn('Для самостоятельной работы по теме ', journal)
            for i, note in enumerate(site_practice.SITE_PRACTICE[name]):
                self.assertIn(escape(note, quote=True), journal, (name, i))
                self.assertGreaterEqual(sum(map(len, site_catalog.article_copy(spec, i))), 300)
            for i, q in enumerate(site_practice.SITE_QUESTIONS[name]):
                displayed = f'{spec.subjects[i]}: {q}'
                self.assertIn('<summary>' + escape(displayed, quote=True) + '</summary>', questions)
            self.assertIn(escape(site_catalog.EDITORIAL_NOTES[name][1], quote=True), about)
            self.assertEqual(site_audit.audit_bundle(bundle, self.DOMAIN, True)['status'], 'PASS')

    def test_catalog_artwork_carries_topic_and_six_reading_compositions(self):
        compositions = set()
        for name in site_catalog.BASE_NAMES:
            spec = site_catalog.THEMES[name]
            bundle = site_catalog.render(name, self.DOMAIN)
            home = bundle['index.html'].decode('utf-8')
            compositions.add(site_catalog.composition(spec))
            self.assertIn('class="hero-art"', home)
            self.assertIn('<text x="55" y="442"', home)
            self.assertIn(escape(spec.subjects[0], quote=True) + '</text>', home)
            css = bundle['style.css'].decode('utf-8')
            self.assertIn('.composition-' + site_catalog.composition(spec), css)
            self.assertIn('.inner-body .article', css)
            self.assertNotIn('/*', css)
        self.assertEqual(compositions, set(site_catalog.COMPOSITIONS))

    def test_12_classics_have_unique_longreads_and_functional_table_of_contents(self):
        self.assertEqual(set(cover_variants.NAMES), set(cover_rich_details.RICH_DETAILS))
        details = [p for row in cover_rich_details.RICH_DETAILS.values() for p in row]
        self.assertEqual(len(details), 60)
        self.assertEqual(len(set(details)), 60)
        for name in cover_variants.NAMES:
            bundle = cover_rich.render_rich(name, self.DOMAIN)
            journal = bundle['journal.html'].decode('utf-8')
            self.assertIn('id="rich-index"', journal)
            self.assertEqual(journal.count('href="#rich-index"'), 5)
            for i, paragraph in enumerate(cover_rich_details.RICH_DETAILS[name], 1):
                self.assertIn(f'id="essay-{i}"', journal)
                self.assertIn(f'href="#essay-{i}"', journal)
                self.assertIn(escape(paragraph, quote=True), journal)
            self.assertEqual(site_audit.audit_bundle(bundle, self.DOMAIN, True)['status'], 'PASS')

    def test_all_120_public_bundles_keep_file_contract_and_inert_resources(self):
        for name in cover_variants.NAMES + site_catalog.NAMES:
            bundle = cover_rich.render_rich(name, self.DOMAIN)
            self.assertEqual(set(bundle), site_audit.RICH)
            self.assertEqual(site_audit.audit_bundle(bundle, self.DOMAIN, True)['status'], 'PASS')
            for path, content in bundle.items():
                self.assertFalse(site_audit.PUBLIC_TECH.search(content.decode()), (name, path))
                self.assertNotIn(b'<!--', content)
                if path.endswith('.html'):
                    self.assertNotIn(b'<script', content.lower())
                    self.assertNotIn(b'<form', content.lower())


if __name__ == '__main__':
    unittest.main()
