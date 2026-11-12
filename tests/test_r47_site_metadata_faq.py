"""r47 offline release gate for owned domains, credible topical FAQs and privacy.

Tests in-memory trusted generators only; no network, VPS or privileges needed.
"""
from html.parser import HTMLParser
from pathlib import Path
import sys
import unittest

from common import ROOT
sys.path.insert(0, str(ROOT / 'scripts'))
import cover_variants
import cover_rich
import site_catalog
import site_audit
import site_metadata
import signature_sites


class FAQParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.questions = []
        self.answers = []
        self.current = None
        self.buffer = []

    def handle_starttag(self, tag, attrs):
        if tag in ('summary', 'p') and self.current is None:
            self.current = tag
            self.buffer = []

    def handle_data(self, data):
        if self.current:
            self.buffer.append(data)

    def handle_endtag(self, tag):
        if self.current == tag:
            text = ''.join(self.buffer).strip()
            if tag == 'summary':
                self.questions.append(text)
            elif text:
                self.answers.append(text)
            self.current = None
            self.buffer = []


class R47CoverRegression(unittest.TestCase):
    DOMAIN = 'owned.example.test'

    def test_all_120_site_families_have_domain_bound_public_metadata(self):
        all_names = cover_variants.NAMES + site_catalog.NAMES
        self.assertEqual(len(all_names), 120)
        for name in all_names:
            with self.subTest(name=name):
                bundle = cover_rich.render_rich(name, self.DOMAIN)
                self.assertEqual(site_audit.audit_bundle(bundle, self.DOMAIN, rich=True)['status'], 'PASS')
                for path in ('index.html', 'journal.html', 'about.html', 'questions.html'):
                    doc = bundle[path].decode()
                    expected = 'https://' + self.DOMAIN + '/' + ('' if path == 'index.html' else path)
                    self.assertIn(f'<link rel="canonical" href="{expected}">', doc)
                    self.assertIn(f'<meta property="og:url" content="{expected}">', doc)
                    self.assertIn('<meta property="og:description"', doc)
                    self.assertNotIn('preview.example.test', doc)
                error = bundle['404.html'].decode()
                self.assertIn('<meta name="robots" content="noindex,follow">', error)
                self.assertNotIn('rel="canonical"', error)
                self.assertNotIn('property="og:url"', error)

    def test_96_questions_pages_have_real_subject_answers_in_correct_language(self):
        question_sets = set()
        for name in site_catalog.BASE_NAMES:
            spec = site_catalog.THEMES[name]
            doc = site_catalog.render(name, self.DOMAIN)['questions.html'].decode()
            parser = FAQParser()
            parser.feed(doc)
            # Three original subject FAQs remain first; r56 adds four
            # original research/readership prompts after them.
            self.assertEqual(len(parser.questions), 7, name)
            self.assertGreaterEqual(len(parser.answers), 7, name)
            for i, question in enumerate(parser.questions[:3]):
                self.assertIn(spec.subjects[i].casefold(), question.casefold(), name)
                self.assertGreaterEqual(len(question), 25, name)
            self.assertEqual(len(set(parser.questions)), 7, name)
            for question in parser.questions[3:]:
                self.assertGreaterEqual(len(question), 20, name)
            for answer in parser.answers[-3:]:
                self.assertGreaterEqual(len(answer), 35, name)
            question_sets.add(tuple(parser.questions))
            self.assertIn('lang="' + spec.language + '"', doc)
            self.assertIn('rel="canonical"', doc)
        self.assertEqual(len(question_sets), 96)

    def test_original_routes_and_styles_are_preserved(self):
        for name in cover_variants.NAMES + site_catalog.NAMES:
            bundle = cover_rich.render_rich(name, self.DOMAIN)
            self.assertEqual(set(bundle), site_audit.RICH)
            self.assertEqual(bundle['robots.txt'],
                             f'User-agent: *\nAllow: /\nSitemap: https://{self.DOMAIN}/sitemap.xml\n'.encode())
        for name in cover_variants.NAMES:
            static = (ROOT/'cover-variants'/name/'style.css').read_bytes()
            generated = cover_variants.render(name, self.DOMAIN)['style.css']
            # R55 keeps handmade styling identical while the *single* trailing
            # domain override legitimately differs between domains.
            self.assertEqual(cover_variants.remove_generated_vars(static),
                             cover_variants.remove_generated_vars(generated))
            self.assertEqual(static.count(b':root{--accent:hsl('),1)
            self.assertEqual(generated.count(b':root{--accent:hsl('),1)

    def test_catalog_snapshots_match_generators(self):
        for name in site_catalog.NAMES:
            for path, value in site_catalog.render(name).items():
                self.assertEqual((ROOT/'site-catalog'/name/path).read_bytes(), value, (name, path))
        for name in cover_variants.NAMES:
            for path, value in cover_variants.render(name, 'preview.example.test').items():
                if path != 'style.css':
                    self.assertEqual((ROOT/'cover-variants'/name/path).read_bytes(), value, (name, path))

    def test_rejects_wrong_canonical_and_duplicate(self):
        bundle = cover_rich.render_rich('33-coffee-roastery', self.DOMAIN)
        changed = dict(bundle)
        changed['journal.html'] = changed['journal.html'].replace(
            b'https://owned.example.test/journal.html', b'https://other.example.test/journal.html', 1)
        with self.assertRaisesRegex(ValueError, 'CANONICAL_URL_MISMATCH'):
            site_audit.audit_bundle(changed, self.DOMAIN, rich=True)
        changed = dict(bundle)
        changed['index.html'] = changed['index.html'].replace(b'</head>',
            b'<link rel="canonical" href="https://owned.example.test/"></head>')
        with self.assertRaisesRegex(ValueError, 'CANONICAL_URL_MISMATCH'):
            site_audit.audit_bundle(changed, self.DOMAIN, rich=True)

    def test_rejects_og_url_and_missing_404_noindex(self):
        bundle = cover_rich.render_rich('111-atlas-docs', self.DOMAIN)
        changed = dict(bundle)
        changed['about.html'] = changed['about.html'].replace(
            b'<meta property="og:url" content="https://owned.example.test/about.html">',
            b'<meta property="og:url" content="https://unowned.example.test/about.html">')
        with self.assertRaisesRegex(ValueError, 'OG_URL_MISMATCH'):
            site_audit.audit_bundle(changed, self.DOMAIN, rich=True)
        changed = dict(bundle)
        changed['404.html'] = changed['404.html'].replace(b'<meta name="robots" content="noindex,follow">', b'')
        with self.assertRaisesRegex(ValueError, 'ERROR_PAGE_INDEXING_METADATA'):
            site_audit.audit_bundle(changed, self.DOMAIN, rich=True)

    def test_metadata_helper_rejects_invalid_hosts_routes_and_html_escapes(self):
        kwargs = dict(domain=self.DOMAIN, route='', site_name='Art & Books',
                      title='Notes <2026>', description='Food & wine "notes"')
        out = site_metadata.head(**kwargs)
        self.assertIn('Art &amp; Books', out)
        self.assertIn('Notes &lt;2026&gt;', out)
        self.assertIn('Food &amp; wine &quot;notes&quot;', out)
        for domain in ('other.example.test/path', '127.0.0.1', 'UPPER.example.test', 'example.test\nwrong'):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                site_metadata.head(**{**kwargs, 'domain': domain})
        for route in ('../', '/admin', 'bad?param', '404.html'):
            with self.subTest(route=route), self.assertRaises(ValueError):
                site_metadata.head(**{**kwargs, 'route': route})

    def test_accessible_site_language_labels(self):
        for name in site_catalog.BASE_NAMES:
            spec = site_catalog.THEMES[name]
            index = site_catalog.render(name, self.DOMAIN)['index.html'].decode()
            expected = 'Авторская иллюстрация:' if spec.language == 'ru' else 'Original illustration:'
            self.assertIn(expected, index)
        for name, spec in signature_sites.SIGNATURES.items():
            index = signature_sites.render_signature(name, self.DOMAIN)['index.html'].decode()
            expected = 'Авторская иллюстрация:' if spec.language == 'ru' else 'Original illustrated study:'
            if '<svg ' in index:
                self.assertIn(expected, index)
            expected_nav = 'Навигация по сайту' if spec.language == 'ru' else 'Site navigation'
            self.assertIn('aria-label="' + expected_nav + '"', index)


if __name__ == '__main__':
    unittest.main()
