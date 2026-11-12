"""r46: subject-specific articles and accessible navigation, offline only."""
from collections import Counter
from html import escape
from html.parser import HTMLParser
from pathlib import Path
import re
import sys
import unittest

from common import ROOT
sys.path.insert(0,str(ROOT/'scripts'))
import site_catalog
import signature_sites
import site_audit
from site_field_guides import FIELD_GUIDES, SIGNATURE_FIELD_GUIDES
from site_editorial import EDITORIAL_NOTES


class ArticleParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.inside = False
        self.capture = False
        self.current = []
        self.articles = []
        self.paragraphs = []
        self.lang = None
        self.skip_labels = []
        self.skip = False
    def handle_starttag(self,tag,attrs):
        d = dict(attrs)
        if tag=='html': self.lang=d.get('lang')
        if tag=='a' and 'skip' in d.get('class','').split():
            self.skip=True
        if tag=='article' and ('article' in d.get('class','').split() or 'longread' in d.get('class','').split()):
            self.inside=True; self.current=[]
        if tag=='p' and self.inside:
            self.capture=True; self.paragraphs=[]
    def handle_data(self,data):
        if self.capture: self.paragraphs.append(data)
        if self.skip: self.skip_labels.append(data)
    def handle_endtag(self,tag):
        if tag=='p' and self.capture:
            self.current.append(''.join(self.paragraphs).strip());self.capture=False
        if tag=='a': self.skip=False
        if tag=='article' and self.inside:
            self.articles.append(self.current);self.inside=False


class SiteContentRegression(unittest.TestCase):
    DOMAIN='review.example.test'

    def test_editorial_stays_complete_and_topic_specific(self):
        self.assertEqual(set(site_catalog.BASE_NAMES),set(FIELD_GUIDES))
        self.assertEqual(set(FIELD_GUIDES),set(EDITORIAL_NOTES))
        self.assertEqual(len(FIELD_GUIDES),96)
        self.assertEqual(len(SIGNATURE_FIELD_GUIDES),12)
        self.assertEqual(set(SIGNATURE_FIELD_GUIDES),set(signature_sites.SIGNATURES))
        values=[v for row in FIELD_GUIDES.values() for v in row]
        self.assertEqual(len(values),384)
        self.assertEqual(len(set(values)),384)
        self.assertTrue(all(len(v)>=100 for v in values))
        self.assertEqual(len(set(v for row in SIGNATURE_FIELD_GUIDES.values() for v in row)),48)

    def test_article_paragraphs_are_not_recycled(self):
        paragraphs=[]; article_count=0
        for name in site_catalog.BASE_NAMES:
            spec=site_catalog.THEMES[name]
            doc=site_catalog.render(name,self.DOMAIN)['journal.html'].decode()
            parser=ArticleParser();parser.feed(doc)
            self.assertEqual(len(parser.articles),4)
            self.assertEqual(parser.lang,spec.language)
            for i,article in enumerate(parser.articles):
                self.assertEqual(len(article),4)  # lead, detailed field note, exercise, local next link
                narrative=article[:3]
                self.assertGreaterEqual(sum(map(len,narrative)),300,(name,i))
                self.assertIn(FIELD_GUIDES[name][i],narrative)
                paragraphs.extend(narrative)
                article_count+=1
        self.assertEqual(article_count,384)
        self.assertEqual(len(paragraphs),len(set(paragraphs)))

    def test_site_language_matches_new_field_guide_language(self):
        for name in site_catalog.BASE_NAMES:
            lang=site_catalog.THEMES[name].language
            for note in FIELD_GUIDES[name]:
                russian=len(re.findall('[А-Яа-яЁё]{3,}',note))
                english=len(re.findall('[A-Za-z]{3,}',note))
                with self.subTest(name=name):
                    if lang=='ru':self.assertGreater(russian,english)
                    else:self.assertGreater(english,russian)
        for name,spec in signature_sites.SIGNATURES.items():
            for note in SIGNATURE_FIELD_GUIDES[name]:
                russian=len(re.findall('[А-Яа-яЁё]{3,}',note))
                english=len(re.findall('[A-Za-z]{3,}',note))
                if spec.language=='ru':self.assertGreater(russian,english)
                else:self.assertGreater(english,russian)

    def test_signature_journal_extends_existing_original_copy(self):
        for name,spec in signature_sites.SIGNATURES.items():
            doc=site_catalog.render(name,self.DOMAIN)['journal.html'].decode()
            parser=ArticleParser();parser.feed(doc)
            self.assertEqual(len(parser.articles),4)
            for i,article in enumerate(parser.articles):
                self.assertEqual(len(article),3)  # kicker, original paragraph, new subject-specific detail
                self.assertIn(SIGNATURE_FIELD_GUIDES[name][i],article)
                self.assertGreaterEqual(sum(map(len,article[1:])),180)
                self.assertIn(escape(spec.cards[i][1],quote=True),doc)

    def test_skip_link_labels_match_actual_destination(self):
        for name in site_catalog.NAMES:
            spec=site_catalog.THEMES[name]
            label='К основному содержимому' if spec.language=='ru' else 'Skip to main content'
            for page in ('index.html','journal.html','about.html','questions.html','404.html'):
                doc=site_catalog.render(name,self.DOMAIN)[page].decode()
                with self.subTest(name=name,page=page):
                    self.assertIn(f'<a class="skip" href="#main">{label}</a>',doc)
                    self.assertIn('<main id="main">',doc)
                    self.assertNotIn('<a class="skip" href="#main">Back to home</a>',doc)

    def test_all_catalog_urls_and_resources_are_preserved(self):
        expected=set(('index.html','journal.html','about.html','questions.html','404.html',
                      'style.css','favicon.svg','robots.txt','sitemap.xml'))
        for name in site_catalog.NAMES:
            with self.subTest(name=name):
                content=site_catalog.render(name,self.DOMAIN)
                self.assertEqual(set(content),expected)
                self.assertEqual(site_audit.audit_bundle(content,self.DOMAIN,rich=True)['status'],'PASS')

    def test_generated_artifacts_match_checked_in_snapshots(self):
        for name in site_catalog.NAMES:
            content=site_catalog.render(name)
            directory=ROOT/'site-catalog'/name
            with self.subTest(name=name):
                self.assertEqual({x.name for x in directory.iterdir()},set(content))
                for fn,data in content.items():self.assertEqual((directory/fn).read_bytes(),data)

    def test_skip_link_audit_rejects_malformed_anchor(self):
        name='33-coffee-roastery'
        content=site_catalog.render(name,self.DOMAIN)
        bad=dict(content)
        bad['index.html']=bad['index.html'].replace(b'href="#main"',b'href="#missing"')
        with self.assertRaisesRegex(ValueError,'INVALID_SKIP_LINK'):
            site_audit.audit_bundle(bad,self.DOMAIN,rich=True)


if __name__=='__main__':unittest.main()
