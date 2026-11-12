"""r51: verify structural differences, curated content and editorial gap tracking."""
import sys
import unittest
from html import escape
from pathlib import Path
from common import ROOT
sys.path.insert(0,str(ROOT/'scripts'))
import site_catalog
import site_identity
import site_quality_review
import site_audit


class ContentArchitectureR51(unittest.TestCase):
    DOMAIN='preview.example.test'

    def test_96_publications_have_distinct_information_architectures(self):
        self.assertEqual(len(site_catalog.BASE_NAMES),96)
        self.assertEqual(len(set(x.layout for x in site_catalog.THEMES.values() if not x.layout.startswith('signature'))),16)
        seen = set()
        for name in site_catalog.BASE_NAMES:
            spec=site_catalog.THEMES[name]
            home=site_catalog.render(name,self.DOMAIN)['index.html'].decode()
            kind=site_identity.architecture(spec)
            self.assertIn('class="resource resource-'+kind+'"',home)
            self.assertGreaterEqual(home.count('href="journal.html#story-'),8)
            self.assertIn('class="resource-heading"',home)
            self.assertIn('class="practice-list"',site_catalog.render(name,self.DOMAIN)['about.html'].decode())
            seen.add(kind)
            self.assertEqual(site_audit.audit_bundle(site_catalog.render(name,self.DOMAIN),self.DOMAIN,True)['status'],'PASS')
        self.assertEqual(len(seen),7)

    def test_new_feature_articles_are_authored_topic_specific_and_match_language(self):
        self.assertEqual(len(site_identity.EXHIBITS),16)
        passages=[]
        for name, entry in site_identity.EXHIBITS.items():
            self.assertEqual(len(entry),4)
            spec=site_catalog.THEMES[name]
            page=site_catalog.render(name,self.DOMAIN)['journal.html'].decode()
            self.assertIn('id="special-study"',page)
            for item in entry:
                self.assertIn(escape(item,quote=True),page)
                passages.append(item)
                if spec.language=='ru':
                    self.assertGreater(len([w for w in item.split() if any('а'<=c.lower()<='я' for c in w)]),
                                       len([w for w in item.split() if any('a'<=c.lower()<='z' for c in w)]))
                else:
                    self.assertGreater(len([w for w in item.split() if any('a'<=c.lower()<='z' for c in w)]),
                                       len([w for w in item.split() if any('а'<=c.lower()<='я' for c in w)]))
        self.assertEqual(len(passages),len(set(passages)))

    def test_quality_inventory_does_not_mislabel_all_sites_as_complete(self):
        report=site_quality_review.scan()
        self.assertEqual(report['total_sites'],120)
        self.assertEqual(report['sites_with_r51_hand_edited_exhibit'],16)
        self.assertGreaterEqual(report['sites_with_new_curated_longform'],16)
        self.assertEqual(report['sites_requiring_independent_editorial_review'],120)
        self.assertEqual({x['editorial_review'] for x in report['sites']},{'REQUIRED'})
        # r56 adds substantive per-site reading guides; the old r51 short-page
        # warning is now superseded, without implying human editorial approval.
        self.assertFalse(any('COLLECTION_CONTENT_LIGHT' in x['flags'] for x in report['sites']))

if __name__=='__main__':unittest.main()
