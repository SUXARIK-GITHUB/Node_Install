#!/usr/bin/env python3
"""Honest editorial inventory for static websites; not an automated quality verdict.

A passing link/CSP/visual test is not proof of valuable writing. This report
separates handcrafted in-depth specimens from still-shallow catalog entries.
It neither modifies files nor contacts the Internet.
"""
import argparse
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys

try:
    from site_catalog import BASE_NAMES, NAMES as CATALOG, THEMES
    from cover_variants import NAMES as CLASSICS
    from cover_rich import render_rich
    from site_identity import EXHIBITS, architecture
    from site_workbooks import WORKBOOKS
    from site_workbooks_r53 import RECORDS as R53_RECORDS
except ImportError:
    from scripts.site_catalog import BASE_NAMES, NAMES as CATALOG, THEMES
    from scripts.cover_variants import NAMES as CLASSICS
    from scripts.cover_rich import render_rich
    from scripts.site_identity import EXHIBITS, architecture
    from scripts.site_workbooks import WORKBOOKS
    from scripts.site_workbooks_r53 import RECORDS as R53_RECORDS


R53_NAMES = frozenset(row.split("|", 1)[0] for row in R53_RECORDS.strip().splitlines())
R52_NAMES = frozenset(WORKBOOKS) - R53_NAMES


class Words(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.depth = 0
        self.parts = []
        self.excluded = 0
    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self.excluded += 1
        if tag == 'main':
            self.depth += 1
    def handle_endtag(self, tag):
        if tag == 'main':
            self.depth -= 1
        if tag in ('script', 'style'):
            self.excluded -= 1
    def handle_data(self, data):
        if self.depth > 0 and self.excluded == 0:
            self.parts.append(data)


def words(data):
    p = Words()
    p.feed(data.decode('utf-8'))
    return len(re.findall(r"[\wА-Яа-яЁё]+(?:[-'][\wА-Яа-яЁё]+)*", ' '.join(p.parts), re.U))


def scan(domain='preview.example.test'):
    rows = []
    for name in CLASSICS + CATALOG:
        b = render_rich(name, domain)
        measurements = {p: words(b[p]) for p in ('index.html', 'journal.html', 'about.html', 'questions.html')}
        baseline = name in BASE_NAMES
        identity = architecture(THEMES[name]) if baseline else 'separate-design'
        original_exhibit = name in EXHIBITS
        practical_workbook = name in WORKBOOKS
        handcrafted = original_exhibit or practical_workbook
        notes = []
        if measurements['index.html'] < 250:
            notes.append('HOME_CONTENT_LIGHT')
        if measurements['journal.html'] < 450:
            notes.append('COLLECTION_CONTENT_LIGHT')
        if measurements['about.html'] < 140:
            notes.append('ABOUT_CONTENT_LIGHT')
        if not handcrafted:
            notes.append('NO_CURATED_DEEP_DIVE')
        rows.append({'site':name,'collection':'catalog' if baseline else 'signature' if name in CATALOG else 'classic',
                     'architecture':identity, 'r51_hand_edited_exhibit':original_exhibit,'r52_practical_workbook':name in R52_NAMES, 'r53_practical_workbook':name in WORKBOOKS and name not in R52_NAMES,
                     'curated_substantive_section':handcrafted,
                     'words':measurements, 'flags':notes,
                     'editorial_review': 'REQUIRED'})
    assert len(rows) == 120
    return {
        'schema': 1,
        'release': 'r56 staging; 120 authored focus notes and fuller reading paths; independent editorial review required',
        'total_sites': len(rows),
        'catalog_layouts': len(set(x['architecture'] for x in rows if x['collection'] == 'catalog')),
        'sites_with_r51_hand_edited_exhibit': sum(x['r51_hand_edited_exhibit'] for x in rows),
        'sites_with_r52_practical_workbook': sum(x['r52_practical_workbook'] for x in rows),
        'sites_with_r53_practical_workbook': sum(x['r53_practical_workbook'] for x in rows),
        'sites_with_new_curated_longform': sum(x['curated_substantive_section'] for x in rows),
        'sites_with_r56_authored_focus': len(rows),
        'sites_passing_descriptive_content_length_signals': sum(not x['flags'] for x in rows),
        'sites_requiring_independent_editorial_review': len(rows),
        'interpretation': 'Word counts are descriptive review signals, not a Google ranking requirement or a substitute for expert editorial checks.',
        'sites': rows,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path)
    args = ap.parse_args(argv)
    data = scan()
    content=json.dumps(data,ensure_ascii=False,indent=2,sort_keys=True)+'\n'
    if args.output:
        if args.output.is_symlink() or args.output.is_dir():
            ap.error('not a regular output path')
        args.output.write_text(content,encoding='utf-8')
    print(json.dumps({k:v for k,v in data.items() if k != 'sites'},ensure_ascii=False))
    return 0

if __name__ == '__main__':
    sys.exit(main())
