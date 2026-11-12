#!/usr/bin/env python3
"""Read-only publication readiness audit for all 120 static site bundles.

Generates prospective domain-bound bundles, validates local links and CSP,
compares the checked-in catalog bytes with the generators and verifies the
legacy handcrafted sources. No server access, DNS, deployment or mutation.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys

try:
    from cover_variants import NAMES as CLASSICS, render as render_classic
    from cover_rich import render_rich
    from site_catalog import NAMES as CATALOG, ROOT, render as render_catalog
    from site_audit import audit_bundle, RICH
    from site_art_direction import validate as validate_directions
    from site_catalog import BASE_NAMES
except ImportError:
    from scripts.cover_variants import NAMES as CLASSICS, render as render_classic
    from scripts.cover_rich import render_rich
    from scripts.site_catalog import NAMES as CATALOG, ROOT, render as render_catalog, BASE_NAMES
    from scripts.site_audit import audit_bundle, RICH
    from scripts.site_art_direction import validate as validate_directions


DEFAULT_DOMAIN = 'preview.example.test'


def scan(domain=DEFAULT_DOMAIN):
    validate_directions(BASE_NAMES)
    names = CLASSICS + CATALOG
    if len(names) != 120 or len(set(names)) != 120:
        raise ValueError('120_THEME_CATALOG_BROKEN')
    counts = Counter()
    rows = []
    for name in names:
        bundle = render_rich(name, domain)
        result = audit_bundle(bundle, domain, rich=True)
        if result['status'] != 'PASS' or set(bundle) != RICH:
            raise ValueError(name + ':BAD_PUBLICATION_BUNDLE')
        counts['audited_bundles'] += 1
        counts['audited_pages'] += sum(f.endswith('.html') for f in bundle)
        counts['audited_resources'] += len(bundle)
        if name in CATALOG:
            expected = render_catalog(name, domain)
            if bundle != expected:
                raise ValueError(name + ':RICH_RENDER_MISMATCH')
            # Static checked-in copies are for the documented preview domain.
            if domain == DEFAULT_DOMAIN:
                directory = ROOT / 'site-catalog' / name
                if not directory.is_dir() or {p.name for p in directory.iterdir()} != set(bundle):
                    raise ValueError(name + ':STATIC_FILESET_MISMATCH')
                for filename, data in bundle.items():
                    if not (directory / filename).is_file() or (directory / filename).is_symlink():
                        raise ValueError(name + ':INVALID_STATIC_RESOURCE_' + filename)
                    if (directory / filename).read_bytes() != data:
                        raise ValueError(name + ':OUTDATED_STATIC_' + filename)
                counts['static_site_copies_checked'] += 1
        else:
            original = render_classic(name, domain)
            for filename, data in original.items():
                path = ROOT / 'cover-variants' / name / filename
                if not path.is_file() or path.is_symlink() or (domain == DEFAULT_DOMAIN and path.read_bytes() != data):
                    raise ValueError(name + ':ORIGINAL_COVER_MISMATCH_' + filename)
            counts['original_cover_contracts_checked'] += 1
        rows.append({'theme': name, 'category': 'classic' if name in CLASSICS else 'catalog',
                     'rich_pages': 5, 'bundle_files': len(bundle), 'status': 'OFFLINE_PASS'})
    return {'schema':1, 'release':'r57 offline prepublication review',
            'scope':'120 prospective bundles and committed catalog; no live host',
            'domain':domain, 'checks':dict(counts), 'status':'OFFLINE_PASS',
            'limitations':['No real public HTTPS/TLS, DNS, certificate or Nginx inspection',
                           'No live site, no live domain, no deployment transaction performed',
                           'Static checks do not replace human editorial and visual review'],
            'sites':rows}


def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--domain',default=DEFAULT_DOMAIN)
    ap.add_argument('--output',type=Path)
    ns=ap.parse_args(argv)
    try:
        report=scan(ns.domain)
        if ns.output:
            if ns.output.exists() or ns.output.is_symlink() or not ns.output.parent.is_dir():
                raise ValueError('REPORT_DESTINATION_MUST_BE_NEW')
            ns.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    except (OSError, ValueError, TypeError) as exc:
        print('SITE_PUBLICATION_REVIEW=FAIL '+str(exc),file=sys.stderr)
        return 1
    print(json.dumps({key:value for key,value in report.items() if key != 'sites'},ensure_ascii=False))
    return 0

if __name__=='__main__':
    sys.exit(main())
