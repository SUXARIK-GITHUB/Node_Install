#!/usr/bin/env python3
"""Choose a stable, reviewed cover for a new ordinary staging node.

A domain-derived theme avoids giving every new node the same default page.
This is deliberately NOT randomness, an anti-DPI claim, or a runtime change:
explicit --site-theme continues to take precedence, and an installed site's
selection is never recalculated. No DNS, machine identifiers or secrets read.
"""
import argparse
import hashlib
import sys
from pathlib import Path

# Python -I intentionally removes the script directory from sys.path. Limit
# reviewed imports to the verified bundle's own adjacent scripts directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from cover_variants import NAMES as HANDMADE
from site_catalog import NAMES as GENERATED, valid_domain

THEMES = tuple(sorted((*HANDMADE, *GENERATED)))
if len(THEMES) != 120 or len(set(THEMES)) != 120:
    raise RuntimeError('REVIEWED_CATALOG_INCOMPLETE')


def choose(domain):
    valid_domain(domain)
    if domain != domain.lower():
        raise ValueError('DOMAIN_MUST_BE_LOWERCASE')
    digest = hashlib.sha256(b'node-install-reviewed-cover-v1\0' + domain.encode('ascii')).digest()
    return THEMES[int.from_bytes(digest, 'big') % len(THEMES)]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--domain', required=True, help='validated public node FQDN')
    args = parser.parse_args(argv)
    try:
        print(choose(args.domain))
    except (ValueError, UnicodeError):
        print('STOP: INVALID_SITE_DEFAULT_DOMAIN', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
