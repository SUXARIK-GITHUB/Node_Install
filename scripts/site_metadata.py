#!/usr/bin/env python3
"""Pure, local HTML metadata for owned static editorial sites.

No network, client tracking, forms, JSON-LD business claims or arbitrary URLs.
Public URLs are derived only from an already validated node FQDN and one
allowlisted static route. Error pages are deliberately not indexed.
"""
from html import escape
import re

HOST = re.compile(r'(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
ROUTES = frozenset(('', 'journal.html', 'about.html', 'questions.html'))


def head(*, domain, route, site_name, title, description):
    """Provide canonical/OpenGraph metadata consistently for the four public routes."""
    if not isinstance(domain, str) or HOST.fullmatch(domain) is None or re.fullmatch(r'[0-9.]+', domain):
        raise ValueError('INVALID_CANONICAL_DOMAIN')
    if route not in ROUTES:
        raise ValueError('INVALID_CANONICAL_ROUTE')
    if not all(isinstance(s, str) and s.strip() for s in (site_name, title, description)):
        raise ValueError('EMPTY_PUBLIC_METADATA')
    # No user-entered paths, query strings or fragments: only owned published pages.
    url = f'https://{domain}/{route}'
    e = lambda s: escape(s, quote=True)
    return (f'<meta name="description" content="{e(description)}">'
            f'<link rel="canonical" href="{url}">'
            f'<meta property="og:type" content="website">'
            f'<meta property="og:title" content="{e(title)}">'
            f'<meta property="og:description" content="{e(description)}">'
            f'<meta property="og:url" content="{url}">'
            f'<meta property="og:site_name" content="{e(site_name)}">')


def not_found():
    """HTTP 404 pages have neither canonical URLs nor indexable claims."""
    return '<meta name="robots" content="noindex,follow">'
