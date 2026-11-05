#!/usr/bin/env python3
"""Offline contract audit of original and opt-in rich cover bundles.

No external requests and no changes to the host. Only allow resolved local
links, immutable CSS/SVG, consistent domain metadata and valid HTML structure.
"""
import argparse
from html.parser import HTMLParser
import json
from pathlib import PurePosixPath
import re
import sys
from xml.etree import ElementTree

try:
    from cover_variants import NAMES, render, valid_domain
    from site_catalog import NAMES as CATALOG_NAMES
    from cover_rich import render_rich, PAGES
except ImportError:
    from scripts.cover_variants import NAMES, render, valid_domain
    from scripts.site_catalog import NAMES as CATALOG_NAMES
    from scripts.cover_rich import render_rich, PAGES

BASE = frozenset(('index.html', 'style.css', '404.html', 'favicon.svg'))
RICH = BASE | frozenset(PAGES) | frozenset(('robots.txt', 'sitemap.xml'))
BAD_HTML = re.compile(r'(?i)<\s*(?:script|iframe|form|object|embed|base|meta\s+http-equiv\s*=\s*["\']refresh)\b')
BAD_CSS = re.compile(r'(?i)@import\b|url\s*\(|expression\s*\(')


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids = set()
        self.refs = []
        self.title = False
        self.main = False
        self.nav = False
        self.csp = False
        self.viewport = False

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if 'id' in d:
            if d['id'] in self.ids:
                raise ValueError('DUPLICATE_ID')
            self.ids.add(d['id'])
        self.main |= tag == 'main'
        self.nav |= tag == 'nav'
        self.title |= tag == 'title'
        if tag == 'meta':
            self.viewport |= d.get('name') == 'viewport'
            self.csp |= (d.get('http-equiv') == 'Content-Security-Policy' and
                         "default-src 'none'" in d.get('content', ''))
        for field in ('href', 'src', 'action'):
            if field in d:
                self.refs.append(d[field])

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)


def check_links(bundle, documents):
    for name, doc in documents.items():
        page = doc['page']
        for ref in page.refs:
            if not isinstance(ref, str) or any(x in ref for x in ('\\', '?', '%', '\r', '\n')):
                raise ValueError(name + ':INVALID_URL')
            if '://' in ref or ref.startswith('//') or ref.startswith('data:'):
                raise ValueError(name + ':EXTERNAL_REFERENCE')
            pathname, sep, frag = ref.partition('#')
            if not pathname:
                if sep and frag not in page.ids:
                    raise ValueError(name + ':UNKNOWN_ANCHOR')
                continue
            if pathname == '/':
                target = 'index.html'
            else:
                value = pathname.lstrip('/')
                norm = PurePosixPath(value)
                if not value or '/' in value or norm.name != value or value.startswith('.'):
                    raise ValueError(name + ':UNSAFE_REFERENCE')
                target = value
            if target not in bundle:
                raise ValueError(name + ':BROKEN_REFERENCE_' + target)
            if sep and (target not in documents or frag not in documents[target]['page'].ids):
                raise ValueError(name + ':UNKNOWN_TARGET_ANCHOR')


def audit_bundle(bundle, domain, rich=False):
    valid_domain(domain)
    wanted = RICH if rich else BASE
    if not isinstance(bundle, dict) or set(bundle) != wanted:
        raise ValueError('INVALID_BUNDLE_FILESET')
    for name, content in bundle.items():
        if not isinstance(content, bytes) or not content or len(content) > 128 * 1024:
            raise ValueError(name + ':INVALID_CONTENT_LENGTH')
    css = bundle['style.css'].decode('utf-8')
    if BAD_CSS.search(css):
        raise ValueError('REMOTE_OR_EXECUTABLE_CSS')
    icon = bundle['favicon.svg'].decode('utf-8')
    if not icon.lstrip().startswith('<svg') or re.search(r'(?i)<script|<foreignobject|https?://(?!www\.w3\.org/2000/svg)', icon):
        raise ValueError('UNSAFE_SVG')
    documents = {}
    for name, content in bundle.items():
        if not name.endswith('.html'):
            continue
        body = content.decode('utf-8')
        if BAD_HTML.search(body):
            raise ValueError(name + ':UNSAFE_HTML')
        parsed = Page()
        parsed.feed(body)
        parsed.close()
        if not parsed.title or not parsed.viewport or not parsed.csp or not parsed.main:
            raise ValueError(name + ':INCOMPLETE_HTML')
        if name != '404.html' and not parsed.nav:
            # Existing original single-page cover uses a nav, as do rich pages.
            raise ValueError(name + ':MISSING_NAVIGATION')
        documents[name] = {'page': parsed}
    check_links(bundle, documents)
    if rich:
        sitemap = bundle['sitemap.xml'].decode('utf-8')
        xml = ElementTree.fromstring(sitemap)
        namespace = '{http://www.sitemaps.org/schemas/sitemap/0.9}'
        found = {el.text for el in xml.findall('.//' + namespace + 'loc')}
        expected = {f'https://{domain}/{path}' for path in ('',) + PAGES}
        if found != expected:
            raise ValueError('SITEMAP_DOMAIN_OR_ROUTES_MISMATCH')
        if bundle['robots.txt'] != f'User-agent: *\nAllow: /\nSitemap: https://{domain}/sitemap.xml\n'.encode():
            raise ValueError('ROBOTS_SITEMAP_MISMATCH')
    return {'status': 'PASS', 'domain': domain, 'pages': len(documents),
            'files': len(bundle), 'total_bytes': sum(map(len, bundle.values())),
            'rich': rich, 'network_requests': 0}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--domain', default='preview.example.test')
    parser.add_argument('--theme', choices=NAMES + CATALOG_NAMES)
    parser.add_argument('--rich', action='store_true')
    args = parser.parse_args(argv)
    themes = (args.theme,) if args.theme else (NAMES + CATALOG_NAMES if args.rich else NAMES)
    if args.theme in CATALOG_NAMES and not args.rich:
        parser.error('R21 catalog themes require --rich (full multi-page bundle)')
    try:
        results = [audit_bundle(render_rich(n, args.domain) if args.rich else
                                render(n, args.domain), args.domain, args.rich)
                   for n in themes]
    except (ValueError, TypeError, UnicodeError, ElementTree.ParseError) as exc:
        print('SITE_AUDIT=FAIL ' + type(exc).__name__ + ': ' + str(exc), file=sys.stderr)
        return 1
    print(json.dumps({'status': 'PASS', 'themes': len(results), 'rich': args.rich,
                      'files_audited': sum(x['files'] for x in results),
                      'pages_audited': sum(x['pages'] for x in results)},
                     ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
