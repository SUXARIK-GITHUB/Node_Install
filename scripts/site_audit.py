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
# Public bundles must not disclose internal tooling, transport or hosting details.
# Check only the bytes actually published; private maintainers' docs are not sites.
PUBLIC_TECH = re.compile(
    r'(?i)(?<![\w])(?:vpn|vless|xray|reality|remnawave|wireguard|openvpn|'
    r'xhttp|selfsteal|vkarmani|node[_-]?install|asn|dpi|tspu|rkn|proxy)(?![\w])'
    r'|впн|тспу|ркн|прокси|обход[а-яё\s-]{0,12}блокиров')
HTML_COMMENT = re.compile(r'<!--[\s\S]*?-->')
CSS_COMMENT = re.compile(r'/\*[\s\S]*?\*/')
# Narrow public-content regression gate; don't confuse legitimate design-topic
# words (prototype, example) with evidence that a site is a placeholder.
PLACEHOLDER = re.compile(r'(?i)демонстрационных и справочных целях|\bознакомительный характер\b|\bsmall editorial demonstration\b|\bfictional independent creative journal\b|\bthis is a test vpn\b|\bсайт в разработке\b|\bскоро открытие\b|\bдемонстрационная коллекция\b')



def _tech_scan_input(filename, public, domain):
    """Exempt only owned, exact URL metadata; never exempt editorial content.

    The downstream metadata and sitemap validators still compare the original
    unmodified bytes with the requested FQDN and approved routes. Avoid
    blanket `replace(domain)` as it could hide public text or foreign links.
    """
    if filename.endswith('.html') and filename != '404.html':
        route = '' if filename == 'index.html' else filename
        owned = f'https://{domain}/{route}'
        safe = f'https://site.example.test/{route}'
        public = public.replace(
            f'<link rel="canonical" href="{owned}">',
            f'<link rel="canonical" href="{safe}">')
        public = public.replace(
            f'<meta property="og:url" content="{owned}">',
            f'<meta property="og:url" content="{safe}">')
    elif filename == 'robots.txt':
        public = public.replace(
            f'Sitemap: https://{domain}/sitemap.xml\n',
            'Sitemap: https://site.example.test/sitemap.xml\n')
    elif filename == 'sitemap.xml':
        for route in ('',) + PAGES:
            public = public.replace(
                f'<loc>https://{domain}/{route}</loc>',
                f'<loc>https://site.example.test/{route}</loc>')
    return public


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
        self.skip_links = []
        self.language = None
        self.canonicals = []
        self.og = {}
        self.descriptions = []
        self.robots = []
        self.title_open = False
        self.title_text = []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == 'html':
            self.language = d.get('lang')
        if tag == 'a' and 'skip' in d.get('class', '').split():
            self.skip_links.append(d.get('href'))
        if 'id' in d:
            if d['id'] in self.ids:
                raise ValueError('DUPLICATE_ID')
            self.ids.add(d['id'])
        self.main |= tag == 'main'
        self.nav |= tag == 'nav'
        self.title |= tag == 'title'
        if tag == 'title':
            self.title_open = True
        is_canonical = (tag == 'link' and 'canonical' in d.get('rel', '').split())
        if is_canonical:
            self.canonicals.append(d.get('href'))
        if tag == 'meta':
            if d.get('name') == 'description':
                self.descriptions.append(d.get('content'))
            if d.get('name') == 'robots':
                self.robots.append(d.get('content'))
            if d.get('property', '').startswith('og:'):
                self.og.setdefault(d['property'], []).append(d.get('content'))
            self.viewport |= d.get('name') == 'viewport'
            self.csp |= (d.get('http-equiv') == 'Content-Security-Policy' and
                         "default-src 'none'" in d.get('content', ''))
        for field in ('href', 'src', 'action'):
            if field in d and not (field == 'href' and is_canonical):
                self.refs.append(d[field])

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_data(self, data):
        if self.title_open:
            self.title_text.append(data)

    def handle_endtag(self, tag):
        if tag == 'title':
            self.title_open = False


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
    # A failed content gate blocks staging publication before any file writes.
    for filename, content in bundle.items():
        public = content.decode('utf-8')
        if PUBLIC_TECH.search(_tech_scan_input(filename, public, domain)):
            raise ValueError(filename + ':PUBLIC_TECHNICAL_REFERENCE')
        if (HTML_COMMENT.search(public) or
                (filename.endswith('.css') and CSS_COMMENT.search(public))):
            raise ValueError(filename + ':PUBLIC_SOURCE_COMMENT')
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
        if PLACEHOLDER.search(body):
            raise ValueError(name + ':PUBLIC_PLACEHOLDER_COPY')
        parsed = Page()
        parsed.feed(body)
        parsed.close()
        if not parsed.title or not parsed.viewport or not parsed.csp or not parsed.main:
            raise ValueError(name + ':INCOMPLETE_HTML')
        if (parsed.skip_links or 'main' in parsed.ids) and (parsed.skip_links != ['#main'] or 'main' not in parsed.ids):
            raise ValueError(name + ':INVALID_SKIP_LINK')
        if parsed.language not in ('ru', 'en'):
            raise ValueError(name + ':INVALID_LANGUAGE')
        if name != '404.html' and not parsed.nav:
            # Existing original single-page cover uses a nav, as do rich pages.
            raise ValueError(name + ':MISSING_NAVIGATION')
        documents[name] = {'page': parsed}
    # A URL is public only if it is actually served through the reviewed Nginx
    # allowlist. Reject accidental preview domains, forged cross-domain
    # canonical/OG entries and duplicates before allowing a site deployment.
    for name, document in documents.items():
        page = document['page']
        if name == '404.html':
            if page.canonicals or page.og.get('og:url') or 'noindex' not in (page.robots[0] if len(page.robots) == 1 else ''):
                raise ValueError(name + ':ERROR_PAGE_INDEXING_METADATA')
            continue
        path = '' if name == 'index.html' else name
        expected = f'https://{domain}/{path}'
        if page.canonicals != [expected]:
            raise ValueError(name + ':CANONICAL_URL_MISMATCH')
        if page.og.get('og:url') != [expected]:
            raise ValueError(name + ':OG_URL_MISMATCH')
        title = ''.join(page.title_text).strip()
        if not title or page.og.get('og:title') != [title]:
            raise ValueError(name + ':OG_TITLE_MISMATCH')
        if len(page.descriptions) != 1 or not isinstance(page.descriptions[0], str) or not page.descriptions[0].strip():
            raise ValueError(name + ':MISSING_PAGE_DESCRIPTION')
        if page.og.get('og:description') != page.descriptions:
            raise ValueError(name + ':OG_DESCRIPTION_MISMATCH')
        if page.og.get('og:type') != ['website'] or len(page.og.get('og:site_name', [])) != 1:
            raise ValueError(name + ':INCOMPLETE_OG_METADATA')
        if page.robots and any('noindex' in str(x) for x in page.robots):
            raise ValueError(name + ':PUBLIC_PAGE_NOINDEX')
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
