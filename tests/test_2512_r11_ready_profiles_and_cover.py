"""R11 offline regressions: three operator exports and static-site hardening.

All paths are sandboxed. No apt, network, Docker, UFW, SSH or live Nginx writes.
"""
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch
from common import ROOT, SCRIPT, module, payload


class ThemeParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.tabs = []
        self.links = []
        self.tags = []
    def handle_starttag(self, tag, attrs):
        props = dict(attrs)
        self.tags.append(tag)
        if props.get('id'): self.ids.add(props['id'])
        if tag == 'a': self.links.append(props.get('href', ''))
        if tag == 'link': self.tabs.append(props.get('href', ''))


class EditorialThemeTests(unittest.TestCase):
    def test_all_twelve_self_contained_unique_themes(self):
        root = ROOT / 'cover-variants'
        expected = {'01-atelier', '02-archive', '03-observatory',
                    '04-fieldnotes', '05-readingroom', '06-foundry',
                    '07-botanica', '08-nocturne', '09-kitchen',
                    '10-atlas', '11-tides', '12-cinema'}
        self.assertEqual({x.name for x in root.iterdir() if x.is_dir()}, expected)
        arts = set()
        for name in sorted(expected):
            with self.subTest(theme=name):
                page = (root / name / 'index.html').read_text(encoding='utf-8')
                css = (root / name / 'style.css').read_text(encoding='utf-8')
                doc = ThemeParser(); doc.feed(page); doc.close()
                self.assertEqual(set(doc.tabs), {'style.css', 'favicon.svg'})
                self.assertTrue({'start', 'features', 'notes', 'about', 'faq'} <= doc.ids)
                for href in doc.links:
                    self.assertTrue(href.startswith('#') and href[1:] in doc.ids, href)
                self.assertGreaterEqual(doc.tags.count('article'), 3)
                self.assertGreaterEqual(doc.tags.count('details'), 3)
                self.assertIn('<svg', page)
                arts.add(hashlib.sha256(page.split('<svg',1)[1].split('</svg>',1)[0].encode()).digest())
                self.assertIn('Content-Security-Policy', page)
                self.assertNotRegex(page.replace('xmlns="http://www.w3.org/2000/svg"', ''), r'(?i)<script\b|<iframe\b|<form\b|(?:https?:)?//|<img\b')
                self.assertNotIn('@import', css)
                self.assertNotIn('url(', css)
                self.assertIn('prefers-reduced-motion', css)
                self.assertLess(len(page.encode()) + len(css.encode()), 32 * 1024)
        self.assertEqual(len(arts), 12)

    def test_dynamic_site_has_nav_articles_no_external_assets(self):
        m = module('VK_SITE_TOOL_PY')
        for seed in ('0'*64,'3'*64, 'a'*64, 'f'*64):
            with self.subTest(seed=seed):
                data, assets = m.render('node.example.test', seed)
                page = data.decode()
                doc = ThemeParser();doc.feed(page);doc.close()
                self.assertTrue({'materials', 'questions', 'about'} <= doc.ids)
                self.assertGreaterEqual(doc.tags.count('article'), 3)
                self.assertGreaterEqual(doc.tags.count('details'), 2)
                for href in doc.links:
                    self.assertTrue(href.startswith('#'), href)
                self.assertNotRegex(page, r'(?i)<script\b|<iframe\b|<form\b|https?://')
                self.assertLess(len(data)+sum(map(len,assets.values())), 15000)
                self.assertEqual(len(assets), 2)


class PrivateExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vk-r11-private-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.m = module('PY_HELPER')
        self.m.ETC = self.base/'etc'
        self.m.ETC.mkdir(mode=0o700)
        self.m.XHTTP_EXPORT = self.base/'root/vkarmani-xhttp-profile.json'
        (self.base/'root').mkdir(mode=0o700)
        self.profile = {'inbounds':[{'tag':'VK_RAW_REALITY_ABCDEF123456', 'protocol':'vless',
                    'settings':{'flow':''},
                    'streamSettings':{'network':'xhttp','security':'reality',
                      'xhttpSettings':{'host':'node.example.test','mode':'auto','path':'/0123'}}}],
                    'outbounds':[], 'routing':{'rules':[]}}
        self.source = self.m.ETC/'profile-xhttp.json'
        self.source.write_text(json.dumps(self.profile,indent=2)+'\n')
        self.source.chmod(0o600)
        p = patch.object(self.m,'validate_profile',return_value=True)
        p.start();self.addCleanup(p.stop)
        self.config={'domain':'node.example.test'}

    def test_export_exact_bytes_mode_retries_and_no_live_changes(self):
        self.m.export_xhttp_profile(self.config)
        target=self.m.XHTTP_EXPORT
        self.assertEqual(target.read_bytes(),self.source.read_bytes())
        self.assertEqual(target.stat().st_mode & 0o777,0o600)
        old=target.read_bytes()
        self.m.export_xhttp_profile(self.config)
        self.assertEqual(target.read_bytes(),old)

    def test_missing_or_untrusted_source_fails_closed(self):
        self.source.unlink()
        with self.assertRaises(self.m.Failure):self.m.export_xhttp_profile(self.config)
        self.assertFalse(self.m.XHTTP_EXPORT.exists())
        self.source.symlink_to(self.base/'root')
        with self.assertRaises(self.m.Failure):self.m.export_xhttp_profile(self.config)

    def test_operator_edits_and_symlinks_refuse_overwrite(self):
        target=self.m.XHTTP_EXPORT
        target.write_text('OPERATOR_EDIT'); target.chmod(0o600)
        with self.assertRaisesRegex(self.m.Failure,'CHANGED_REFUSE_OVERWRITE'):
            self.m.export_xhttp_profile(self.config)
        self.assertEqual(target.read_text(),'OPERATOR_EDIT')
        target.unlink();target.symlink_to(self.source)
        with self.assertRaises(self.m.Failure):self.m.export_xhttp_profile(self.config)

    def test_source_duplicate_keys_and_invalid_flow_refused(self):
        self.source.write_text('{"inbounds":[],"inbounds":[]}')
        with self.assertRaises(self.m.Failure):self.m.export_xhttp_profile(self.config)
        self.source.write_text(json.dumps({**self.profile,'inbounds':[{**self.profile['inbounds'][0],
                  'settings':{'flow':'xtls-rprx-vision'}}]}))
        with self.assertRaisesRegex(self.m.Failure,'TRANSPORT_OR_FLOW_INVALID'):
            self.m.export_xhttp_profile(self.config)

    def test_cascade_does_not_export_xhttp(self):
        (self.m.ETC/'cascade-role.json').write_text('{}')
        with self.assertRaisesRegex(self.m.Failure,'CASCADE'):
            self.m.export_xhttp_profile(self.config)


class ReleaseGates(unittest.TestCase):
    def test_selfsteal_security_headers_and_no_new_external_proxy(self):
        self.assertIn('add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;',SCRIPT)
        self.assertIn('add_header Cross-Origin-Resource-Policy "same-origin" always;',SCRIPT)
        self.assertIn('NGINX_SELFSTEAL_HTTPS_SOCKET=/run/vkarmani-selfsteal/nginx.sock', SCRIPT)
        self.assertIn("target = '/dev/shm/nginx.sock'", SCRIPT)
        self.assertIn('xver = 1', SCRIPT)
        self.assertNotIn('proxy_pass http://', SCRIPT.split('cat > /etc/nginx/conf.d/20-vkarmani-selfsteal.conf',1)[1].split('\nEOF',1)[0])

    def test_embedded_finalizer_equal_standalone_and_requires_validated_xhttp(self):
        self.assertEqual(payload('VK_FINALIZER_PY').strip(),
                         (ROOT/'integrations/finalize_install.py').read_text().strip())
        self.assertIn("reality-export-xhttp", payload('VK_FINALIZER_PY'))
        self.assertIn('ORDINARY_XHTTP_CORE_TESTED_TEMPLATE_REQUIRED', payload('VK_FINALIZER_PY'))
        self.assertIn('XHTTP_IMPORT_TEMPLATE_NOT_VALIDATED_BY_BUNDLED_CORE',SCRIPT)
        self.assertIn("if [[ $VK_CASCADE_ACTIVE -eq 1 ]]; then",SCRIPT)

    def test_readme_version_one_command_autoreboot_default(self):
        text=(ROOT/'README.md').read_text()
        head=text.split('\n---\n',1)[0]
        self.assertIn('2.5.15 r16',head)
        self.assertIn('2.5.13 r12', (ROOT/'CHANGELOG.md').read_text())
        self.assertNotIn('2.5.10 r7e',head)
        self.assertNotIn('локальный непубликованный staging ZIP r10',head)
        self.assertIn('vkarmani-xhttp-profile.json',head)
        self.assertIn('bash ./install.sh\n',head)
        self.assertNotIn('bash ./install.sh --no-reboot',head)


if __name__=='__main__':unittest.main()
