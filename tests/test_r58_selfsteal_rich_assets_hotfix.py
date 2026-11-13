"""Regression: publishable rich-site links must satisfy the installed checker.

No host changes, no client keys, no network access. The actual embedded script
and actual page renderer are used rather than separate reimplementations.
"""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from cover_rich import render_rich
from selfsteal_checker_repair import (OLD_SHA256, NEW_SHA256, bundled_checker,
                                     sha256, RepairError, apply)

OPEN = "cat > '/usr/local/sbin/vkarmani-selfsteal-check' <<'VK_PAYLOAD_VK_WRITE_SELFSTEAL_CHECK'\n"
CLOSE = '\nVK_PAYLOAD_VK_WRITE_SELFSTEAL_CHECK'


def checker():
    text = (ROOT/'install.sh').read_text()
    payload = text.split(OPEN, 1)[1].split(CLOSE, 1)[0]
    namespace={'__name__':'local_checker_fixture'}
    exec(compile(payload, '<actual embedded checker>', 'exec'), namespace)
    return namespace


def active_html(theme='97-design-museum'):
    contents = render_rich(theme, 'cover.example.test')
    name = 'assets/style-' + hashlib.sha256(contents['style.css']).hexdigest()[:20] + '.css'
    html = contents['index.html'].replace(b'href="style.css"', b'href="/' + name.encode() + b'"')
    html = html.replace(b'href="favicon.svg"', b'href="/favicon.svg"')
    return html, name


class SelfstealRichAssets(unittest.TestCase):
    def test_actual_deploy_html_accepted_by_actual_embedded_checker(self):
        cls = checker()['Assets']
        # Cover both the catalog and a classic theme without a special-case domain.
        for theme in ('97-design-museum','01-atelier'):
            with self.subTest(theme=theme):
                html, name = active_html(theme)
                parser = cls()
                parser.feed(html.decode())
                parser.close()
                self.assertIn(name, parser.paths)
                self.assertEqual(len(parser.paths), 1)

    def test_original_versioned_relative_assets_still_supported(self):
        cls=checker()['Assets']; parser=cls()
        parser.feed('<link rel="stylesheet" href="assets/style-'+'a'*20+'.css">'
                    '<link rel="icon" href="assets/icon-'+'b'*20+'.svg">')
        self.assertEqual(len(parser.paths),2)

    def test_strictly_rejects_external_unhashed_or_traversal_assets(self):
        cls=checker()['Assets']
        invalid=[
            '<link rel="stylesheet" href="https://evil.invalid/assets/style-'+'a'*20+'.css">',
            '<link rel="stylesheet" href="style.css">',
            '<link rel="stylesheet" href="/assets/../assets/style-'+'a'*20+'.css">',
            '<link rel="stylesheet" href="//assets/style-'+'a'*20+'.css">',
            '<link rel="stylesheet" href="/assets/style-'+'a'*20+'.css?v=1">',
            '<link rel="icon" href="https://evil.invalid/favicon.svg">',
            '<link rel="icon" href="/assets/fav.svg">',
        ]
        for html in invalid:
            with self.subTest(html=html):
                with self.assertRaisesRegex(ValueError,'COVER_ASSET_REFERENCE_NOT_LOCAL_VERSIONED'):
                    cls().feed(html)

    def test_no_bypass_of_favicon_live_content_guard(self):
        src=bundled_checker()
        self.assertEqual(sha256(src),NEW_SHA256)
        self.assertTrue(src.endswith(b'\n'))  # Exact installed heredoc bytes
        self.assertIn(b"for uri, mime in (('/robots.txt', 'text/plain'), ('/favicon.svg', 'image/svg+xml'))", src)
        self.assertIn(b'expected_file = local_bytes(site.parent / uri[1:])', src)
        self.assertIn(b'body != expected_file', src)

    def test_repair_rejects_unknown_checker_and_preserves_bytes(self):
        import selfsteal_checker_repair as repair
        with tempfile.TemporaryDirectory() as d:
            fake=Path(d)/'checker';fake.write_bytes(b'operator modified checker');fake.chmod(0o755)
            original=repair.regular_file
            def test_owner_file(path, **kw):
                return original(path, uid=os.geteuid(), **kw)
            with mock.patch.object(repair, 'regular_file', side_effect=test_owner_file):
                with self.assertRaisesRegex(RepairError,'UNKNOWN_CHECKER_VERSION_REFUSED'):
                    apply(fake, Path(d), before_after_probe=lambda _: None)
            self.assertEqual(fake.read_bytes(),b'operator modified checker')

    def test_repair_restores_legacy_if_postcheck_fails(self):
        # Test orchestration without root permissions, using a mocked, strictly
        # deterministic old checker SHA and a real temporary file.
        import selfsteal_checker_repair as repair
        with tempfile.TemporaryDirectory() as d:
            fake=Path(d)/'checker'
            old=b'legacy checker fixture'
            fake.write_bytes(old)
            checkpoint=Path(d)/'backup.py'
            checks=[]
            def probe(path):
                checks.append(path.read_bytes())
                if len(checks)==2:
                    raise RepairError('simulated postcheck failure')
            with mock.patch.object(repair,'regular_file', return_value=old), \
                 mock.patch.object(repair,'OLD_SHA256', sha256(old)), \
                 mock.patch.object(repair,'save_backup', side_effect=lambda data, directory: (checkpoint.write_bytes(data), checkpoint)[1]), \
                 mock.patch.object(repair,'atomic_replace', side_effect=lambda path,data,**kw: path.write_bytes(data)):
                with self.assertRaisesRegex(RepairError,'ORIGINAL_RESTORED'):
                    repair.apply(fake, Path(d), before_after_probe=probe)
            self.assertEqual(fake.read_bytes(), old)
            self.assertEqual(checkpoint.read_bytes(),old)
            self.assertEqual(len(checks),3)


if __name__=='__main__':
    unittest.main()
