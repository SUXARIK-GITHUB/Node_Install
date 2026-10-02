"""Persistent site-only random identity; failures never alter VPN state."""
import hashlib
import json
import os
from pathlib import Path
import stat
import unittest
from unittest.mock import patch
import test_210_cover as fixture


class CoverIdentity220Tests(unittest.TestCase):
    setUp = fixture.CoverTests.setUp

    def test_new_install_random_seed_persisted_private(self):
        (self.site/'index.html').unlink()
        with patch.object(self.m.secrets, 'token_hex', return_value='b'*64) as random:
            self.m.install_site(self.root)
            random.assert_called_once_with(32)
        p=self.state/'cover-identity.json'
        self.assertEqual(p.stat().st_mode&0o777,0o600)
        self.assertEqual(json.loads(p.read_bytes())['seed'],'b'*64)
        self.assertNotIn(('b'*64).encode(),(self.site/'index.html').read_bytes())

    def test_install_and_noop_update_keep_identity_and_bytes(self):
        (self.site/'index.html').unlink();self.m.install_site(self.root)
        p=self.state/'cover-identity.json';before=(p.read_bytes(),p.stat().st_mtime_ns)
        content=(self.site/'index.html').read_bytes()
        with patch.object(self.m.secrets,'token_hex',side_effect=AssertionError('must not rotate')):
            self.m.install_site(self.root)
            self.assertIn('UNCHANGED',self.m.update(self.root,self.check))
        self.assertEqual(before,(p.read_bytes(),p.stat().st_mtime_ns))
        self.assertEqual(content,(self.site/'index.html').read_bytes())

    def test_four_variants_have_distinct_css_and_content(self):
        seen={}
        for n in range(64):
            seed=f'{n:064x}'
            variant=hashlib.sha256(('node.example.test:'+seed).encode()).digest()[2]%4
            seen.setdefault(variant,self.m.render('node.example.test',seed))
        self.assertEqual(set(seen),{0,1,2,3})
        self.assertEqual(len({v[0] for v in seen.values()}),4)
        for data,assets in seen.values():
            self.assertLess(len(data)+sum(map(len,assets.values())),15000)
            self.assertNotRegex(data.decode(),r'<(?:script|iframe|form)\b|https?://')
            self.assertIn('Сайт в разработке.'.encode(),data)

    def test_bad_seed_not_silently_regenerated(self):
        p=self.state/'cover-identity.json'
        variants=[{'version':1,'domain':'wrong.test','seed':'a'*64},
                  {'version':True,'domain':'node.example.test','seed':'a'*64},
                  {'version':1,'domain':'node.example.test','seed':'x'},
                  {'version':1,'domain':'node.example.test','seed':'a'*64,'extra':1}]
        for value in variants:
            with self.subTest(value=value):
                self.m.atomic(p,json.dumps(value).encode())
                with self.assertRaises(self.m.Failure):self.m.update(self.root,self.check)
                self.assertEqual(json.loads(p.read_bytes()),value)
        self.assertEqual((self.site/'index.html').read_bytes(),self.old)

    def test_duplicate_identity_key_refused(self):
        p=self.state/'cover-identity.json'
        self.m.atomic(p,b'{"version":1,"version":1,"domain":"node.example.test","seed":"'+b'a'*64+b'"}')
        with self.assertRaisesRegex(self.m.Failure,'duplicate'):
            self.m.cover_identity(self.state,'node.example.test')

    def test_malformed_identity_refused(self):
        p=self.state/'cover-identity.json';self.m.atomic(p,b'{bad')
        with self.assertRaises(ValueError):self.m.update(self.root,self.check)
        self.assertEqual(p.read_bytes(),b'{bad')

    def test_symlink_or_public_identity_refused(self):
        p=self.state/'cover-identity.json';p.symlink_to(self.etc/'config.json')
        with self.assertRaises(self.m.Failure):self.m.update(self.root,self.check)
        p.unlink();self.m.atomic(p,b'{}',0o644)
        with self.assertRaises(self.m.Failure):self.m.update(self.root,self.check)

    def test_precheck_failure_creates_no_identity(self):
        with self.assertRaises(RuntimeError):
            self.m.update(self.root,lambda *a:(_ for _ in ()).throw(RuntimeError('down')))
        self.assertFalse((self.state/'cover-identity.json').exists())

    def test_foreign_site_install_refuses_before_seed_write(self):
        with self.assertRaises(self.m.Failure):self.m.install_site(self.root)
        self.assertFalse((self.state/'cover-identity.json').exists())

    def test_rollback_keeps_identity_for_deterministic_retry(self):
        self.m.update(self.root,self.check)
        seed=(self.state/'cover-identity.json').read_bytes()
        candidate=(self.site/'index.html').read_bytes()
        self.m.rollback(self.root,self.check)
        self.assertEqual((self.site/'index.html').read_bytes(),self.old)
        self.assertEqual((self.state/'cover-identity.json').read_bytes(),seed)
        self.m.update(self.root,self.check)
        self.assertEqual((self.site/'index.html').read_bytes(),candidate)

    def test_postcheck_failure_preserves_old_page_and_retry_identity(self):
        def check(*a):
            if (self.site/'index.html').read_bytes()!=self.old:raise self.m.Failure('candidate')
        with self.assertRaises(self.m.Failure):self.m.update(self.root,check)
        seed=(self.state/'cover-identity.json').read_bytes()
        self.assertEqual((self.site/'index.html').read_bytes(),self.old)
        self.m.update(self.root,self.check)
        self.assertEqual((self.state/'cover-identity.json').read_bytes(),seed)

    def test_atomic_no_clobber_concurrent_seed(self):
        value=self.m.cover_identity(self.state,'node.example.test')
        winner=dict(value,seed='0'*64)
        link=self.m.os.link
        def race(src,dst,**kw):
            self.m.atomic(Path(dst),json.dumps(winner).encode())
            return link(src,dst,**kw)
        with patch.object(self.m.os,'link',side_effect=race):
            with self.assertRaises(FileExistsError):self.m.store_identity(self.state,value)
        self.assertEqual(json.loads((self.state/'cover-identity.json').read_bytes()),winner)
        self.assertEqual(list(self.state.glob('.cover-identity-*')),[])

    def test_fifo_never_opened_for_read(self):
        p=self.site/'fifo';os.mkfifo(p)
        with self.assertRaises(self.m.Failure):self.m.safe_read(p)

    def test_regular_file_replaced_by_symlink_not_followed(self):
        p=self.site/'race';p.write_bytes(b'public');p.chmod(0o644)
        original=self.m.os.open
        def change(path,flags,*a,**kw):
            if Path(path)==p:
                p.unlink();p.symlink_to(self.etc/'config.json')
            return original(path,flags,*a,**kw)
        with patch.object(self.m.os,'open',side_effect=change):
            with self.assertRaises(OSError):self.m.safe_read(p)

    def test_new_release_ready_without_marker_rewrite(self):
        self.m.atomic(self.state/'install-version',b'2.2.0\n')
        self.m.atomic(self.state/'INSTALL_COMPLETE',b'version=2.2.0\n')
        self.m.ready(self.root)

    def test_render_invalid_seed_fails_closed(self):
        for seed in (True,32,'a'*63,'G'*64,'a'*64+'\n'):
            with self.subTest(seed=seed),self.assertRaises(self.m.Failure):
                self.m.render('node.example.test',seed)
