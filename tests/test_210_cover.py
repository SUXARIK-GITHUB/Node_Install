"""Atomic site publication/rollback with injected failures; never touch host services."""
import errno
import json
import os
from pathlib import Path
import re
import signal
import tempfile
import unittest
from unittest.mock import patch
from common import module, payload


class CoverTests(unittest.TestCase):
    def setUp(self):
        self.m=module('VK_SITE_TOOL_PY')
        self.temp=tempfile.TemporaryDirectory(prefix='vk-cover-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.state=self.root/'var/lib/vkarmani-node';self.state.mkdir(parents=True,mode=0o700)
        self.etc=self.root/'etc/vkarmani-node';self.etc.mkdir(parents=True,mode=0o700)
        self.site=self.root/'var/www/vkarmani-node/site';(self.site/'assets').mkdir(parents=True)
        for p in [self.site.parent,self.site,self.site/'assets']:p.chmod(0o755)
        self.m.atomic(self.etc/'config.json',json.dumps({'installation_mode':'secret-key-only','domain':'node.example.test','public_ipv4':'1.1.1.1'}).encode())
        for name,data in [('owned-installation',b''),('install-version',b'2.0.3\n'),('INSTALL_COMPLETE',b'version=2.0.3\nat=test\n')]:
            self.m.atomic(self.state/name,data)
        self.old=b'<!doctype html><title>Existing working cover</title><p>Existing</p>'
        self.m.atomic(self.site/'index.html',self.old,0o644)
        self.checked=[]
        self.check=lambda c,s,t:self.checked.append((c['domain'],(s/'index.html').read_bytes()))

    def test_render_is_deterministic_small_static_and_domain_safe(self):
        data,assets=self.m.render('node.example.test')
        self.assertEqual((data,assets),self.m.render('node.example.test'))
        self.assertIn('Сайт в разработке.'.encode(),data)
        self.assertLess(sum(map(len,assets.values()))+len(data),15000)
        self.assertNotRegex(data.decode(),r'(?i)<(?:script|iframe|form)\b|https?://|x-instance|remnawave|vless')
        for name,body in assets.items():
            self.assertIn(self.m.sha(body)[:20],name)
        for domain in ['bad<script>.test','https://test.com','*.test.com','1.1.1.1','bad\n.test','a'*64+'.test']:
            with self.subTest(domain=domain),self.assertRaises(self.m.Failure):self.m.render(domain)

    def test_full_install_refuses_overwrite_but_new_install_is_idempotent(self):
        with self.assertRaises(self.m.Failure):self.m.install_site(self.root)
        self.assertEqual((self.site/'index.html').read_bytes(),self.old)
        (self.site/'index.html').unlink();self.m.install_site(self.root)
        once={p.relative_to(self.site):p.read_bytes() for p in self.site.rglob('*') if p.is_file()}
        self.m.install_site(self.root)
        self.assertEqual(once,{p.relative_to(self.site):p.read_bytes() for p in self.site.rglob('*') if p.is_file()})

    def test_publish_then_rollback_preserves_vpn_files_and_assets(self):
        protected={self.etc/'remnanode.env':b'SECRET=test-only',self.etc/'profile.json':b'profile-test-only',self.etc/'reality.json':b'keys-test-only'}
        for p,data in protected.items():self.m.atomic(p,data)
        before={p:(p.read_bytes(),p.stat().st_mtime_ns) for p in protected}
        message=self.m.update(self.root,self.check)
        self.assertIn('COVER_UPDATE=PASS',message);self.assertEqual(len(self.checked),2)
        self.assertNotEqual((self.site/'index.html').read_bytes(),self.old)
        assets={p:p.read_bytes() for p in (self.site/'assets').iterdir()}
        self.assertTrue(assets);self.assertFalse((self.state/'cover-pending').exists())
        folder,receipt,old=self.m.pointer_read(self.state,'cover-last-update')
        self.assertEqual(old,self.old);self.assertEqual(receipt['state'],'active')
        self.assertEqual((folder/'index.before').stat().st_mode&0o777,0o600)
        self.m.rollback(self.root,self.check)
        self.assertEqual((self.site/'index.html').read_bytes(),self.old)
        self.assertEqual(assets,{p:p.read_bytes() for p in assets})
        self.assertEqual(before,{p:(p.read_bytes(),p.stat().st_mtime_ns) for p in protected})
        self.m.rollback(self.root,self.check) # retry after successful rollback

    def test_repeat_update_checks_assets_and_is_noop(self):
        self.m.update(self.root,self.check)
        names=set((self.state/'backups').iterdir())
        self.assertIn('UNCHANGED',self.m.update(self.root,self.check))
        self.assertEqual(names,set((self.state/'backups').iterdir()))
        next((self.site/'assets').glob('*.css')).write_text('tampered')
        with self.assertRaises(self.m.Failure):self.m.update(self.root,self.check)

    def test_precheck_failure_writes_nothing(self):
        with self.assertRaises(self.m.Failure):self.m.update(self.root,lambda *a:(_ for _ in ()).throw(self.m.Failure('down')))
        self.assertFalse((self.state/'backups').exists())
        self.assertEqual((self.site/'index.html').read_bytes(),self.old)

    def test_postcheck_failure_rolls_back(self):
        def checker(c,s,t):
            if (s/'index.html').read_bytes()!=self.old:raise self.m.Failure('candidate fails')
        with self.assertRaises(self.m.Failure):self.m.update(self.root,checker)
        self.assertEqual((self.site/'index.html').read_bytes(),self.old)
        self.assertFalse((self.state/'cover-pending').exists())
        receipt=json.loads(next((self.state/'backups').glob('*/receipt.json')).read_text())
        self.assertEqual(receipt['state'],'rolled-back')

    def test_backup_enospc_prevents_publication(self):
        atomic=self.m.atomic
        def fail_backup(path,*args):
            if path.name=='index.before':raise OSError(errno.ENOSPC,'test full disk')
            return atomic(path,*args)
        with patch.object(self.m,'atomic',side_effect=fail_backup):
            with self.assertRaises(OSError):self.m.update(self.root,self.check)
        self.assertEqual((self.site/'index.html').read_bytes(),self.old)
        self.assertFalse((self.state/'cover-pending').exists())

    def test_fsync_error_after_publication_rolls_back(self):
        atomic=self.m.atomic;failed=False
        def after_replace(path,data,*args):
            nonlocal failed
            atomic(path,data,*args)
            if path==self.site/'index.html' and data!=self.old and not failed:
                failed=True;raise OSError(errno.EIO,'injected after rename')
        with patch.object(self.m,'atomic',side_effect=after_replace):
            with self.assertRaises(OSError):self.m.update(self.root,self.check)
        self.assertEqual((self.site/'index.html').read_bytes(),self.old)
        self.assertFalse((self.state/'cover-pending').exists())

    def test_handled_signal_after_publication_rolls_back_and_propagates(self):
        def checker(c,s,t):
            if (s/'index.html').read_bytes()!=self.old:self.m.interrupted(signal.SIGTERM,None)
        with self.assertRaises(SystemExit) as e:self.m.update(self.root,checker)
        self.assertEqual(e.exception.code,143)
        self.assertEqual((self.site/'index.html').read_bytes(),self.old)

    def test_crash_marker_can_be_recovered_explicitly(self):
        self.m.update(self.root,self.check)
        name=(self.state/'cover-last-update').read_bytes()
        self.m.atomic(self.state/'cover-pending',name)
        with self.assertRaises(self.m.Failure):self.m.update(self.root,self.check)
        self.m.rollback(self.root,self.check)
        self.assertEqual((self.site/'index.html').read_bytes(),self.old)
        self.assertFalse((self.state/'cover-pending').exists())

    def test_backup_tamper_or_pointer_traversal_refused(self):
        self.m.update(self.root,self.check)
        folder,_,_=self.m.pointer_read(self.state,'cover-last-update')
        self.m.atomic(folder/'index.before',b'bad')
        new=(self.site/'index.html').read_bytes()
        with self.assertRaises(self.m.Failure):self.m.rollback(self.root,self.check)
        self.assertEqual((self.site/'index.html').read_bytes(),new)
        self.m.atomic(self.state/'cover-last-update',b'../../etc\n')
        with self.assertRaises(self.m.Failure):self.m.rollback(self.root,self.check)

    def test_rollback_never_overwrites_later_operator_edit(self):
        self.m.update(self.root,self.check)
        self.m.atomic(self.site/'index.html',b'operator new page',0o644)
        with self.assertRaises(self.m.Failure):self.m.rollback(self.root,self.check)
        self.assertEqual((self.site/'index.html').read_bytes(),b'operator new page')

    def test_unresolved_node_transaction_and_foreign_version_refused(self):
        for name in ['INSTALL_FAILED','image-update-pending','network-rollback-armed','network-rollback-running']:
            with self.subTest(marker=name):
                self.m.atomic(self.state/name,b'test')
                with self.assertRaises(self.m.Failure):self.m.update(self.root,self.check)
                (self.state/name).unlink()
        self.m.atomic(self.state/'install-version',b'1.3.0\n')
        with self.assertRaises(self.m.Failure):self.m.update(self.root,self.check)
        self.assertEqual((self.site/'index.html').read_bytes(),self.old)

    def test_unsafe_symlink_world_writable_and_oversized_index_refused(self):
        index=self.site/'index.html'
        index.unlink();index.symlink_to(self.etc/'config.json')
        with self.assertRaises(self.m.Failure):self.m.update(self.root,self.check)
        index.unlink();index.write_bytes(self.old);index.chmod(0o666)
        with self.assertRaises(self.m.Failure):self.m.update(self.root,self.check)
        index.chmod(0o644);index.write_bytes(b'x'*(self.m.MAX_INDEX+1))
        with self.assertRaises(self.m.Failure):self.m.update(self.root,self.check)

    def test_does_not_invoke_mutating_system_commands_or_read_keys(self):
        code=payload('VK_SITE_TOOL_PY')
        for value in ['systemctl','apt-get','docker','remnanode.env','reality.json','profile.json']:
            self.assertNotIn(value,code)
        self.assertNotIn('reload',code.replace('No service reload',''))
