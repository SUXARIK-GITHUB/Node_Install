"""Real Unix sockets and filesystem races, isolated from host Nginx."""
import errno
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch
from common import module

class SocketPrepareTests(unittest.TestCase):
    def setUp(self):
        self.h=module('VK_SOCKET_PREPARE')
        self.tmp=tempfile.TemporaryDirectory(prefix='vk-socket-');self.addCleanup(self.tmp.cleanup)
        self.p=Path(self.tmp.name)/'selfsteal.sock'
    def test_absent_socket(self): self.assertEqual(self.h.prepare(self.p),'ABSENT')
    def test_stale_owned_socket_removed(self):
        with socket.socket(socket.AF_UNIX) as s:s.bind(str(self.p))
        self.assertEqual(self.h.prepare(self.p),'STALE_REMOVED');self.assertFalse(self.p.exists())
    def test_live_socket_not_removed(self):
        with socket.socket(socket.AF_UNIX) as s:
            s.bind(str(self.p));s.listen()
            with self.assertRaisesRegex(self.h.UnsafeSocket,'LIVE_SOCKET'):self.h.prepare(self.p)
            self.assertTrue(self.p.is_socket())
    def test_regular_file_not_removed(self):
        self.p.write_text('preserve')
        with self.assertRaises(self.h.UnsafeSocket):self.h.prepare(self.p)
        self.assertEqual(self.p.read_text(),'preserve')
    def test_symlink_not_removed(self):
        other=self.p.with_name('other');other.write_text('preserve');self.p.symlink_to(other)
        with self.assertRaises(self.h.UnsafeSocket):self.h.prepare(self.p)
        self.assertTrue(self.p.is_symlink());self.assertEqual(other.read_text(),'preserve')
    def test_parent_symlink_refused(self):
        link=self.p.parent/'alias';link.symlink_to(self.p.parent,target_is_directory=True)
        with self.assertRaisesRegex(self.h.UnsafeSocket,'PARENT_SYMLINK'):self.h.prepare(link/self.p.name)
    def test_permission_denied_does_not_prove_staleness(self):
        with socket.socket(socket.AF_UNIX) as s:s.bind(str(self.p))
        with patch.object(self.h.socket.socket,'connect',side_effect=PermissionError(errno.EACCES,'denied')):
            with self.assertRaisesRegex(self.h.UnsafeSocket,'LIVENESS_NOT_PROVEN'):self.h.prepare(self.p)
        self.assertTrue(self.p.is_socket())
    def test_replaced_inode_never_unlinked(self):
        with socket.socket(socket.AF_UNIX) as s:s.bind(str(self.p))
        def replace(*a):
            self.p.unlink();self.p.write_text('new owner')
            raise ConnectionRefusedError(errno.ECONNREFUSED,'refused')
        with patch.object(self.h.socket.socket,'connect',side_effect=replace):
            with self.assertRaisesRegex(self.h.UnsafeSocket,'INODE_CHANGED'):self.h.prepare(self.p)
        self.assertEqual(self.p.read_text(),'new owner')
    def test_foreign_uid_not_removed(self):
        with socket.socket(socket.AF_UNIX) as s:s.bind(str(self.p))
        with patch.object(self.h.os,'geteuid',return_value=self.p.stat().st_uid+1):
            with self.assertRaisesRegex(self.h.UnsafeSocket,'NOT_OWNED_SOCKET'):self.h.prepare(self.p)
        self.assertTrue(self.p.is_socket())
