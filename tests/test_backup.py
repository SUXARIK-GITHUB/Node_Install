"""Actual tar/restore of synthetic fixture files, never the host's /etc or secrets."""
import errno
import hashlib
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from common import module

class BackupArchiveTests(unittest.TestCase):
    def setUp(self):
        self.h = module('VK_PAYLOAD_VK_WRITE_MAINTENANCE')
        self.tmp = tempfile.TemporaryDirectory(prefix='vk-backup-test-')
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.source, self.backup, self.restore = [root / name for name in ('source', 'backup', 'restore')]
        for path in (self.source, self.backup, self.restore):
            path.mkdir(mode=0o700)
        directory = self.source / 'etc' / 'vk-test'
        directory.mkdir(parents=True)
        (directory / 'synthetic.env').write_text('SECRET_KEY=SYNTHETIC_FIXTURE_ONLY\n')
        (directory / 'synthetic.env').chmod(0o600)
        (directory / 'config.json').write_text('{"fixture": true}\n')
        (directory / 'alias').symlink_to('config.json')
        self.paths = ['etc/vk-test']

    def test_real_archive_roundtrip_contents_permissions_symlinks_and_hash(self):
        archive = self.h.write_backup_archive(self.backup, self.paths, self.source)
        self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
        checksum = (self.backup / 'SHA256SUMS').read_text().split()[0]
        self.assertEqual(checksum, hashlib.sha256(archive.read_bytes()).hexdigest())
        subprocess.run(['tar', '-xzf', str(archive), '-C', str(self.restore)], check=True, timeout=5)
        for name in ('synthetic.env', 'config.json'):
            relative = Path('etc/vk-test') / name
            self.assertEqual((self.source / relative).read_bytes(), (self.restore / relative).read_bytes())
            self.assertEqual((self.source / relative).stat().st_mode, (self.restore / relative).stat().st_mode)
        self.assertEqual(os.readlink(self.restore / 'etc/vk-test/alias'), 'config.json')

    def test_truncated_archive_is_detected_by_tar_and_checksum(self):
        archive = self.h.write_backup_archive(self.backup, self.paths, self.source)
        expected = (self.backup / 'SHA256SUMS').read_text().split()[0]
        archive.write_bytes(archive.read_bytes()[:30])
        self.assertNotEqual(self.h.sha(archive), expected)
        with self.assertRaisesRegex(self.h.Failure, 'COMMAND_FAILED'):
            self.h.run(['tar', '-tzf', str(archive)], 5)

    def test_tar_failure_does_not_create_success_checksum(self):
        with patch.object(self.h, 'run', side_effect=self.h.Failure('COMMAND_FAILED: tar rc=2')):
            with self.assertRaises(self.h.Failure):
                self.h.write_backup_archive(self.backup, self.paths, self.source)
        self.assertFalse((self.backup / 'SHA256SUMS').exists())

    def test_archive_name_cannot_silently_overwrite_existing_backup(self):
        self.h.write_backup_archive(self.backup, self.paths, self.source)
        with self.assertRaises(FileExistsError):
            self.h.write_backup_archive(self.backup, self.paths, self.source)

    def test_fsync_io_failure_does_not_publish_success_checksum(self):
        real_fsync = os.fsync
        def fail_archive(fd):
            path = os.readlink('/proc/self/fd/' + str(fd))
            if path.endswith('node-config.tar.gz'):
                raise OSError(errno.EIO, 'synthetic archive flush failure')
            return real_fsync(fd)
        with patch.object(os, 'fsync', side_effect=fail_archive):
            with self.assertRaises(OSError):
                self.h.write_backup_archive(self.backup, self.paths, self.source)
        self.assertFalse((self.backup / 'SHA256SUMS').exists())
