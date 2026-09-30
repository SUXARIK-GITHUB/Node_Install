"""Real APT cache locking uses only a temporary cache; never touches host packages."""
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from common import module, payload, SCRIPT, template


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.m = module('VK_APT_CLEAN_PY')

    def test_success(self):
        self.assertEqual(self.m.clean([sys.executable, '-c', 'pass'])['status'], 'PASS')

    def test_busy_and_permission_are_distinct(self):
        for message, expected in [
            ('E: Could not get lock /var/cache/apt/archives/lock. It is held by process 42 (unattended-upgr)\nE: Unable to lock directory /var/cache/apt/archives/', 'DEFERRED'),
            ('E: Could not get lock /var/cache/apt/archives/lock (13: Permission denied)\nE: Unable to lock directory /var/cache/apt/archives/', 'WARNING'),
            ('an arbitrary package hook failed', 'WARNING')]:
            with self.subTest(expected=expected, message=message):
                result = self.m.clean([sys.executable, '-c', 'import sys;print('+repr(message)+');sys.exit(100)'])
                self.assertEqual(result['status'], expected)
                self.assertNotIn('message', result)

    def test_missing_command_is_reported(self):
        self.assertEqual(self.m.clean(['/nonexistent/vk-test-command'])['reason'], 'COMMAND_UNAVAILABLE_OR_IO')

    def test_timeout_kills_own_descendant_without_late_write(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'late'
            child='import time,pathlib;time.sleep(0.6);pathlib.Path('+repr(str(path))+').touch()'
            code='import subprocess,time,sys;subprocess.Popen([sys.executable,"-c",'+repr(child)+']);time.sleep(8)'
            t=time.monotonic()
            result=self.m.clean([sys.executable,'-c',code], timeout=.12)
            self.assertEqual(result['reason'],'TIMEOUT')
            self.assertLess(time.monotonic()-t,3)
            time.sleep(.7)
            self.assertFalse(path.exists())

    def test_real_apt_locked_cache_defers_then_cleans(self):
        if not shutil.which('apt-get'):
            self.skipTest('apt-get is required for the real isolated cache test')
        with tempfile.TemporaryDirectory(prefix='vk-clean-cache-') as d:
            root=Path(d); cache=root/'archives'; cache.mkdir();(cache/'partial').mkdir()
            sentinel=cache/'example.deb';sentinel.write_bytes(b'test-only')
            config=root/'apt.conf';config.write_text('Dir::Etc::parts "-"; Dir::Etc::main "-";\n')
            argv=['apt-get','-o','Dir::Cache::archives='+str(cache), 'clean']
            with (cache/'lock').open('wb') as lock, patch.dict(os.environ,{'APT_CONFIG':str(config)}):
                inode=(cache/'lock').stat().st_ino
                fcntl.lockf(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                r=self.m.clean(argv)
                self.assertEqual(r['status'],'DEFERRED',r)
                self.assertTrue(sentinel.exists())
                self.assertEqual((cache/'lock').stat().st_ino,inode)
                fcntl.lockf(lock,fcntl.LOCK_UN)
                self.assertEqual(self.m.clean(argv)['status'],'PASS')
                self.assertFalse(sentinel.exists())
                self.assertTrue((cache/'lock').exists())

    def test_status_record_private_atomic_and_old_survives_replace_error(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'apt-clean-status.json'
            self.m.record({'status':'DEFERRED','reason':'LOCK_BUSY','rc':100},Path(d))
            before=path.read_bytes()
            self.assertEqual(path.stat().st_mode&0o777,0o600)
            self.assertEqual(json.loads(before)['status'],'DEFERRED')
            with patch.object(self.m.os,'replace',side_effect=OSError('ENOSPC')):
                with self.assertRaises(OSError):
                    self.m.record({'status':'PASS'},Path(d))
            self.assertEqual(path.read_bytes(),before)
            self.assertEqual(len(list(Path(d).iterdir())),1)

    def test_failed_cleanup_does_not_skip_acceptance_and_acceptance_error_propagates(self):
        # Execute the REAL final sequence up to the marker with all commands mocked.
        final=SCRIPT.split("stage 'Очистка только APT-кэша и ограниченных журналов'",1)[1]
        final=final.split("stage 'Установка завершена",1)[0]
        with tempfile.TemporaryDirectory() as d:
            code='set -Eeuo pipefail\nSTATE='+repr(d)+'; INSTALLER_VERSION=2.1.0; DIGEST=test\n'
            code+='python3(){ printf "cleanup deferred\\n"; return 0; }\n'
            # Only replace the diagnostic executable path, retaining shell strict mode.
            final=final.replace('/usr/local/sbin/vkarmani-node-check','test_check')
            for rc in (1,0):
                with self.subTest(acceptance_rc=rc):
                    result=subprocess.run(['bash','-c',code+f'test_check(){{ echo acceptance; return {rc}; }}\n'+final],capture_output=True,text=True)
                    self.assertEqual(result.returncode,rc)
                    self.assertIn('acceptance',result.stdout)
                    self.assertEqual((Path(d)/'INSTALL_COMPLETE').exists(),rc==0)
        self.assertIn('apt_clean.py',template('/usr/local/sbin/vkarmani-node-cleanup'))

    def test_no_lock_removal_or_security_update_disabling(self):
        code=payload('VK_APT_CLEAN_PY')
        self.assertNotIn('unattended-upgrades.service',code)
        self.assertNotIn("unlink('/var",code)
        with self.assertRaises(SystemExit) as c:
            self.m.interrupted(15,None)
        self.assertEqual(c.exception.code,143)
