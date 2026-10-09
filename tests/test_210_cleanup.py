"""Real APT cache locking uses only a temporary cache; never touches host packages."""
import fcntl
import json
import os
import pwd
import shlex
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from common import module, payload, SCRIPT, template


def isolated_apt_cache(root):
    """Redirect every APT state/cache/config path, not only archives.

    APT clean can also lock Dir::State::lists and delete binary caches. Loading
    an empty local config directory avoids host APT hooks. Nothing is installed,
    and the real locks remain enabled. This must work without root or sudo.
    """
    root = root.resolve()
    for relative in ('etc/apt/apt.conf.d', 'etc/apt/sources.list.d',
                     'etc/apt/preferences.d', 'var/lib/apt/lists/partial',
                     'var/lib/dpkg', 'var/cache/apt/archives/partial', 'var/log/apt'):
        (root / relative).mkdir(parents=True, exist_ok=True)
    for relative in ('etc/apt/apt.conf', 'etc/apt/sources.list',
                     'etc/apt/preferences', 'var/lib/dpkg/status'):
        (root / relative).write_text('')
    paths = {
        'Dir': root,
        'Dir::Etc': root / 'etc/apt',
        'Dir::Etc::parts': root / 'etc/apt/apt.conf.d',
        'Dir::Etc::main': root / 'etc/apt/apt.conf',
        'Dir::State': root / 'var/lib/apt',
        'Dir::State::lists': root / 'var/lib/apt/lists',
        'Dir::State::status': root / 'var/lib/dpkg/status',
        'Dir::Cache': root / 'var/cache/apt',
        'Dir::Cache::archives': root / 'var/cache/apt/archives',
        'Dir::Cache::pkgcache': root / 'var/cache/apt/pkgcache.bin',
        'Dir::Cache::srcpkgcache': root / 'var/cache/apt/srcpkgcache.bin',
        'Dir::Log': root / 'var/log/apt',
    }
    config = root / 'apt-sandbox.conf'
    config.write_text(''.join(key + ' ' + json.dumps(str(value)) + ';\n'
                              for key, value in paths.items()) +
                      'APT::Sandbox::User ' + json.dumps(pwd.getpwuid(os.getuid()).pw_name) + ';\n')
    return paths, {**os.environ, 'APT_CONFIG': str(config), 'LC_ALL': 'C'}


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
            root = Path(d)
            paths, env = isolated_apt_cache(root)
            cache = paths['Dir::Cache::archives']
            sentinel = cache / 'example.deb'
            sentinel.write_bytes(b'test-only')
            status_before = paths['Dir::State::status'].read_bytes()
            argv = ['apt-get', 'clean']
            with (cache/'lock').open('wb') as lock, patch.dict(os.environ, env):
                inode=(cache/'lock').stat().st_ino
                fcntl.lockf(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                r=self.m.clean(argv)
                self.assertEqual(r['status'],'DEFERRED',r)
                self.assertTrue(sentinel.exists())
                self.assertEqual((cache/'lock').stat().st_ino,inode)
                fcntl.lockf(lock,fcntl.LOCK_UN)
                result = self.m.clean(argv)
                self.assertEqual(result['status'], 'PASS', result)
                self.assertEqual(paths['Dir::State::status'].read_bytes(), status_before)
                self.assertFalse(sentinel.exists())
                self.assertTrue((cache/'lock').exists())

    def test_real_apt_effective_paths_stay_in_disposable_tree(self):
        if not shutil.which('apt-config'):
            self.skipTest('apt-config needed for effective path validation')
        with tempfile.TemporaryDirectory(prefix='vk-clean-paths-') as d:
            paths, env = isolated_apt_cache(Path(d))
            args = ['apt-config', 'shell']
            expected = {}
            for i, (key, value) in enumerate(paths.items()):
                name = 'P' + str(i)
                suffix = '/f' if key.endswith(('main', 'status', 'pkgcache')) else '/d'
                args += [name, key + suffix]
                expected[name] = str(value).rstrip('/')
            result = subprocess.run(args, env=env, capture_output=True, text=True,
                                    timeout=5, check=True)
            actual = dict(item.split('=', 1) for item in shlex.split(result.stdout))
            self.assertEqual({k: v.rstrip('/') for k, v in actual.items()}, expected)

    def test_real_apt_cleans_only_fixture_caches_not_adjacent_data(self):
        if not shutil.which('apt-get'):
            self.skipTest('apt-get needed for isolated cleanup')
        with tempfile.TemporaryDirectory(prefix='vk-clean-boundary-') as d:
            outer = Path(d)
            paths, env = isolated_apt_cache(outer / 'sandbox')
            protected = outer / 'outside.deb'
            protected.write_bytes(b'outside disposable APT root')
            cache_files = [paths['Dir::Cache::archives'] / 'fixture.deb',
                           paths['Dir::Cache::pkgcache'], paths['Dir::Cache::srcpkgcache']]
            for p in cache_files:
                p.write_bytes(b'synthetic cache')
            status = paths['Dir::State::status']
            status.write_bytes(b'# synthetic dpkg sentinel; not parsed by clean\n')
            before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in (protected, status)}
            with patch.dict(os.environ, env):
                result = self.m.clean(['apt-get', 'clean'])
            self.assertEqual(result['status'], 'PASS', result)
            self.assertTrue(all(not p.exists() for p in cache_files))
            self.assertEqual({p: (p.read_bytes(), p.stat().st_mtime_ns) for p in before}, before)

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
        code = r'''set -Eeuo pipefail
LIB=/fixture; STATE=/fixture
stage(){ :; }
vk_write_finalizer_helper(){ echo finalizer_written; }
python3(){
    case "$*" in
        *apt_clean.py*) echo cleanup_deferred; return 0 ;;
        *prepare) echo checkpoint_prepared; return 0 ;;
        *finish) echo acceptance; return "$MOCK_CHECK_RC" ;;
        *) return 99 ;;
    esac
}
'''
        for rc in (1,0):
            with self.subTest(acceptance_rc=rc):
                result=subprocess.run(['bash','-c',code+final],
                                      env={**os.environ,'MOCK_CHECK_RC':str(rc)},
                                      capture_output=True,text=True)
                self.assertEqual(result.returncode,rc,result.stderr)
                self.assertIn('acceptance',result.stdout)
                self.assertLess(result.stdout.index('cleanup_deferred'), result.stdout.index('checkpoint_prepared'))
                self.assertLess(result.stdout.index('checkpoint_prepared'), result.stdout.index('acceptance'))
        self.assertIn('apt_clean.py',template('/usr/local/sbin/vkarmani-node-cleanup'))

    def test_no_lock_removal_or_security_update_disabling(self):
        code=payload('VK_APT_CLEAN_PY')
        self.assertNotIn('unattended-upgrades.service',code)
        self.assertNotIn("unlink('/var",code)
        with self.assertRaises(SystemExit) as c:
            self.m.interrupted(15,None)
        self.assertEqual(c.exception.code,143)
