"""Offline regressions for exact candidate archive/README contract.

These exercise mismatches, not the network/download/UI sandbox link.
"""
import hashlib
import json
from pathlib import Path
import sys
import unittest
from copy import deepcopy

from common import ROOT
sys.path.insert(0, str(ROOT / 'scripts'))
import verify_release as vr


class R2ReleasePackageTests(unittest.TestCase):
    def minimal_package(self):
        c = {name: (b'fixture-' + name.encode()) for name in vr.REQUIRED}
        c['install.sh'] = (b'INSTALLER_VERSION=2.5.17\n'
                           b'vk_rkn_safe_shutdown()\nvk_write_docker_local()\n'
                           b'vk_write_nightly_maintenance()\n')
        c['README.md'] = ('2.5.17 — текущая staging-сборка\n'
                          'Node_Install_2.5.17-docs-menu_r2-fixed-test-build.zip\n').encode()
        items = [{'path':n,'size':len(c[n]),'sha256':vr.sha256(c[n]),'mode':'0644'}
                 for n in sorted(c)]
        meta = {'version':'2.5.17','build_id':'r2-fixed-test-build',
                'source_commit':'e0e076678d92daa074daa8289db2df3a3a395a42',
                'release_status':'INCOMPLETE_STAGING_ONLY',
                'excluded_from_manifest':sorted(vr.SKIPPED),'files':items}
        c[vr.MANIFEST] = (json.dumps(meta, sort_keys=True) + '\n').encode()
        c[vr.SUMS] = ''.join(f'{vr.sha256(c[n])}  {n}\n'
                              for n in sorted(c) if n != vr.SUMS).encode()
        return c

    def test_valid_manifest_and_exact_bytes(self):
        c = self.minimal_package()
        info, files = vr.verify_bytes(c)
        self.assertEqual(info['build_id'],'r2-fixed-test-build')
        self.assertEqual(set(files),vr.REQUIRED)

    def test_old_binary_under_new_name_is_rejected(self):
        c = self.minimal_package()
        c['install.sh'] = b'INSTALLER_VERSION=2.5.6\n'
        with self.assertRaisesRegex(ValueError,'mismatch'):
            vr.verify_bytes(c)

    def test_missing_new_helper_is_rejected(self):
        c = self.minimal_package()
        del c['integrations/docker_local.sh']
        with self.assertRaisesRegex(ValueError,'missing/unexpected'):
            vr.verify_bytes(c)

    def test_unmanifested_file_refused(self):
        c = self.minimal_package()
        c['extra/secret.env'] = b'SECRET_KEY=do-not-send\n'
        with self.assertRaisesRegex(ValueError,'missing/unexpected'):
            vr.verify_bytes(c)

    def test_wrong_readme_version_detected_even_if_rehashed(self):
        c = self.minimal_package()
        c['README.md'] = '2.5.6 legacy\n'.encode()
        meta = json.loads(c[vr.MANIFEST]); row=next(x for x in meta['files'] if x['path']=='README.md')
        row['size'] = len(c['README.md']); row['sha256'] = vr.sha256(c['README.md'])
        c[vr.MANIFEST] = (json.dumps(meta, sort_keys=True)+'\n').encode()
        c[vr.SUMS] = ''.join(f'{vr.sha256(c[n])}  {n}\n'
                              for n in sorted(c) if n != vr.SUMS).encode()
        with self.assertRaisesRegex(ValueError,'README release'):
            vr.verify_bytes(c)

    def test_wrong_archive_build_id_in_readme_is_rejected_even_when_rehashed(self):
        c = self.minimal_package()
        c['README.md'] = c['README.md'].replace(b'r2-fixed-test-build.zip', b'old-build.zip')
        meta = json.loads(c[vr.MANIFEST])
        row = next(x for x in meta['files'] if x['path'] == 'README.md')
        row['size'] = len(c['README.md'])
        row['sha256'] = vr.sha256(c['README.md'])
        c[vr.MANIFEST] = (json.dumps(meta, sort_keys=True) + '\n').encode()
        c[vr.SUMS] = ''.join(f'{vr.sha256(c[n])}  {n}\n'
                              for n in sorted(c) if n != vr.SUMS).encode()
        with self.assertRaisesRegex(ValueError, 'README release command/build ID'):
            vr.verify_bytes(c)

    def test_modified_manifest_is_detected(self):
        c = self.minimal_package()
        m = json.loads(c[vr.MANIFEST]); m['build_id']='tampered-build'
        c[vr.MANIFEST] = (json.dumps(m)+'\n').encode()
        with self.assertRaisesRegex(ValueError,'SHA256SUMS'):
            vr.verify_bytes(c)

    def test_duplicate_paths_or_traversal(self):
        for name in ('../outside', 'x/../y', '/absolute', 'x//y', 'x\\y', '.git/config'):
            with self.subTest(path=name):
                with self.assertRaises(ValueError):
                    vr.verify_name(name)


if __name__ == '__main__':
    unittest.main()
