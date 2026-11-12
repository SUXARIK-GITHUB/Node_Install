"""Rootless fault-injection tests for the actual pre-mutation install.sh backup block.

No service, firewall, SSH, external network, or production path is changed.
"""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from common import ROOT

SOURCE = (ROOT / 'install.sh').read_text()
MAIN = SOURCE.split('vkarmani_main() {', 1)[1]
START = MAIN.index('BK="$STATE/backups/')
END = MAIN.index('# Stage the installer, private inputs, helper scripts', START)
COMMIT_BLOCK = MAIN[START:END]


def sandbox_block():
    """Use the real snapshot/commit instructions, replacing only /etc sources."""
    text = COMMIT_BLOCK
    first = text.index('for p in etc/ssh ')
    last = text.index('\ndone', first) + len('\ndone')
    text = text[:first] + '''for p in original.txt; do
    if [[ -e "$FIXTURE_SOURCE/$p" ]]; then cp -a --parents "$FIXTURE_SOURCE/$p" "$BK/"; fi
done''' + text[last:]
    return text


class BackupCommitBoundary(unittest.TestCase):
    def test_backup_verification_precedes_version_owner_source_and_inputs(self):
        start = MAIN.index('exec </dev/null')
        backup = MAIN.index('sha256sum --check --quiet MANIFEST.sha256', start)
        version = MAIN.index('> "$STATE/install-version.tmp"', start)
        owner = MAIN.index('touch "$STATE/owned-installation"', start)
        stage = MAIN.index('install -d -m 0700 "$ETC" "$LIB" "$OPT"', start)
        source = MAIN.index('install -m 0700 -- "$VK_SOURCE_PATH"', start)
        enrollment = MAIN.index('"$LIB/cascade_deployment.py" enroll', start)
        pending = MAIN.index('"$ETC/inputs.pending.tmp"', start)
        self.assertTrue(backup < version < owner < stage < source < enrollment < pending)
        self.assertEqual(MAIN[start:].count('touch "$STATE/owned-installation"'), 1)
        self.assertNotIn('PubkeyAuthentication yes', SOURCE)

    def test_copy_failure_leaves_no_committed_installation_and_can_retry(self):
        self.check_failure('copy')

    def test_manifest_sha_failure_leaves_no_committed_installation_and_can_retry(self):
        self.check_failure('verify')

    def check_failure(self, mode):
        with tempfile.TemporaryDirectory(prefix='vk-r54-backup-') as td:
            root = Path(td)
            src = root / 'fixture-source'
            src.mkdir()
            (src / 'original.txt').write_text('the pre-install file must survive\n')
            state = root / 'state'
            state.mkdir(mode=0o700)
            (state / 'INSTALL_FAILED').write_text('prior staging failure\n')
            script = ('set -Eeuo pipefail\n'
                      'STATE="$1"\nFIXTURE_SOURCE="$2"\nINSTALLER_VERSION=2.5.18\n'
                      'RESUME_FROM=\'\'\n')
            if mode == 'copy':
                script += 'cp() { return 81; }\n'
            else:
                script += ('sha256sum() {\n'
                           '  if [[ " $* " == *" --check "* ]]; then return 82; fi\n'
                           '  command sha256sum "$@"\n}\n')
            script += sandbox_block() + '\n'
            args = ['bash', '-c', script, '_', str(state), str(src)]
            first = subprocess.run(args, capture_output=True, text=True, timeout=15)
            self.assertNotEqual(first.returncode, 0, first.stdout + first.stderr)
            for name in ('owned-installation', 'install-version', 'latest-backup-path', 'first-backup-path'):
                self.assertFalse((state / name).exists(), name)
            self.assertFalse((root / 'etc').exists())
            self.assertEqual((state / 'INSTALL_FAILED').read_text(), 'prior staging failure\n')
            second = subprocess.run(['bash', '-c', 'set -Eeuo pipefail\n'
                'STATE="$1"\nFIXTURE_SOURCE="$2"\nINSTALLER_VERSION=2.5.18\nRESUME_FROM=\'\'\n'
                + sandbox_block(), '_', str(state), str(src)], capture_output=True, text=True, timeout=15)
            self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
            self.assertTrue((state / 'owned-installation').is_file())
            self.assertEqual((state / 'install-version').read_text(), '2.5.18\n')
            backup = Path((state / 'latest-backup-path').read_text().strip())
            self.assertTrue(backup.is_dir())
            self.assertEqual((state / 'first-backup-path').read_text().strip(), str(backup))
            self.assertTrue((backup / 'MANIFEST.sha256').is_file())
            entries = (backup / 'MANIFEST.sha256').read_text().splitlines()
            self.assertEqual(len(entries), 1)
            digest, name = entries[0].split('  ', 1)
            self.assertEqual(hashlib.sha256((backup / name).read_bytes()).hexdigest(), digest)


if __name__ == '__main__':
    unittest.main()
