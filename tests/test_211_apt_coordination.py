"""APT/dpkg lock coordination for production installer.

These tests never install packages or touch host package-manager locks. They source the
real installer (source-safe) and replace only lslocks/sleep/command-under-test with
fixture executables/functions.
"""
from pathlib import Path
import os
import subprocess
import tempfile
import textwrap
import unittest

from common import ROOT, SCRIPT


INSTALL = ROOT / 'install.sh'


def run_bash(body, env=None, timeout=10):
    code = 'set -Eeuo pipefail\nsource ' + repr(str(INSTALL)) + '\n' + body
    return subprocess.run(['bash', '-c', code], text=True, capture_output=True,
                          env={**os.environ, **(env or {})}, timeout=timeout)


class AptCoordinationTests(unittest.TestCase):
    def test_contract_has_bounded_wait_and_short_internal_lock_timeout(self):
        self.assertIn('APT_LOCK_TOTAL_WAIT=1800', SCRIPT)
        self.assertIn('APT_LOCK_REPORT_INTERVAL=30', SCRIPT)
        self.assertIn('APT_LOCK_POLL_INTERVAL=5', SCRIPT)
        self.assertIn('APT_LOCK_ATTEMPT_WAIT=15', SCRIPT)
        self.assertIn('DPkg::Lock::Timeout "15";', SCRIPT)
        self.assertIn('vk_wait_apt_idle "$APT_LOCK_TOTAL_WAIT"', SCRIPT)
        self.assertIn('vk_apt_run "${APT[@]}" install "${DOCKER_PACKAGES[@]}"', SCRIPT)

    def test_no_lock_deletion_or_package_process_kill(self):
        start = SCRIPT.index('vk_apt_lock_snapshot()')
        end = SCRIPT.index('# Release mappings are exact.', start)
        code = SCRIPT[start:end]
        for bad in ('rm /var/lib/dpkg', 'rm -f /var/lib/dpkg', 'unlink(', 'kill ', 'pkill', 'killall'):
            self.assertNotIn(bad, code)
        self.assertIn('Ничего не остановлено и lock-файлы не удалены', code)

    def test_real_fixture_waits_for_frontend_lock_then_passes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            state = root / 'count'
            fake = root / 'lslocks'
            fake.write_text(textwrap.dedent(f'''\
                #!/usr/bin/env bash
                n=$(cat {state!s} 2>/dev/null || echo 0)
                n=$((n+1)); printf '%s\\n' "$n" > {state!s}
                if (( n <= 3 )); then
                    printf '15941 unattended-upgr /var/lib/dpkg/lock-frontend\\n'
                    printf '15941 unattended-upgr /var/cache/apt/archives/lock\\n'
                fi
            '''))
            fake.chmod(0o700)
            body = textwrap.dedent(f'''\
                PATH={root!s}:$PATH
                APT_LOCK_REPORT_INTERVAL=30
                APT_LOCK_POLL_INTERVAL=5
                SECONDS=0
                sleep() {{ SECONDS=$((SECONDS+$1)); }}
                vk_wait_apt_idle 60
            ''')
            r = run_bash(body)
            self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
            self.assertIn('APT_WAIT:', r.stdout)
            self.assertIn('unattended-upgr(pid=15941)', r.stdout)
            self.assertIn('APT_WAIT=PASS waited=', r.stdout)
            self.assertEqual(state.read_text().strip(), '4')

    def test_timeout_is_explicit_and_non_destructive(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            fake = root / 'lslocks'
            fake.write_text('#!/usr/bin/env bash\nprintf "99 dpkg /var/lib/dpkg/lock\\n"\n')
            fake.chmod(0o700)
            body = textwrap.dedent(f'''\
                PATH={root!s}:$PATH
                SECONDS=0
                sleep() {{ SECONDS=$((SECONDS+$1)); }}
                set +e
                vk_wait_apt_idle 10
                rc=$?
                set -e
                echo RC=$rc
                exit 0
            ''')
            r = run_bash(body)
            self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
            self.assertIn('RC=75', r.stdout)
            self.assertIn('пакетный менеджер занят более 10s', r.stderr)
            self.assertIn('dpkg(pid=99)', r.stderr)

    def test_lock_race_retries_but_arbitrary_apt_error_does_not(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            # No pre-existing locks; the first command simulates a race after snapshot.
            lslocks = root / 'lslocks'
            lslocks.write_text('#!/usr/bin/env bash\nexit 0\n')
            lslocks.chmod(0o700)
            log = root / 'install.log'; log.write_text('')
            count = root / 'count'
            apt = root / 'fake-apt'
            apt.write_text(textwrap.dedent(f'''\
                #!/usr/bin/env bash
                n=$(cat {count!s} 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > {count!s}
                if (( n == 1 )); then
                    msg='E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 42 (unattended-upgr)'
                    printf '%s\\n' "$msg" | tee -a "$LOG"
                    exit 100
                fi
                printf 'success\\n' | tee -a "$LOG"
                exit 0
            '''))
            apt.chmod(0o700)
            body = textwrap.dedent(f'''\
                PATH={root!s}:$PATH
                LOG={log!s}; export LOG
                APT_LOCK_TOTAL_WAIT=60
                sleep() {{ :; }}
                vk_apt_run {apt!s}
            ''')
            r = run_bash(body)
            self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
            self.assertIn('APT_LOCK_RACE:', r.stdout)
            self.assertEqual(count.read_text().strip(), '2')

            count.write_text('0')
            bad = root / 'bad-apt'
            bad.write_text(textwrap.dedent(f'''\
                #!/usr/bin/env bash
                n=$(cat {count!s}); n=$((n+1)); echo "$n" > {count!s}
                printf 'E: repository signature failed\\n' | tee -a "$LOG"
                exit 100
            '''))
            bad.chmod(0o700)
            body = textwrap.dedent(f'''\
                PATH={root!s}:$PATH
                LOG={log!s}; export LOG
                APT_LOCK_TOTAL_WAIT=60
                sleep() {{ :; }}
                set +e
                vk_apt_run {bad!s}
                rc=$?
                set -e
                echo RC=$rc
            ''')
            r = run_bash(body)
            self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
            self.assertIn('RC=100', r.stdout)
            self.assertEqual(count.read_text().strip(), '1')

    def test_package_audit_is_after_lock_wait(self):
        wait = SCRIPT.index('vk_wait_apt_idle "$APT_LOCK_TOTAL_WAIT"')
        audit = SCRIPT.index('dpkg --audit', wait)
        collect = SCRIPT.index('vk_collect_inputs', audit)
        self.assertLess(wait, audit)
        self.assertLess(audit, collect)


if __name__ == '__main__':
    unittest.main()
