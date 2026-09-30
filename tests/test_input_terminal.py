"""Actual pseudo-terminal tests of ONLY input functions, not vkarmani_main."""
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import tempfile
import termios
import time
import unittest
from common import SCRIPT

class TerminalInputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='vk-pty-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.etc = self.root / 'etc'
        self.etc.mkdir(mode=0o700)
        start = SCRIPT.index('vk_input_error()')
        end = SCRIPT.index('\n}\n', SCRIPT.index('vk_collect_inputs()')) + 3
        self.harness = self.root / 'input-only.sh'
        # Neither sourcing nor calling the installer main is allowed here.
        self.harness.write_text('set -Eeuo pipefail\nETC=$1\n' + SCRIPT[start:end] +
                                '\nvk_collect_inputs\nprintf "RESULT_LENGTH=%s DOMAIN=%s PANEL=%s\\n" "${#VK_INPUT_SECRET}" "$VK_INPUT_DOMAIN" "$VK_INPUT_PANEL_IP"\n')
        self.master, self.slave = pty.openpty()
        self.addCleanup(os.close, self.master)
        self.addCleanup(os.close, self.slave)
        self.initial = termios.tcgetattr(self.slave)
        self.proc = None
        self.output = bytearray()
        self.addCleanup(self.stop)

    def stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=3)

    def start(self):
        slave = self.slave
        def setup_tty():
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        self.proc = subprocess.Popen(['bash', str(self.harness), str(self.etc)],
                                     stdin=self.slave, stdout=self.slave, stderr=self.slave,
                                     preexec_fn=setup_tty)

    def until(self, marker, timeout=3):
        deadline = time.monotonic() + timeout
        while marker not in self.output:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.fail('PTY output did not reach marker ' + repr(marker))
            if select.select([self.master], [], [], remaining)[0]:
                self.output.extend(os.read(self.master, 65536))
        return bytes(self.output)

    def test_three_questions_long_hidden_secret_and_normalized_domain(self):
        self.start()
        self.until(b'[1/3]')
        self.assertFalse(termios.tcgetattr(self.slave)[3] & termios.ECHO)
        secret = b'A' * 8192
        os.write(self.master, secret + b'\n')
        self.until(b'[2/3]')
        self.assertTrue(termios.tcgetattr(self.slave)[3] & termios.ECHO)
        self.assertNotIn(secret[:64], self.output)
        os.write(self.master, b' NODE.EXAMPLE.TEST. \n')
        self.until(b'[3/3]')
        os.write(self.master, b'1.1.1.1\n')
        result = self.until(b'RESULT_LENGTH=8192 DOMAIN=node.example.test PANEL=1.1.1.1')
        self.assertEqual(self.proc.wait(timeout=3), 0)
        self.assertEqual([result.count(x) for x in (b'[1/3]', b'[2/3]', b'[3/3]')], [1, 1, 1])
        self.assertEqual(termios.tcgetattr(self.slave), self.initial)

    def test_invalid_secret_does_not_appear_or_advance(self):
        self.start()
        self.until(b'[1/3]')
        os.write(self.master, b'SYNTHETIC_INVALID_SECRET\n')
        self.assertEqual(self.proc.wait(timeout=3), 1)
        while select.select([self.master], [], [], .05)[0]:
            self.output.extend(os.read(self.master, 65536))
        self.assertNotIn(b'SYNTHETIC_INVALID_SECRET', self.output)
        self.assertNotIn(b'[2/3]', self.output)
        self.assertEqual(termios.tcgetattr(self.slave), self.initial)

    def test_termination_during_hidden_input_restores_terminal(self):
        self.start()
        self.until(b'[1/3]')
        self.proc.send_signal(signal.SIGTERM)
        self.assertEqual(self.proc.wait(timeout=3), 143)
        self.assertEqual(termios.tcgetattr(self.slave), self.initial)

    def test_completed_config_does_not_prompt(self):
        (self.etc / 'config.json').write_text('{"synthetic": true}')
        self.start()
        self.until(b'RESULT_LENGTH=0')
        self.assertEqual(self.proc.wait(timeout=3), 0)
        self.assertNotIn(b'[1/3]', self.output)

    def test_missing_controlling_terminal_is_rejected(self):
        result = subprocess.run(['bash', str(self.harness), str(self.etc)], stdin=subprocess.DEVNULL,
                                capture_output=True, start_new_session=True, timeout=3)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(self.etc.iterdir()), [])
