"""Real subprocess cancellation plus injected local disk/syscall faults."""
import errno
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from common import module,payload

class ProcessFaultTests(unittest.TestCase):
    def setUp(self):
        self.h=module('VK_PAYLOAD_VK_WRITE_MAINTENANCE')
        self.tmp=tempfile.TemporaryDirectory(prefix='vk-fault-');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
    def test_successful_process(self): self.assertEqual(self.h.run(['/bin/sh','-c','printf PASS']),'PASS')
    def test_failed_command_is_precise_but_redacted(self):
        with self.assertRaisesRegex(self.h.Failure,'COMMAND_FAILED: sh rc=7') as caught:
            self.h.run(['/bin/sh','-c','printf TEST_PRIVATE_TOKEN >&2; exit 7'])
        self.assertNotIn('PRIVATE_TOKEN',str(caught.exception))
    def test_missing_command_is_diagnostic(self):
        with self.assertRaisesRegex(self.h.Failure,'COMMAND_START_FAILED'):
            self.h.run([str(self.root/'nonexistent')])
    def test_timeout_kills_descendant_before_it_can_write(self):
        marker=self.root/'late'
        with self.assertRaisesRegex(self.h.Failure,'COMMAND_TIMEOUT'):
            self.h.run(['/bin/sh','-c','(sleep .45; printf late >"$1") & sleep 2','_',str(marker)],timeout=.12)
        time.sleep(.5);self.assertFalse(marker.exists(),'descendant survived cancellation')
    def test_sigterm_ignored_by_child_is_escalated(self):
        started=time.monotonic()
        with self.assertRaisesRegex(self.h.Failure,'COMMAND_TIMEOUT'):
            self.h.run(['/bin/sh','-c','trap "" TERM; while :; do sleep 1; done'],timeout=.12)
        self.assertLess(time.monotonic()-started,4)
    def test_sigterm_interrupts_command_without_waiting_for_completion(self):
        helper=self.root/'helper.py';helper.write_text(payload('VK_PAYLOAD_VK_WRITE_MAINTENANCE'))
        marker=self.root/'late'
        program=("import importlib.util,signal,time\n"
                 "s=importlib.util.spec_from_file_location('h',"+repr(str(helper))+");h=importlib.util.module_from_spec(s);s.loader.exec_module(h)\n"
                 "signal.signal(signal.SIGTERM,h.interrupted)\n"
                 "try: h.run(['/bin/sh','-c','(sleep .5; printf late >\\\"$1\\\") & sleep .1; kill -TERM $PPID; sleep 2','_',"+repr(str(marker))+"])\n"
                 "except h.Failure as e: print(e)\n")
        # Use a real shell process; no server or system service is involved.
        program=program.replace('\\"','"')
        started=time.monotonic()
        result=subprocess.run([sys.executable,'-c',program],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('INTERRUPTED signal=15',result.stdout)
        self.assertLess(time.monotonic()-started,2)
        time.sleep(.5);self.assertFalse(marker.exists())
    def test_command_pipes_do_not_leak_file_descriptors(self):
        before=len(list(Path('/proc/self/fd').iterdir()))
        for _ in range(30):self.h.run(['/bin/sh','-c','exit 0'])
        self.assertLessEqual(len(list(Path('/proc/self/fd').iterdir())),before+1)

class AtomicFaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='vk-atomic-');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.h=module('PY_HELPER');self.m=module('VK_PAYLOAD_VK_WRITE_MAINTENANCE')
    def check_replace_fault(self,write):
        target=self.root/'state';target.write_text('OLD');target.chmod(0o600)
        with patch.object(os,'replace',side_effect=OSError(errno.ENOSPC,'injected disk full')):
            with self.assertRaises(OSError):write(target)
        self.assertEqual(target.read_text(),'OLD');self.assertEqual(list(self.root.iterdir()),[target])
    def test_json_rename_enospc_preserves_old_and_cleans_temp(self): self.check_replace_fault(lambda p:self.h.atomic_json(p,{'new':True}))
    def test_text_rename_enospc_preserves_old_and_cleans_temp(self): self.check_replace_fault(lambda p:self.h.atomic_text(p,'NEW'))
    def test_transaction_rename_enospc_preserves_old(self): self.check_replace_fault(lambda p:self.m.atomic(p,'NEW'))
    def test_failed_file_fsync_preserves_old(self):
        target=self.root/'state';target.write_text('OLD')
        with patch.object(os,'fsync',side_effect=OSError(errno.EIO,'injected I/O error')):
            with self.assertRaises(OSError):self.h.atomic_json(target,{'new':True})
        self.assertEqual(target.read_text(),'OLD');self.assertEqual(list(self.root.iterdir()),[target])
    def test_atomic_json_syncs_contents_and_parent(self):
        with patch.object(os,'fsync',wraps=os.fsync) as sync:self.h.atomic_json(self.root/'state',{'new':True})
        self.assertEqual(sync.call_count,2)
    def test_secret_json_remains_private_under_permissive_umask(self):
        old=os.umask(0)
        try:self.h.atomic_json(self.root/'state',{'test':'synthetic'})
        finally:os.umask(old)
        self.assertEqual((self.root/'state').stat().st_mode&0o777,0o600)
