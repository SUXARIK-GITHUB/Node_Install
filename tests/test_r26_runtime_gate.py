"""Optional local Xray binary gate checks only configuration; no network calls."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from common import ROOT
sys.path.insert(0,str(ROOT/'integrations'))
import optional_transports as optional
import transport_readiness as readiness

class RuntimeGate(unittest.TestCase):
    @staticmethod
    def stub_executable(root):
        executable = root/'xray-test-stub'
        executable.write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
        executable.chmod(0o700)
        return executable

    def test_no_live_side_effect_and_opt_in_xray_check(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            bundle=root/'private-bundle'
            optional.write_bundle(bundle,optional.xhttp_tls('node.example.test',33643,'/api/1234567890abcdef'))
            executable=self.stub_executable(root)
            called=[]
            def test(command,**kw):
                called.append((command,kw))
                return subprocess.CompletedProcess(command,0)
            with patch.object(readiness.subprocess,'run',side_effect=test):
                self.assertEqual(readiness.xray_config_test('xhttp-tls',bundle,executable),'PASS')
            self.assertEqual(len(called),1)
            self.assertEqual(called[0][0][1:4],['run','-test','-config'])
            self.assertIs(called[0][1]['stdout'],subprocess.DEVNULL)
            self.assertIs(called[0][1]['stderr'],subprocess.DEVNULL)
            with self.assertRaisesRegex(readiness.CheckError,'ONLY_FOR_XRAY_BUNDLES'):
                readiness.xray_config_test('awg2',bundle,executable)

    def test_xray_binary_must_be_trusted_and_failure_not_misreported(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            bundle=root/'b'
            optional.write_bundle(bundle,optional.hysteria2('node.example.test',443))
            executable=self.stub_executable(root)
            link=root/'xray'
            link.symlink_to(sys.executable)
            with self.assertRaisesRegex(readiness.CheckError,'ABSOLUTE_PATH_REQUIRED'):
                readiness.xray_config_test('hysteria2',bundle,link)
            with patch.object(readiness.subprocess,'run',return_value=subprocess.CompletedProcess([],1)):
                with self.assertRaisesRegex(readiness.CheckError,'CONFIG_REJECTED'):
                    readiness.xray_config_test('hysteria2',bundle,executable)

    def test_cli_runtime_test_failure_is_fail_not_pass(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            bundle=root/'b'
            optional.write_bundle(bundle,optional.xhttp_tls('node.example.test',33643,'/api/1234567890abcdef'))
            # Not the Xray binary: --xray-bin must be an explicit, known executable.
            p=subprocess.run(['bash',str(ROOT/'install.sh'),'--transport-readiness','xhttp-tls',
                              '--bundle',str(bundle),'--expected-domain','node.example.test',
                              '--xray-bin',str(root/'missing')], capture_output=True,text=True,timeout=12)
            self.assertEqual(p.returncode,1,p.stderr)
            self.assertIn('XRAY_EXECUTABLE_NOT_FOUND',p.stdout)
            self.assertNotIn('node.example.test',p.stdout)

if __name__=='__main__':unittest.main()
