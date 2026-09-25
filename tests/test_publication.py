#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from test_helper import bundle, encode

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('scan',ROOT/'tools/check-publication.py')
scan=importlib.util.module_from_spec(spec);spec.loader.exec_module(scan)

class PublicationTests(unittest.TestCase):
    def test_encoded_secret_found(self):
        secret=encode(bundle())
        findings=list(scan.inspect('SECRET_KEY='+secret+'\n'))
        self.assertTrue(any(kind=='encoded private-key payload' for _,kind in findings))
    def test_no_secret_value_in_scan_output(self):
        secret=encode(bundle())
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp)/'example.txt').write_text('SECRET_KEY='+secret+'\n')
            r=subprocess.run([sys.executable,str(ROOT/'tools/check-publication.py'),temp],capture_output=True,text=True)
            self.assertEqual(r.returncode,1)
            self.assertNotIn(secret,r.stdout+r.stderr)
            self.assertIn('VALUE REDACTED',r.stdout)
    def test_plain_private_key_found(self):
        self.assertTrue(list(scan.inspect(bundle()['nodeKeyPem'])))
    def test_shell_placeholders_not_credentials(self):
        self.assertEqual(list(scan.inspect('SECRET_KEY=$USER_INPUT\n')),[])
    def test_command_generation(self):
        for origin in ['sample-team/VKarmani-Node','https://github.com/sample-team/VKarmani-Node.git','git@github.com:sample-team/VKarmani-Node.git']:
            r=subprocess.run([sys.executable,str(ROOT/'tools/install-command.py'),origin],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)
            self.assertEqual(r.stdout.strip(),'bash <(curl -fsSL https://raw.githubusercontent.com/sample-team/VKarmani-Node/main/install.sh)')
    def test_command_generation_rejects_injection(self):
        for value in ['https://evil.example.com/x/y','owner/repo;id','owner/$(id)']:
            r=subprocess.run([sys.executable,str(ROOT/'tools/install-command.py'),value],capture_output=True,text=True)
            self.assertNotEqual(r.returncode,0)
    def test_collector_rejects_ipv4_injection(self):
        source=str(ROOT/'build/collect-input.sh')
        for ip in ['$(id)','1.1.1.1;id','001.1.1.1','256.1.1.1','127.0.0.1','1.1.1.1/32']:
            r=subprocess.run(['bash','-c','. "$1"; vk_validate_ipv4 "$2"','test',source,ip],capture_output=True,text=True)
            self.assertNotEqual(r.returncode,0)
    def test_collector_accepts_public_ipv4(self):
        for ip in ['1.1.1.1','8.8.8.8','9.9.9.9']:
            r=subprocess.run(['bash','-c','. "$1"; vk_validate_ipv4 "$2"','test',str(ROOT/'build/collect-input.sh'),ip],capture_output=True,text=True)
            self.assertEqual(r.returncode,0)

if __name__=='__main__':unittest.main()
