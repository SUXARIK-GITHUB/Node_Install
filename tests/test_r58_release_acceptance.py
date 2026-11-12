"""R58: release evidence is never marked accepted without the exact ZIP.

All files are synthetic temporary fixtures; no live network, servers or install.
"""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import sys
from common import ROOT
sys.path.insert(0,str(ROOT/'scripts'))
import staging_acceptance as gate


class ReleaseBindingTests(unittest.TestCase):
    def complete_receipt(self, sha):
        receipt=gate.template('ordinary',sha)
        receipt['status']='ACCEPTED'
        for value in receipt['checks'].values():
            value.update(result='PASS',tested_at_utc='2026-11-13T10:00:00Z',
                         evidence_reference='safe/vps-evidence.txt',operator='test_operator')
        return receipt

    def call(self, argv):
        out,err=io.StringIO(),io.StringIO()
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            code=gate.main(argv)
        return code,out.getvalue(),err.getvalue()

    def test_claimed_acceptance_without_archive_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'receipt.json'
            path.write_text(json.dumps(self.complete_receipt('a'*64)))
            code,_,err=self.call(['--evaluate',str(path)])
            self.assertEqual(code,2)
            self.assertIn('SOURCE_ARCHIVE_REQUIRED_FOR_ACCEPTANCE',err)

    def test_mismatched_archive_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); archive=root/'release.zip'; archive.write_bytes(b'actual ZIP fixture')
            receipt=root/'receipt.json';receipt.write_text(json.dumps(self.complete_receipt('b'*64)))
            code,_,err=self.call(['--evaluate',str(receipt),'--archive',str(archive)])
            self.assertEqual(code,2)
            self.assertIn('SOURCE_ARCHIVE_SHA256_MISMATCH',err)

    def test_exact_archive_binding_allows_only_metadata_complete(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); archive=root/'release.zip'; archive.write_bytes(b'dummy release content')
            digest=hashlib.sha256(archive.read_bytes()).hexdigest()
            receipt=root/'receipt.json';receipt.write_text(json.dumps(self.complete_receipt(digest)))
            code,out,_=self.call(['--evaluate',str(receipt),'--archive',str(archive)])
            self.assertEqual(code,0)
            self.assertIn('SOURCE_ARCHIVE=SHA256_MATCH',out)
            self.assertIn('LIVE_EVIDENCE=OPERATOR_SUBMITTED_NOT_AUTOMATICALLY_VERIFIED',out)

    def test_symlink_and_missing_archive_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); real=root/'real.zip';real.write_bytes(b'content')
            link=root/'link.zip';link.symlink_to(real)
            receipt=root/'receipt.json';receipt.write_text(json.dumps(
                self.complete_receipt(hashlib.sha256(real.read_bytes()).hexdigest())))
            for archive in (link,root/'missing.zip'):
                with self.subTest(archive=archive):
                    code,_,err=self.call(['--evaluate',str(receipt),'--archive',str(archive)])
                    self.assertEqual(code,2)
                    self.assertIn('SOURCE_ARCHIVE_NOT_REGULAR_FILE',err)

    def test_incomplete_template_never_claims_success(self):
        with tempfile.TemporaryDirectory() as td:
            file=Path(td)/'blocked.json'
            file.write_text(json.dumps(gate.template('ordinary','c'*64)))
            code,out,_=self.call(['--evaluate',str(file)])
            self.assertEqual(code,1)
            self.assertIn('EVIDENCE_REVIEW=INCOMPLETE',out)
            self.assertIn('SOURCE_ARCHIVE=NOT_VERIFIED',out)

if __name__=='__main__':
    unittest.main()
