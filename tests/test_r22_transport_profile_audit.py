"""R22: transport audit must be conservative, read-only and secret-safe."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from common import ROOT
sys.path.insert(0,str(ROOT/'integrations'))
import transport_profile_audit as audit


class ProfileAudit(unittest.TestCase):
    def base(self, filename='inbound-raw-full.example.json'):
        return json.loads((ROOT/'examples'/filename).read_text())

    def test_supported_raw_and_xhttp_examples_are_statically_valid(self):
        for filename, expected in [('inbound-raw-full.example.json','raw'),
                                   ('inbound-xhttp-full.example.json','xhttp')]:
            with self.subTest(filename=filename):
                result=audit.audit(self.base(filename),'node.example.com')
                self.assertEqual(result['status'],'STATIC_PASS',result)
                self.assertEqual(result['modes'][0]['network'],expected)
                self.assertEqual(result['actions_performed'],'NONE')

    def test_reality_unix_xver_and_sni_mismatch_fail(self):
        o=self.base()
        o['inbounds'][0]['streamSettings']['realitySettings']['xver']=0
        self.assertIn('SELFSTEAL_UNIX_PROXY_PROTOCOL_VERSION_MISMATCH',audit.audit(o)['issues'])
        o=self.base()
        o['inbounds'][0]['streamSettings']['realitySettings']['serverNames']=['invalid;thing']
        self.assertIn('REALITY_SNI_LIST_INVALID',audit.audit(o)['issues'])
        o=self.base()
        o['inbounds'][0]['streamSettings']['realitySettings']['target']='external.example.com:443'
        self.assertEqual(audit.audit(o)['status'],'REVIEW')
        self.assertIn('REALITY_TARGET_NOT_OWN_REVIEWED_SOCKET',audit.audit(o)['observations'])

    def test_xhttp_vision_or_bad_path_is_rejected(self):
        o=self.base('inbound-xhttp-full.example.json')
        o['inbounds'][0]['settings']['flow']='xtls-rprx-vision'
        o['inbounds'][0]['streamSettings']['xhttpSettings']['path']='/../admin'
        self.assertEqual(audit.audit(o)['status'],'FAIL')
        self.assertIn('XHTTP_MUST_NOT_USE_VISION_FLOW',audit.audit(o)['issues'])
        self.assertIn('XHTTP_PATH_INVALID',audit.audit(o)['issues'])

    def test_tls_xhttp_not_claimed_ready_without_live_test(self):
        o=self.base('inbound-xhttp-full.example.json')
        o['inbounds'][0]['streamSettings']['security']='tls'
        o['inbounds'][0]['streamSettings'].pop('realitySettings')
        result=audit.audit(o)
        self.assertEqual(result['status'],'REVIEW')
        self.assertIn('XHTTP_TLS_REVERSE_PROXY_REQUIRES_LIVE_TEST',result['observations'])

    def test_cascade_entry_failclosed_rule(self):
        o=self.base('cascade-entry-profile.reference.json')
        self.assertEqual(audit.audit(o)['status'],'STATIC_PASS')
        o['outbounds'].append({'tag':'DIRECT','protocol':'freedom'})
        self.assertEqual(audit.audit(o)['status'],'FAIL')
        self.assertIn('CASCADE_ENTRY_FAIL_CLOSED_OUTBOUNDS_MISMATCH',audit.audit(o)['issues'])

    def test_duplicate_keys_symlinks_sensitive_values_not_printed(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'test.json'
            p.write_text('{"x":1,"x":2}')
            with self.assertRaises(ValueError):audit.secret_free_json(p)
            o=self.base();o['inbounds'][0]['streamSettings']['realitySettings']['privateKey']='HIGHLY_PRIVATE_SECRET_NEVER_PRINT'
            p.write_text(json.dumps(o))
            cmd=[sys.executable,str(ROOT/'integrations/transport_profile_audit.py'),str(p)]
            r=subprocess.run(cmd,capture_output=True,text=True,timeout=6)
            self.assertEqual(r.returncode,0,r.stderr)
            self.assertNotIn('HIGHLY_PRIVATE',r.stdout+r.stderr)
            link=Path(td)/'link.json';link.symlink_to(p)
            r=subprocess.run(cmd[:-1]+[str(link)],capture_output=True,text=True,timeout=6)
            self.assertEqual(r.returncode,1)
            self.assertIn('PROFILE_FILE_UNREADABLE_OR_INVALID',r.stdout)
            self.assertNotIn(str(p),r.stdout+r.stderr)

if __name__=='__main__':unittest.main()
