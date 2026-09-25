#!/usr/bin/env python3
"""Offline tests; use only synthetic keys, temp directories and command mocks."""
import base64
import contextlib
import datetime as dt
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('h', ROOT/'build/node_helper.py')
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)

def config(**kw):
    c={'installation_mode': h.MODE, 'domain':'ee1.example.com', 'public_ipv4':'8.8.4.4',
       'panel_ipv4':['1.1.1.1'], 'node_port':2222}
    c.update(kw)
    return c

def bundle(expired=False):
    ca_key=ec.generate_private_key(ec.SECP256R1())
    leaf_key=ec.generate_private_key(ec.SECP256R1())
    now=dt.datetime.now(dt.timezone.utc)
    ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Synthetic CA for offline test')])
    leaf_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Synthetic node for offline test')])
    ca=(x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-dt.timedelta(days=10)).not_valid_after(now+dt.timedelta(days=100))
        .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(ca_key,hashes.SHA256()))
    leaf=(x509.CertificateBuilder().subject_name(leaf_name).issuer_name(ca_name)
          .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-dt.timedelta(days=5))
          .not_valid_after(now+dt.timedelta(days=-1 if expired else 50))
          .sign(ca_key,hashes.SHA256()))
    return {'nodeCertPem':leaf.public_bytes(ser.Encoding.PEM).decode(),
            'nodeKeyPem':leaf_key.private_bytes(ser.Encoding.PEM,ser.PrivateFormat.PKCS8,ser.NoEncryption()).decode(),
            'caCertPem':ca.public_bytes(ser.Encoding.PEM).decode(),
            'jwtPublicKey':ca_key.public_key().public_bytes(ser.Encoding.PEM,ser.PublicFormat.SubjectPublicKeyInfo).decode()}

def encode(obj):
    return base64.b64encode(json.dumps(obj).encode()).decode()

class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        c=h.normalize_config(config())
        self.assertEqual(c['node_port'],2222)
        self.assertEqual(c['panel_ipv4'],['1.1.1.1'])
        self.assertTrue(c['auto_reboot'])
        self.assertTrue(c['certbot_dry_run'])
        self.assertEqual(c['image'],'remnawave/node:latest')
    def test_forbid_panel_api_credentials(self):
        for field in ['api_token','api_headers','panel_url','email','squad','SECRET_KEY']:
            with self.subTest(field=field),self.assertRaises(h.Failure):
                h.normalize_config(config(**{field:'UNTRUSTED'}))
    def test_refuse_api_installer_state(self):
        with self.assertRaises(h.Failure):h.normalize_config({'domain':'ee1.example.com','panel_url':'https://example.com'})
    def test_domain_normalization(self):
        self.assertEqual(h.domain(' EE1.EXAMPLE.COM. '),'ee1.example.com')
    def test_domain_injections_and_invalid_values(self):
        for d in ['x.com;id','$(id)','a.com\ninclude x','../etc/passwd','https://x.com',
                  '*.x.com','1.2.3.4','-x.com','a..com','a'*64+'.com',None]:
            with self.subTest(d=d),self.assertRaises(h.Failure):h.domain(d)
    def test_ipv4_only(self):
        for ip in ['::1','2606:4700::1111','10.0.0.1','127.0.0.1','169.254.169.254','1.1.1.0/24','224.0.0.1',None]:
            with self.subTest(ip=ip),self.assertRaises(h.Failure):h.public_ipv4(ip)
    def test_invalid_config_types(self):
        for kw in [{'node_port':True},{'node_port':8444},{'node_port':65536},{'node_port':80},
                   {'panel_ipv4':[]},{'panel_ipv4':['0.0.0.0']},{'auto_reboot':'false'},
                   {'image':'attacker/node:latest'},{'image':'remnawave/node:latest;id'}]:
            with self.subTest(kw=kw),self.assertRaises(h.Failure):h.normalize_config(config(**kw))
    def test_ip_discovery(self):
        result=subprocess.CompletedProcess([],0,json.dumps([{'dev':'eth0','prefsrc':'8.8.4.4'}]),'')
        with patch.object(h.subprocess,'run',return_value=result) as run:
            self.assertEqual(h.detect_public_ipv4(),'8.8.4.4')
            self.assertEqual(run.call_args[0][0],['ip','-j','-4','route','get','1.1.1.1'])
    def test_refuse_nat_discovery(self):
        result=subprocess.CompletedProcess([],0,'[{"prefsrc":"10.0.0.5"}]','')
        with patch.object(h.subprocess,'run',return_value=result),self.assertRaises(h.Failure):h.detect_public_ipv4()

class SecretTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.data=bundle();cls.key=encode(cls.data)
    def test_valid_bundle(self):self.assertEqual(h.normalize_secret(self.key,True),self.key)
    def test_assignment_quotes(self):self.assertEqual(h.normalize_secret('SECRET_KEY="'+self.key+'"'),self.key)
    def test_urlsafe_unpadded(self):
        s=base64.urlsafe_b64encode(json.dumps(self.data).encode()).decode().rstrip('=')
        self.assertEqual(h.normalize_secret(s),s)
    def test_invalid_key_hidden_in_error(self):
        secret='sensitive-value-that-is-not-valid-'+('x'*100)
        with self.assertRaises(h.Failure) as result:h.normalize_secret(secret)
        self.assertNotIn(secret,str(result.exception))
    def test_reject_missing_fields(self):
        c=dict(self.data);c.pop('jwtPublicKey')
        with self.assertRaises(h.Failure):h.normalize_secret(encode(c))
    def test_reject_mismatched_private_key(self):
        c=dict(self.data);c['nodeKeyPem']=bundle()['nodeKeyPem']
        with self.assertRaises(h.Failure):h.normalize_secret(encode(c))
    def test_reject_wrong_ca(self):
        c=dict(self.data);c['caCertPem']=bundle()['caCertPem']
        with self.assertRaises(h.Failure):h.normalize_secret(encode(c))
    def test_expiry_checked_only_after_ntp(self):
        key=encode(bundle(True))
        h.normalize_secret(key,False)
        with self.assertRaises(h.Failure):h.normalize_secret(key,True)
    def test_literal_pem_newlines(self):
        c={k:v.replace('\n','\\n') for k,v in self.data.items()}
        h.normalize_secret(encode(c))
    def test_reject_newlines_in_secret(self):
        with self.assertRaises(h.Failure):h.normalize_secret(self.key[:100]+'\n'+self.key[100:])
    def test_reject_shell_env_injection(self):
        for key in ['$(touch /tmp/x)','x\nNODE_PORT=22','"; echo secret;',self.key+'$HOME']:
            with self.subTest(),self.assertRaises(h.Failure):h.normalize_secret(key)

class StateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.key=encode(bundle())
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.etc=Path(self.temp.name)/'etc';self.state=Path(self.temp.name)/'state'
        self.p1=patch.object(h,'ETC',self.etc);self.p2=patch.object(h,'STATE',self.state)
        self.p1.start();self.p2.start()
    def tearDown(self):self.p2.stop();self.p1.stop();self.temp.cleanup()
    def install(self):
        with patch.object(h,'detect_public_ipv4',return_value='8.8.4.4'),\
             patch.object(h,'dns_check') as dns,\
             patch.object(h.sys,'stdin',io.StringIO(self.key+'\n1.1.1.1\nee1.example.com\n')),\
             contextlib.redirect_stdout(io.StringIO()) as output:
            h.init_config()
        return dns,output.getvalue()
    def test_stdin_inputs_and_no_secret_in_output(self):
        dns,out=self.install();dns.assert_called_once()
        self.assertNotIn(self.key,out)
        c=h.read_json(self.etc/'config.json')
        self.assertNotIn(self.key,json.dumps(c))
        self.assertEqual(c['panel_ipv4'],['1.1.1.1'])
        self.assertFalse((self.etc/'api-auth.json').exists())
    def test_no_panel_ip_default(self):
        with patch.object(h.sys,'stdin',io.StringIO(self.key+'\n\nee1.example.com\n')),self.assertRaises(h.Failure):
            h.init_config()
        self.assertFalse((self.etc/'config.json').exists())
    def test_invalid_input_count(self):
        for inputs in [[], [self.key], [self.key,'1.1.1.1'], [self.key,'1.1.1.1','ee1.example.com','EXTRA']]:
            with self.subTest(count=len(inputs)),self.assertRaises(h.Failure): h.init_config(inputs=inputs)
    def test_dns_failure_does_not_commit_config(self):
        with patch.object(h,'detect_public_ipv4',return_value='8.8.4.4'),\
             patch.object(h,'dns_check',side_effect=h.Failure('DNS failure')),self.assertRaises(h.Failure):
            h.init_config(inputs=[self.key,'1.1.1.1','ee1.example.com'])
        self.assertFalse((self.etc/'config.json').exists())
        self.assertFalse((self.etc/'remnanode.env').exists())
    def test_panel_and_node_cannot_be_same(self):
        with patch.object(h,'detect_public_ipv4',return_value='1.1.1.1'),self.assertRaises(h.Failure):
            h.init_config(inputs=[self.key,'1.1.1.1','ee1.example.com'])
    def test_secret_file_permissions(self):
        self.install()
        self.assertEqual((self.etc/'remnanode.env').stat().st_mode & 0o777,0o600)
        self.assertEqual((self.etc/'config.json').stat().st_mode & 0o777,0o600)
        h.check_secret(h.normalize_config(h.read_json(self.etc/'config.json')))
    def test_resume_does_not_read_stdin(self):
        self.install();before=(self.etc/'remnanode.env').read_bytes()
        with patch.object(h,'detect_public_ipv4',return_value='8.8.4.4'),\
             patch.object(h.sys,'stdin') as stream,contextlib.redirect_stdout(io.StringIO()):
            h.init_config()
            stream.read.assert_not_called()
        self.assertEqual((self.etc/'remnanode.env').read_bytes(),before)
    def test_resume_rejects_ip_change(self):
        self.install()
        with patch.object(h,'detect_public_ipv4',return_value='8.8.8.8'),self.assertRaises(h.Failure):h.init_config()
    def test_secret_permissions_enforced(self):
        self.install();(self.etc/'remnanode.env').chmod(0o644)
        with self.assertRaises(h.Failure):h.check_secret(h.normalize_config(h.read_json(self.etc/'config.json')))
    def test_profile_xhttp_and_stable_keys(self):
        c=h.normalize_config(config());h.make_keys_profile(c)
        before=(self.etc/'reality.json').read_bytes()
        first=(self.etc/'profile.json').read_bytes()
        h.make_keys_profile(c)
        self.assertEqual((self.etc/'reality.json').read_bytes(),before)
        self.assertEqual((self.etc/'profile.json').read_bytes(),first)
        p=json.loads(first);i=p['inbounds'][0]
        self.assertEqual(i['streamSettings']['network'],'xhttp')
        self.assertEqual(i['streamSettings']['security'],'reality')
        self.assertEqual(i['settings']['clients'],[])
        self.assertNotIn('flow',i['settings'])
        self.assertEqual(i['listen'],'0.0.0.0')
    def test_panel_guide_does_not_include_private_keys(self):
        self.install();h.write_panel_guide(h.normalize_config(config()))
        guide=(self.etc/'PANEL-SETUP.txt').read_text()
        keys=h.read_json(self.etc/'reality.json')
        self.assertNotIn(self.key,guide);self.assertNotIn(keys['private_key'],guide)
        self.assertIn('1.1.1.1',guide);self.assertIn('2222',guide)
        self.assertIn('НЕ live-конфиг',guide)

class DNSTests(unittest.TestCase):
    def answer(self,cmd,**kwargs):
        kind=cmd[-1]
        text=';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 10\n'
        if kind=='A':text+='ee1.example.com. 300 IN A 8.8.4.4\n'
        return subprocess.CompletedProcess(cmd,0,text,'')
    def test_three_resolvers_a_and_aaaa(self):
        with patch.object(h.subprocess,'run',side_effect=self.answer) as run,contextlib.redirect_stdout(io.StringIO()):
            h.dns_check(h.normalize_config(config()))
        self.assertEqual(run.call_count,6)
        self.assertTrue(all('-4' in x[0][0] for x in run.call_args_list))
    def test_reject_servfail(self):
        r=subprocess.CompletedProcess([],0,';; status: SERVFAIL,\n','')
        with patch.object(h.subprocess,'run',return_value=r),self.assertRaises(h.Failure):h.dns_check(h.normalize_config(config()))
    def test_reject_aaaa(self):
        def answer(cmd,**kw):
            r=self.answer(cmd,**kw)
            if cmd[-1]=='AAAA':r.stdout+='ee1.example.com. 300 IN AAAA 2606:4700::1111\n'
            return r
        with patch.object(h.subprocess,'run',side_effect=answer),self.assertRaises(h.Failure):h.dns_check(h.normalize_config(config()))

class HealthStateTests(unittest.TestCase):
    def run_summary(self,mode='--normal',f=0,xray=0,cover=0):
        source=(ROOT/'build/health.sh').read_text()
        tail=source[source.index('warn PANEL_CONNECTION'):]
        with tempfile.TemporaryDirectory() as directory:
            prefix=f'''F={f}; XRAY_PRESENT={xray}; XRAY_COVER_OK={cover}; MODE={mode}; STATE={directory}
warn(){{ :; }}; pass(){{ :; }}; fail(){{ F=1; }}; helper(){{ return 0; }}
'''
            return subprocess.run(['bash','-c',prefix+tail],capture_output=True,text=True)
    def test_pending_not_vpn_pass(self):
        r=self.run_summary();self.assertEqual(r.returncode,0)
        self.assertIn('NODE_SETUP=PASS',r.stdout)
        self.assertIn('VPN_STATUS=WAITING_FOR_PANEL_PROFILE',r.stdout)
        self.assertNotIn('ACCEPTANCE=PASS',r.stdout)
    def test_strict_pending_nonzero(self):self.assertEqual(self.run_summary('--require-xray').returncode,2)
    def test_local_xray_does_not_claim_panel_verified(self):
        r=self.run_summary('--require-xray',xray=1,cover=1)
        self.assertEqual(r.returncode,0)
        self.assertIn('PANEL_CONNECTION=NOT_VERIFIED',r.stdout)
        self.assertIn('CLIENT_NOT_TESTED',r.stdout)
    def test_infrastructure_error_blocks_install(self):
        r=self.run_summary('--preboot',f=1,xray=1,cover=1)
        self.assertEqual(r.returncode,1);self.assertIn('NODE_SETUP=FAIL',r.stdout)
    def test_existing_unmatched_cover_not_confirmed(self):
        r=self.run_summary('--require-xray',xray=1,cover=0)
        self.assertEqual(r.returncode,2);self.assertIn('PROFILE_NOT_CONFIRMED',r.stdout)

if __name__=='__main__':unittest.main(verbosity=2)
