#!/usr/bin/env python3
"""Offline tests. No Docker daemon, VPS access or production credentials needed.
Run: python3 -m unittest discover -s tests -v
Requires: Python 3.10+, cryptography, Node.js 18+ and Bash.
"""
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import types
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'install.sh').read_text()
NODE = shutil.which('node')

def payload(marker):
    return SOURCE.split("<<'" + marker + "'\n", 1)[1].split('\n' + marker + '\n', 1)[0] + '\n'

def load(code, name):
    m = types.ModuleType(name)
    exec(compile(code, name, 'exec'), m.__dict__)
    return m

TLS = load(payload('VK_PAYLOAD_VK_WRITE_TLS_CHECK'), 'vk_tls_test')
CONNECTION = load((ROOT / 'tools/node_connection.py').read_text(), 'vk_connection_test')

def pemkey(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption()).decode()

def pemcert(c):
    return c.public_bytes(serialization.Encoding.PEM).decode()

class Fixture:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.ca = self.certificate('test-panel-root', self.ca_key, None, True)
        self.server_key = ec.generate_private_key(ec.SECP256R1())
        self.server = self.certificate('random-node-identity', self.server_key, self.ca, False, ExtendedKeyUsageOID.SERVER_AUTH)
        self.client_key = ec.generate_private_key(ec.SECP256R1())
        self.client = self.certificate('panel-client', self.client_key, self.ca, False, ExtendedKeyUsageOID.CLIENT_AUTH)
        self.jwt = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.keys = {
            'ca_cert': pemcert(self.ca), 'client_cert': pemcert(self.client),
            'client_key': pemkey(self.client_key), 'priv_key': pemkey(self.jwt),
            'pub_key': self.jwt.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
        }
        for name, value in {'server.pem': pemcert(self.server), 'server.key': pemkey(self.server_key)}.items():
            path = self.directory / name
            path.write_text(value)
            path.chmod(0o600)
        self.sni = TLS.derive_api_sni(self.keys['ca_cert'], self.keys['pub_key'])
        self.leaf_fp = hashlib.sha256(self.server.public_bytes(serialization.Encoding.DER)).digest()

    def certificate(self, name, key, issuer, is_ca, usage=None):
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        now = datetime.now(timezone.utc)
        b = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject if issuer is None else issuer.subject)
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=1))
             .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()), critical=False)
             .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                 data_encipherment=False, key_agreement=False, key_cert_sign=is_ca, crl_sign=is_ca,
                 encipher_only=False, decipher_only=False), critical=True))
        if usage:
            b = b.add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        return b.sign(self.ca_key, hashes.SHA256())

class Server:
    """TLS 1.3 fixture with mandatory client certificates and RS256 JWT check."""
    def __init__(self, fixture, check_sni=True, response_override=None):
        self.fixture = fixture
        self.response_override = response_override
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = self.context.maximum_version = ssl.TLSVersion.TLSv1_3
        self.context.load_cert_chain(str(fixture.directory/'server.pem'), str(fixture.directory/'server.key'))
        self.context.load_verify_locations(cadata=fixture.keys['ca_cert'])
        self.context.verify_mode = ssl.CERT_REQUIRED
        if check_sni:
            self.context.set_servername_callback(lambda sock, name, ctx: None if name == fixture.sni else ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(10)
        self.listener.settimeout(.15)
        self.port = self.listener.getsockname()[1]
        self.stopped = threading.Event()
        self.requests = []
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stopped.is_set():
            try:
                raw, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                raw.settimeout(3)
                with self.context.wrap_socket(raw, server_side=True) as conn:
                    data = b''
                    while b'\r\n\r\n' not in data and len(data) < 32768:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    lines = data.decode('ascii', errors='replace').split('\r\n')
                    self.requests.append(lines[0])
                    status = 401
                    try:
                        token = next(x.split(' ', 2)[2] for x in lines if x.lower().startswith('authorization: bearer '))
                        head, body, sig = token.split('.')
                        decode = lambda s: base64.urlsafe_b64decode(s+'='*(-len(s)%4))
                        assert json.loads(decode(head))['alg'] == 'RS256'
                        assert json.loads(decode(body))['exp'] > datetime.now(timezone.utc).timestamp()
                        self.fixture.jwt.public_key().verify(decode(sig), (head+'.'+body).encode(), padding.PKCS1v15(), hashes.SHA256())
                        status = 200
                    except Exception:
                        pass
                    assert lines[0] == 'GET /node/xray/healthcheck HTTP/1.1'
                    body = self.response_override if self.response_override is not None else (b'{"response":{"test":true}}' if status == 200 else b'{"error":"unauthorized"}')
                    conn.sendall(f'HTTP/1.1 {status} Test\r\nContent-Length: {len(body)}\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n'.encode()+body)
            except (OSError, ssl.SSLError, AssertionError):
                raw.close()

    def close(self):
        self.stopped.set()
        self.listener.close()
        self.thread.join(4)
    def __enter__(self): return self
    def __exit__(self, *args): self.close()

class SyntaxAndBundleTests(unittest.TestCase):
    def test_bash_syntax(self):
        subprocess.run(['bash', '-n', str(ROOT/'install.sh')], check=True, capture_output=True)
    def test_help_without_side_effects(self):
        r = subprocess.run(['bash', str(ROOT/'install.sh'), '--help'], check=True, capture_output=True, text=True)
        self.assertIn('--repair-connection', r.stdout)
        self.assertIn('--diagnose-panel', r.stdout)
        self.assertIn('1.3.5', r.stdout)
    def test_embedded_python_compiles(self):
        for marker in ('VK_PAYLOAD_VK_WRITE_TLS_CHECK', 'VK_PAYLOAD_VK_WRITE_SELFSTEAL_CHECK', 'PY_HELPER', 'VK_PAYLOAD_NODE_CONNECTION'):
            with self.subTest(marker=marker): compile(payload(marker), marker, 'exec')
    def test_embedded_matches_development_sources(self):
        self.assertEqual(payload('VK_PAYLOAD_NODE_CONNECTION'), (ROOT/'tools/node_connection.py').read_text())
        self.assertEqual(payload('VK_PAYLOAD_PANEL_CHECK'), (ROOT/'tools/panel_check.cjs').read_text())
    @unittest.skipUnless(NODE, 'Node.js is required')
    def test_javascript_syntax(self):
        subprocess.run([NODE, '--check', str(ROOT/'tools/panel_check.cjs')], check=True, capture_output=True)
    def test_full_install_no_oneshot_activation(self):
        full = SOURCE.split('vkarmani_main() {',1)[1].split('vkarmani_repair_main()',1)[0]
        self.assertNotIn('systemctl start vkarmani-node\n', full)
        self.assertIn('vk_write_connection_tools\n', full)
    def test_management_repair_does_not_change_unrelated_services(self):
        repair = SOURCE.split('vkarmani_repair_connection_main() (',1)[1].split('# VKARMANI_COMPLETE_PAYLOAD',1)[0]
        for bad in ('apt-get ', 'ufw reset', 'ufw disable', 'sysctl -w', 'systemctl restart nginx', 'shutdown -r', 'reboot\n', 'helper keys'):
            self.assertNotIn(bad, repair)
        self.assertIn('--force-recreate remnanode', repair)
        self.assertIn('cmp --silent "$ETC/remnanode.env"', repair)
        self.assertIn('connection_repair_error', repair)
    def test_only_read_only_endpoint_and_query(self):
        js = (ROOT/'tools/panel_check.cjs').read_text()
        self.assertIn("path: '/node/xray/healthcheck'", js)
        self.assertNotRegex(js, r"path:\s*['\"][^'\"]*(?:stop|start|restart)")
        self.assertIn('SET TRANSACTION READ ONLY', js)
        self.assertNotIn('SELECT *', js.replace('no SELECT *', ''))
        self.assertNotRegex(js, r'SELECT[^\n]+\bca_key\b')

class ComposeTests(unittest.TestCase):
    def doc(self):
        return {'name':'vkarmani-node', 'services': {'remnanode': {
            'image':'remnawave/node:latest', 'ports':[{'target':2222, 'published':'2222'}],
            'networks':{'default':{}}, 'environment': {'SECRET_KEY':'OLD_TEST_ONLY', 'NODE_PORT':'9999', 'TZ':'UTC', 'SNI_VERIFICATION':'true', 'EXTRA':'cost$1'},
            'volumes':[{'type':'bind','source':'/dev/shm','target':'/dev/shm'}]
        }}}
    def test_reconcile_stale_environment(self):
        doc=CONNECTION.reconcile_compose(self.doc(), {}, 'remnawave/node@sha256:'+'a'*64)
        service=doc['services']['remnanode']
        for key in ('SECRET_KEY','NODE_PORT','TZ'): self.assertNotIn(key, service['environment'])
        self.assertEqual(service['environment']['SNI_VERIFICATION'], 'true')
        self.assertEqual(service['environment']['EXTRA'], 'cost$$1')
        self.assertEqual(service['network_mode'],'host')
        self.assertEqual(service['restart'],'always')
        self.assertNotIn('ports', service)
        self.assertNotIn('networks', service)
        self.assertEqual(service['env_file'], ['/etc/vkarmani-node/remnanode.env'])
    def test_reject_foreign_image(self):
        doc=self.doc(); doc['services']['remnanode']['image']='untrusted/test:latest'
        with self.assertRaises(CONNECTION.Error): CONNECTION.reconcile_compose(doc,{},'remnawave/node@sha256:'+'a'*64)
    def test_reject_extra_services(self):
        doc=self.doc();doc['services']['other']={}
        with self.assertRaises(CONNECTION.Error): CONNECTION.reconcile_compose(doc,{},'remnawave/node@sha256:'+'a'*64)
    def test_reject_mismatched_selfsteal_mount(self):
        doc=self.doc();doc['services']['remnanode']['volumes'][0]['source']='/other'
        with self.assertRaises(CONNECTION.Error): CONNECTION.reconcile_compose(doc,{},'remnawave/node@sha256:'+'a'*64)
    def test_reject_unpinned_image(self):
        with self.assertRaises(CONNECTION.Error): CONNECTION.reconcile_compose(self.doc(),{},'remnawave/node:latest')
    def test_runtime_mismatch(self):
        expected={'NODE_PORT':'2222','SECRET_KEY':'new_test_only','TZ':'Europe/Moscow'}
        inspect={'Config':{'Env':['NODE_PORT=2222','SECRET_KEY=old_test_only','TZ=Europe/Moscow']}}
        result=CONNECTION.runtime_matches(inspect,expected)
        self.assertTrue(result['NODE_PORT']);self.assertFalse(result['SECRET_KEY']);self.assertTrue(result['TZ'])
    def test_runtime_match(self):
        expected={'NODE_PORT':'2222','SECRET_KEY':'new_test_only','TZ':'Europe/Moscow'}
        inspect={'Config':{'Env':[k+'='+v for k,v in expected.items()]}}
        self.assertTrue(all(CONNECTION.runtime_matches(inspect,expected).values()))
    def test_atomic_write_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'compose.yaml'
            CONNECTION.atomic_text(path,'{}\n')
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            self.assertEqual(path.read_text(),'{}\n')

@unittest.skipUnless(NODE, 'Node.js is required for cross-runtime TLS tests')
class ProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.f=Fixture(cls.tmp.name)
    @classmethod
    def tearDownClass(cls): cls.tmp.cleanup()
    def node(self, code, data):
        pre="const m=require("+json.dumps(str(ROOT/'tools/panel_check.cjs'))+");const d=JSON.parse(require('fs').readFileSync(0,'utf8'));"
        r=subprocess.run([NODE,'-e',pre+code],input=json.dumps(data),capture_output=True,text=True,timeout=18)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertNotIn('PRIVATE KEY',r.stdout+r.stderr)
        return json.loads(r.stdout)
    def api(self, server, keys=None, options=None):
        return self.node("m.probe('127.0.0.1',d.port,d.keys,d.options).then(x=>console.log(JSON.stringify(x)));",
                         {'port':server.port, 'keys':keys or self.f.keys, 'options': options or {'timeout':4000}})
    def test_hkdf_python_matches_node_crypto(self):
        result=self.node("console.log(JSON.stringify(m.deriveSni(d.ca,d.jwt)));",{'ca':self.f.keys['ca_cert'],'jwt':self.f.keys['pub_key']})
        self.assertEqual(result,self.f.sni)
    def test_hkdf_whitespace_normalization(self):
        ca=self.f.keys['ca_cert'].replace('\n','\r\n')
        jwt=self.f.keys['pub_key'].replace('\n','\\n')
        self.assertEqual(TLS.derive_api_sni(ca,jwt),self.f.sni)
        self.assertEqual(self.node("console.log(JSON.stringify(m.deriveSni(d.ca,d.jwt)));",{'ca':ca,'jwt':jwt}),self.f.sni)
    def test_original_selfsteal_sni_fails(self):
        with Server(self.f) as server:
            ok,detail,_=TLS.probe('127.0.0.1',server.port,'cover.example.com',self.f.keys['ca_cert'],self.f.leaf_fp,timeout=3)
        self.assertFalse(ok);self.assertIn('TLS',detail)
    def test_correct_sni_local_tls_passes_without_claiming_mtls(self):
        with Server(self.f) as server:
            ok,detail,_=TLS.probe('127.0.0.1',server.port,self.f.sni,self.f.keys['ca_cert'],self.f.leaf_fp,timeout=3)
        self.assertTrue(ok,detail);self.assertEqual(detail,'TLS13_CA_AND_LEAF_OK')
    def test_fragmented_large_clienthello(self):
        with Server(self.f) as server:
            ok,detail,length=TLS.probe('127.0.0.1',server.port,self.f.sni,self.f.keys['ca_cert'],self.f.leaf_fp,fragmented=True,timeout=3)
        self.assertTrue(ok,detail);self.assertGreater(length,1500)
    def test_local_leaf_mismatch_detected(self):
        with Server(self.f) as server:
            ok,detail,_=TLS.probe('127.0.0.1',server.port,self.f.sni,self.f.keys['ca_cert'],b'X'*32,timeout=3)
        self.assertFalse(ok);self.assertEqual(detail,'TLS_LEAF_MISMATCH')
    def test_authenticated_panel_api(self):
        with Server(self.f) as server: result=self.api(server)
        self.assertTrue(result['ok'],result);self.assertEqual(result['status'],200)
        self.assertEqual(server.requests,['GET /node/xray/healthcheck HTTP/1.1'])
    def test_node_stdin_entrypoint_arguments(self):
        r=subprocess.run([NODE,'-','127.0.0.1','2222'],input=(ROOT/'tools/panel_check.cjs').read_text(),capture_output=True,text=True,timeout=5)
        self.assertEqual(r.returncode,2)
        self.assertIn('PRISMA_NOT_AVAILABLE',r.stderr)
    def test_wrong_jwt_rejected(self):
        keys=dict(self.f.keys);keys['priv_key']=pemkey(rsa.generate_private_key(public_exponent=65537,key_size=2048))
        with Server(self.f) as server: result=self.api(server,keys)
        self.assertFalse(result['ok']);self.assertEqual(result['status'],401)
    def test_server_certificate_cannot_authenticate_as_panel(self):
        keys=dict(self.f.keys);keys['client_cert']=pemcert(self.f.server);keys['client_key']=pemkey(self.f.server_key)
        with Server(self.f) as server: result=self.api(server,keys)
        self.assertFalse(result['ok']);self.assertNotEqual(result.get('status'),200)
    def test_wrong_ca_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            other=Fixture(tmp);keys=dict(self.f.keys);keys['ca_cert']=other.keys['ca_cert']
            with Server(self.f,check_sni=False) as server: result=self.api(server,keys)
        self.assertFalse(result['ok']);self.assertNotEqual(result.get('status'),200)
    def test_classic_curve_diagnostic(self):
        with Server(self.f) as server: result=self.api(server,options={'curve':'X25519','timeout':4000})
        self.assertTrue(result['ok'],result)
    def test_http200_without_contract_not_success(self):
        with Server(self.f,response_override=b'{"some":"other service"}') as server: result=self.api(server)
        self.assertFalse(result['ok']);self.assertEqual(result['status'],200)
    def test_tcp_refused_is_not_tls_error(self):
        with socket.socket() as s:
            s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        result=self.node("m.probe('127.0.0.1',d.port,d.keys,{timeout:2000}).then(x=>console.log(JSON.stringify(x)));",{'port':port,'keys':self.f.keys})
        self.assertFalse(result['ok']);self.assertEqual(result['stage'],'TCP')
    def test_target_validation(self):
        result=self.node("let out=[]; for (const h of d) {try{m.validateTarget(h,2222);out.push(true)}catch(_){out.push(false)}}console.log(JSON.stringify(out));",
                         ['127.0.0.1','node.example.com','https://node.example.com','--bad','node.example.com/path','::1'])
        self.assertEqual(result,[True,True,False,False,False,False])

if __name__ == '__main__': unittest.main()
