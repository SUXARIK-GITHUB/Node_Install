"""Strict cascade role installers: unit/integration WITHOUT OS, Docker or Panel mutation."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from common import ROOT, SCRIPT, payload
sys.path.insert(0,str(ROOT/'integrations'))
import cascade_deployment as cd
import cascade_profiles as cp


def xkey():
    k = X25519PrivateKey.generate()
    e = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip('=')
    return e(k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())), e(k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def pair():
    def node(name, ip, tag):
        pr, pu = xkey()
        return {'domain':name+'.example.org','ipv4':ip,'private_key':pr,
                'public_key':pu,'short_id':os.urandom(8).hex(), 'inbound_tag':tag}
    return {'schema':1, 'entry':node('entry','8.8.4.4','VK_CASCADE_ENTRY_ABCD'),
            'exit':node('exit','1.1.1.1','VK_CASCADE_EXIT_EFGH'),
            'bridge':{'service_user_uuid':str(uuid.uuid4())}}


def fpriv(path, obj):
    path.write_text(json.dumps(obj))
    path.chmod(0o600)
    return path


class CascadeRoleOffline(unittest.TestCase):
    def test_split_preserves_key_isolation_and_pair_id(self):
        source = pair()
        with tempfile.TemporaryDirectory() as t:
            base=Path(t)
            output=cd.prepare(fpriv(base/'pair.json',source),base/'out')
            e=cd.read_role(output/'entry/role-bundle.json','entry')
            x=cd.read_role(output/'exit/role-bundle.json','exit')
            self.assertEqual(e['pair_id'],x['pair_id'])
            self.assertNotIn(source['exit']['private_key'],(output/'entry/role-bundle.json').read_text())
            self.assertNotIn(source['entry']['private_key'],(output/'exit/role-bundle.json').read_text())
            self.assertNotIn(source['bridge']['service_user_uuid'],
                             (output/'exit/panel-plan.json').read_text())
            self.assertEqual(e['self']['private_key'],source['entry']['private_key'])
            self.assertEqual(x['self']['private_key'],source['exit']['private_key'])
            self.assertEqual(stat.S_IMODE((output/'entry/role-bundle.json').stat().st_mode),0o600)
            self.assertEqual(stat.S_IMODE((output/'entry').stat().st_mode),0o700)
            with self.assertRaisesRegex(cp.Invalid,'OUTPUT_EXISTS'):cd.prepare(base/'pair.json',output)

    def test_pair_rejects_crossed_keys_before_creating_anything(self):
        obj=pair();obj['entry']['public_key']=xkey()[1]
        with tempfile.TemporaryDirectory() as t:
            base=Path(t)
            with self.assertRaisesRegex(cp.Invalid,'REALITY_PRIVATE_PUBLIC_MISMATCH'):
                cd.prepare(fpriv(base/'pair.json',obj),base/'out')
            self.assertFalse((base/'out').exists())

    def test_entry_no_dns_direct_and_exit_direct_only(self):
        source=pair()
        for role in ('entry','exit'):
            b=cd.bundles(cd.validated_pair(source))[role]
            p=cd.role_profile(b)
            own={x['tag'] for x in p['outbounds']}
            if role=='entry':
                self.assertEqual(own,{'BLOCK','TO_EXIT_VLESS'})
                self.assertNotIn('DIRECT',p.__repr__())
                self.assertNotIn('dns',p)
                self.assertEqual(p['outbounds'][1]['settings']['vnext'][0]['address'],source['exit']['ipv4'])
            else:
                self.assertEqual(own,{'DIRECT','BLOCK'})
                self.assertNotIn('TO_EXIT_VLESS',own)
            self.assertEqual(p['inbounds'][0]['streamSettings']['realitySettings']['privateKey'],source[role]['private_key'])

    def test_role_bundle_rejects_corrupted_identity_even_valid_structure(self):
        good=cd.bundles(cd.validated_pair(pair()))['entry']
        changes=[lambda x:x.update(role='ordinary'),
                 lambda x:x['peer'].update(ipv4='127.0.0.1'),
                 lambda x:x['peer'].update(domain=x['self']['domain']),
                 lambda x:x['peer'].update(public_key=x['self']['public_key']),
                 lambda x:x['bridge'].update(service_user_uuid=str(uuid.UUID(int=0))),
                 lambda x:x.update(pair_id='0'*64),
                 lambda x:x['self'].update(private_key=x['peer']['public_key'])]
        for cb in changes:
            with self.subTest(cb=cb):
                altered=json.loads(json.dumps(good))
                cb(altered)
                with self.assertRaises(cp.Invalid):cd.validate_bundle(altered)

    def test_role_state_enrollment_idempotent_and_frozen(self):
        source=pair();good=cd.bundles(cd.validated_pair(source))['entry']
        with tempfile.TemporaryDirectory() as t:
            base=Path(t)
            etc=base/'etc';state=base/'state';etc.mkdir(mode=0o700);state.mkdir(mode=0o700)
            p=fpriv(base/'bundle.json',good)
            pin=hashlib.sha256(p.read_bytes()).hexdigest()
            cd.enrollment(p,etc/'cascade-role.json',state/'role.json','entry',pin)
            marker=cd.installed_role(etc,state)
            cd.ensure_local_identity(marker,source['entry']['domain'],source['entry']['ipv4'])
            with self.assertRaises(cp.Invalid):cd.ensure_local_identity(marker,'other.example.org',source['entry']['ipv4'])
            cd.enrollment(p,etc/'cascade-role.json',state/'role.json','entry',pin)
            with self.assertRaises(cp.Invalid):cd.enrollment(p,etc/'cascade-role.json',state/'role.json','exit',pin)
            with self.assertRaises(cp.Invalid):cd.enrollment(p,etc/'cascade-role.json',state/'role.json','entry','0'*64)
            with self.assertRaises(cp.Invalid):cd.enrollment(p,etc/'cascade-role.json',state/'role.json','entry',pin[:-1]+'0') if pin[-1]!='0' else cd.enrollment(p,etc/'cascade-role.json',state/'role.json','entry','1'*64)
            other=cd.bundles(cd.validated_pair(pair()))['entry']
            fpriv(p,other)
            with self.assertRaises(cp.Invalid):cd.enrollment(p,etc/'cascade-role.json',state/'role.json','entry',hashlib.sha256(p.read_bytes()).hexdigest())
            self.assertEqual(cd.installed_role(etc,state)['pair_id'],good['pair_id'])
            (state/'role.json').unlink()
            with self.assertRaises(cp.Invalid):cd.installed_role(etc,state)

    def test_private_inputs_no_symlink_or_group_read(self):
        with tempfile.TemporaryDirectory() as t:
            base=Path(t)
            p=fpriv(base/'bundle.json',cd.bundles(cd.validated_pair(pair()))['entry'])
            p.chmod(0o640)
            with self.assertRaises(cp.Invalid):cd.read_role(p)
            p.chmod(0o600)
            symlink=base/'link.json'
            symlink.symlink_to(p)
            with self.assertRaises(cp.Invalid):cd.read_role(symlink)
            p.chmod(0o600)
            (base/'unsafe').mkdir(mode=0o777)
            (base/'unsafe').chmod(0o777)
            inp=base/'unsafe/bundle.json'
            fpriv(inp,json.loads(p.read_text()))
            with self.assertRaises(cp.Invalid):cd.read_role(inp)

    def test_cli_never_emits_bridge_uuid_or_secret(self):
        raw=pair()
        with tempfile.TemporaryDirectory() as t:
            base=Path(t)
            spec=fpriv(base/'pair.json',raw)
            cmd=[sys.executable,str(ROOT/'integrations/cascade_deployment.py')]
            r=subprocess.run(cmd+['prepare','--pair',str(spec),'--output',str(base/'out')],
                capture_output=True,text=True,timeout=8)
            self.assertEqual(r.returncode,0,r.stderr)
            q=subprocess.run(cmd+['validate','--bundle',str(base/'out/entry/role-bundle.json'),
                '--role','entry'],capture_output=True,text=True,timeout=8)
            self.assertEqual(q.returncode,0,q.stderr)
            for secret in (raw['bridge']['service_user_uuid'],raw['entry']['private_key'],raw['exit']['private_key']):
                self.assertNotIn(secret,r.stdout+r.stderr+q.stdout+q.stderr)

    def test_node_helper_embedded_cascade_branch_exists_and_acceptance_has_guards(self):
        helper=payload('PY_HELPER')
        self.assertIn('cascade.installed_role(ETC, STATE)',helper)
        self.assertIn('CASCADE_REALITY_KEYS_DRIFT_REFUSE_OVERWRITE',helper)
        self.assertIn('CASCADE_PROFILE_DRIFT_REFUSE_OVERWRITE',helper)
        self.assertIn('CASCADE_IMPORT_PROFILE_DRIFT',helper)
        self.assertIn('cascade.panel_guidance',helper)
        self.assertIn('CASCADE_XHTTP=DISABLED',SCRIPT)
        self.assertIn('CASCADE_ROLE_CRYPTO_OR_IDENTITY_INVALID',SCRIPT)
        self.assertIn('CASCADE_ROLE=ENROLLED', (ROOT/'integrations/cascade_deployment.py').read_text())
        self.assertIn("'etc/vkarmani-node/cascade-role.json'",payload('VK_FINALIZER_PY'))
        self.assertLess(SCRIPT.index('python3 "$LIB/cascade_deployment.py" enroll'),
                        SCRIPT.index("stage 'Базовые инструменты из подписанного репозитория ОС'"))

    def test_actual_embedded_node_helper_generates_immutable_cascade_profiles(self):
        # Execute the *embedded* Python installed on VPS, not a mock generator.
        import types
        from contextlib import redirect_stdout
        import io
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp)
            helper=types.ModuleType('node_helper_cascade_test')
            exec(compile(payload('PY_HELPER'),'embedded-node-helper','exec'),helper.__dict__)
            helper.ETC=base/'etc';helper.STATE=base/'state'
            helper.ETC.mkdir(mode=0o700);helper.STATE.mkdir(mode=0o700)
            cfg=cd.bundles(cd.validated_pair(pair()))['entry']
            inp=fpriv(base/'input.json',cfg)
            cd.enrollment(inp,helper.ETC/'cascade-role.json',helper.STATE/'role.json','entry',
                          hashlib.sha256(inp.read_bytes()).hexdigest())
            c={'domain':cfg['self']['domain'], 'public_ipv4':cfg['self']['ipv4'],
               'panel_ipv4':['9.9.9.9'], 'node_port':2222}
            _,tag,p=helper.make_keys_profile(c)
            self.assertEqual(tag,cfg['self']['inbound_tag'])
            self.assertEqual(p,cd.role_profile(cfg))
            self.assertEqual(json.loads((helper.ETC/'profile.json').read_text()),p)
            with redirect_stdout(io.StringIO()) as log:
                helper.audit_profile(helper.ETC/'profile.json',c)
            self.assertIn('CASCADE_IMPORT_PROFILE_POLICY=PASS',log.getvalue())
            helper.write_panel_guide(c)
            self.assertNotIn(cfg['bridge']['service_user_uuid'],
                             (helper.ETC/'PANEL-SETUP.txt').read_text())
            before=(helper.ETC/'profile.json').read_bytes()
            helper.make_keys_profile(c)
            self.assertEqual((helper.ETC/'profile.json').read_bytes(),before)
            tampered=json.loads(before);tampered['outbounds'].insert(0,{'tag':'DIRECT','protocol':'freedom'})
            fpriv(helper.ETC/'profile.json',tampered)
            with self.assertRaisesRegex(helper.Failure,'CASCADE_PROFILE_DRIFT_REFUSE_OVERWRITE'):
                helper.make_keys_profile(c)

    def test_generated_pair_cli_keeps_0600_and_validates_crypto(self):
        with tempfile.TemporaryDirectory() as t:
            base=Path(t)
            output=cd.create_pair('entry.example.org','8.8.4.4','exit.example.org','1.1.1.1',base/'newpair.json')
            self.assertEqual(stat.S_IMODE(output.stat().st_mode),0o600)
            material=cd.validated_pair(cd.private_file(output))
            self.assertNotEqual(material['entry']['private_key'],material['exit']['private_key'])
            result=cd.prepare(output,base/'roles')
            self.assertTrue((result/'entry/role-bundle.json').is_file())
            with self.assertRaisesRegex(cp.Invalid,'PAIR_OUTPUT_EXISTS'):
                cd.create_pair('entry.example.org','8.8.4.4','exit.example.org','1.1.1.1',output)

    def test_flag_and_installed_guards_before_os_mutation(self):
        cli=str(ROOT/'install.sh')
        for index, arguments in enumerate((['--cascade-role','entry'],
                ['--cascade-bundle','/root/entry.json'],
                ['--cascade-role','not-a-role','--cascade-bundle','/root/x'],
                ['--cascade-role','entry','--cascade-bundle','relative.json'])):
            p=subprocess.run(['bash',cli]+arguments,capture_output=True,text=True,timeout=5)
            # The root permission guard intentionally runs after argument parsing
            # but before any role state/host writes. An unprivileged invocation
            # with valid fragments exits 1; invalid flags exit 2 at the parser.
            expected = 1 if os.geteuid() != 0 and index < 2 else 2
            self.assertEqual(p.returncode, expected, p.stdout+p.stderr)
            if expected == 1:
                self.assertIn('root', p.stdout+p.stderr)
        self.assertLess(SCRIPT.index('CASCADE_ROLE_LOCAL_DOMAIN_IPV4_MISMATCH') if 'CASCADE_ROLE_LOCAL_DOMAIN_IPV4_MISMATCH' in SCRIPT else SCRIPT.index('CASCADE_ROLE_CRYPTO_OR_IDENTITY_INVALID'),
                        SCRIPT.index("stage 'Компоненты ноды из подписанных"))


if __name__=='__main__': unittest.main()
