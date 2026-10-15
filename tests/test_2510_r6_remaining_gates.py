"""r6 fail-closed extensions. Offline: never use real Panel, UFW or Docker."""
import copy
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from common import ROOT, module, payload
sys.path.insert(0,str(ROOT/'integrations'))
import cascade_deployment as cd
import cascade_panel_inventory as inventory
import cascade_live_gate as live
import cascade_panel_audit as panel
import cascade_recovery as recovery
from test_2510_r5_cascade_roles import pair, fpriv


def ready():
    b=cd.bundles(cd.validated_pair(pair()))
    e,x=b['entry'],b['exit']
    now=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(days=365)).isoformat()
    cfg={
        'schema':1,'panel_api_major':3,
        'nodes':[
            {'role':'entry','uuid':'node-entry','address':e['self']['ipv4'], 'port':2222,
             'profile_uuid':'p-entry','active_inbounds':[e['self']['inbound_tag']]},
            {'role':'exit','uuid':'node-exit','address':x['self']['ipv4'], 'port':2222,
             'profile_uuid':'p-exit','active_inbounds':[x['self']['inbound_tag']]},
        ],
        'profiles':[{'uuid':'p-entry','inbound_tags':[e['self']['inbound_tag']]},
                    {'uuid':'p-exit','inbound_tags':[x['self']['inbound_tag']]}],
        'squads':[{'purpose':'clients','uuid':'s-entry', 'inbound_tags':[e['self']['inbound_tag']]},
                  {'purpose':'bridge','uuid':'s-exit', 'inbound_tags':[x['self']['inbound_tag']]}],
        'hosts':[{'inbound_tag':e['self']['inbound_tag'],'node_uuid':'node-entry'}],
        'users':[{'purpose':'bridge','vlessUuid':e['bridge']['service_user_uuid'],
                  'status':'ACTIVE', 'active_internal_squads':['s-exit'],'expireAt':now}]
    }
    return e,x,cfg


class OfflinePanelInventory(unittest.TestCase):
    def test_exact_isolated_pair(self):
        e,x,obj=ready()
        self.assertEqual(inventory.check(e,x,obj)['status'],'PASS')
        self.assertEqual(inventory.check(e,x,obj)['bridge_vless_uuid_matches'],True)

    def test_roles_cross_and_missing_objects_fail(self):
        e,x,obj=ready()
        for mutate in (
            lambda z:z['nodes'][0].update(address='8.8.8.8'),
            lambda z:z['nodes'][1].update(profile_uuid='p-entry'),
            lambda z:z['nodes'][0]['active_inbounds'].append('EXTRA'),
            lambda z:z['profiles'][1]['inbound_tags'].append('DIRECT'),
            lambda z:z['squads'][1].update(inbound_tags=[e['self']['inbound_tag']]),
            lambda z:z['squads'][1]['inbound_tags'].append(e['self']['inbound_tag']),
            lambda z:z['hosts'][0].update(node_uuid='node-exit'),
            lambda z:z['users'][0].update(vlessUuid='bad'),
            lambda z:z['users'][0].update(active_internal_squads=['s-entry','s-exit']),
            lambda z:z['users'][0].update(status='DISABLED'),
            lambda z:z['users'][0].update(expireAt='2020-01-01T00:00:00Z'),
            lambda z:z.update(panel_api_major=2),
            lambda z:z['nodes'].append(z['nodes'][0]),
        ):
            with self.subTest(mutate=mutate):
                v=copy.deepcopy(obj);mutate(v)
                with self.assertRaises(inventory.InventoryError):inventory.check(e,x,v)
        # The generated opposite role private bundle must not leak into this role.
        p=copy.deepcopy(x);p['pair_id']='0'*64
        with self.assertRaises(cd.DeploymentError):inventory.check(e,p,obj)

    def test_cli_inventory_does_not_echo_user_uuid(self):
        e,x,obj=ready()
        from subprocess import run
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp)
            entry=fpriv(d/'entry.json',e)
            exit_=fpriv(d/'exit.json',x)
            obs=fpriv(d/'inventory.json',obj)
            args=[sys.executable,str(ROOT/'integrations/cascade_panel_inventory.py'),
                  '--entry-bundle',str(entry),'--exit-bundle',str(exit_),
                  '--inventory',str(obs)]
            p=run(args,capture_output=True,text=True,timeout=10)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertNotIn(e['bridge']['service_user_uuid'],p.stdout+p.stderr)
            obs.chmod(0o644)
            p=run(args,capture_output=True,text=True,timeout=10)
            self.assertNotEqual(p.returncode,0)


class RknPeerException(unittest.TestCase):
    def setUp(self):
        self.guard=module('VK_RKN_GUARD_PY')
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base=Path(self.temp.name)
        self.guard.CONFIG=fpriv(base/'node.json',{'installation_mode':'secret-key-only',
                                                 'panel_ipv4':['9.9.9.9']})
        self.guard.CASCADE_ROLE=base/'cascade-role.json'
        self.guard.CASCADE_MARKER=base/'role.json'
        self.bundles=cd.bundles(cd.validated_pair(pair()))

    def role(self,what):
        b=self.bundles[what]
        fpriv(self.guard.CASCADE_ROLE,b)
        fpriv(self.guard.CASCADE_MARKER,{'schema':2,'role':b['role'],'pair_id':b['pair_id']})

    def test_ordinary_and_entry_do_not_change_panel_exceptions(self):
        self.assertEqual(self.guard.trusted_exception_ips(), ['9.9.9.9'])
        self.role('entry')
        self.assertEqual(self.guard.trusted_exception_ips(), ['9.9.9.9'])

    def test_exit_exception_for_pinned_entry_only(self):
        self.role('exit')
        ip=self.bundles['exit']['peer']['ipv4']
        self.assertEqual(set(self.guard.trusted_exception_ips()), {'9.9.9.9',ip})
        recorded=[]
        with (patch.object(self.guard,'ipset_stage',side_effect=lambda *args: recorded.append(args)),
              patch.object(self.guard,'run',return_value='')):
            self.guard.panel_refresh()
        self.assertEqual(set(recorded[0][1]),{ip,'9.9.9.9'})
        self.assertEqual(self.guard.panel_ips(),['9.9.9.9'])  # Node API ACL unchanged

    def test_torn_marker_changed_peer_symlink_or_world_readable_rejected(self):
        self.role('exit')
        b=copy.deepcopy(self.bundles['exit'])
        b['peer']['ipv4']='8.8.8.8'
        fpriv(self.guard.CASCADE_ROLE,b)
        with self.assertRaises(self.guard.GuardError):self.guard.trusted_exception_ips()
        self.role('exit')
        self.guard.CASCADE_MARKER.unlink()
        with self.assertRaises(self.guard.GuardError):self.guard.trusted_exception_ips()
        self.role('exit')
        self.guard.CASCADE_ROLE.chmod(0o644)
        with self.assertRaises(self.guard.GuardError):self.guard.trusted_exception_ips()
        self.role('exit')
        self.guard.CASCADE_ROLE.unlink();self.guard.CASCADE_ROLE.symlink_to(self.guard.CASCADE_MARKER)
        with self.assertRaises(self.guard.GuardError):self.guard.trusted_exception_ips()

    def test_embedded_matches_separate_reviewed_file(self):
        self.assertEqual(payload('VK_RKN_GUARD_PY'),
                         (ROOT/'integrations/rkn_guard.py').read_text())


class LocalRecovery(unittest.TestCase):
    def test_backup_verify_tamper_refusal_and_no_overwrite(self):
        b=cd.bundles(cd.validated_pair(pair()))['entry']
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);s=d/'source';s.mkdir(mode=0o700)
            for name in recovery.REQUIRED:
                f=s/name;f.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                if name.endswith('cascade-role.json'):v=b
                elif name.endswith('role.json'):v={'schema':2,'role':b['role'],'pair_id':b['pair_id']}
                else:v={'installation_mode':'secret-key-only','domain':b['self']['domain'],
                        'public_ipv4':b['self']['ipv4'],'SECRET_KEY':'test-value'}
                fpriv(f,v)
            target=d/'protected-backup.zip'
            self.assertEqual(recovery.create(s,target),b['pair_id'])
            self.assertEqual(recovery.check(target)['pair_id'],b['pair_id'])
            self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o600)
            self.assertNotIn(b['self']['private_key'],repr(recovery.check(target)))
            with self.assertRaises(recovery.RecoveryError):recovery.create(s,target)
            damaged=d/'damaged.zip'
            with zipfile.ZipFile(target) as z, zipfile.ZipFile(damaged,'w') as dst:
                for name in z.namelist():
                    data=z.read(name)
                    if name == 'etc/vkarmani-node/config.json':
                        data=data.replace(b'test-value',b'another-secret')
                    dst.writestr(name,data)
            damaged.chmod(0o600)
            with self.assertRaises(recovery.RecoveryError):recovery.check(damaged)
            f=s/recovery.REQUIRED[0]
            f.unlink();f.symlink_to(s/recovery.REQUIRED[1])
            with self.assertRaises(recovery.RecoveryError):recovery.create(s,d/'second.zip')
            self.assertFalse((d/'second.zip').exists())


class NodeColdConfigAudit(unittest.TestCase):
    def test_offline_cold_config_and_no_trusting_missing_client(self):
        e,x,obj=ready()
        for role,bundle in (('entry',e),('exit',x)):
            p=cd.role_profile(bundle)
            import uuid
            p['inbounds'][0]['settings']['clients']=[{
                'id':bundle['bridge']['service_user_uuid'] if role=='exit' else str(uuid.uuid4()),
                'flow':'xtls-rprx-vision'}]
            self.assertEqual(panel.audit(bundle,p)['status'],'PASS')
            p['inbounds'][0]['settings']['clients']=[]
            with self.assertRaises(panel.PanelPolicyError):panel.audit(bundle,p)

    def test_real_dump_never_shells_and_fails_without_root(self):
        with patch.object(live.os,'geteuid',return_value=1000):
            with self.assertRaisesRegex(ValueError,'ROOT_REQUIRED'):
                live.capture_cold()
        with patch.object(live.os,'geteuid',return_value=0),patch.object(live.subprocess,'run') as runner:
            b=cd.bundles(cd.validated_pair(pair()))['exit'];p=cd.role_profile(b)
            p['inbounds'][0]['settings']['clients']=[{'id':b['bridge']['service_user_uuid'],'flow':'xtls-rprx-vision'}]
            runner.return_value.returncode=0
            runner.return_value.stdout=json.dumps(p).encode()
            runner.return_value.stderr=b''
            self.assertEqual(panel.audit(b,live.capture_cold())['status'],'PASS')
            args,kwargs=runner.call_args
            self.assertEqual(args[0],['/usr/local/sbin/vkarmani-docker-local','exec','remnanode','cli','--dump-config'])
            self.assertFalse(kwargs.get('shell',False))


if __name__=='__main__':unittest.main()
