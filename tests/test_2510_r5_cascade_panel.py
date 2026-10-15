#!/usr/bin/env python3
"""The computed Panel configuration is untrusted: reject egress drift and ACL leaks."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
import uuid
import sys

from common import ROOT
sys.path.insert(0, str(ROOT / 'integrations'))
import cascade_deployment as cd
import cascade_panel_audit as panel
from test_2510_r5_cascade_roles import pair, fpriv


class ComputedPanelPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.both = cd.bundles(cd.validated_pair(pair()))

    def configured(self, role):
        b = self.both[role]
        p = cd.role_profile(b)
        p['inbounds'][0]['settings']['clients'] = [{
            'id': b['bridge']['service_user_uuid'] if role == 'exit' else str(uuid.uuid4()),
            'flow': 'xtls-rprx-vision',
        }]
        return b, p

    def assertReject(self, b, cfg, reason=None):
        with self.assertRaises(panel.PanelPolicyError) as err:
            panel.audit(b, cfg)
        if reason:
            self.assertIn(reason, str(err.exception))

    def test_roles_pass_only_exact_routing_plus_expected_clients(self):
        for role in ('entry', 'exit'):
            with self.subTest(role=role):
                b, cfg = self.configured(role)
                original = copy.deepcopy(cfg)
                outcome = panel.audit(b, cfg)
                self.assertEqual(cfg, original, 'auditing must be read-only')
                self.assertEqual(outcome['role'], b['role'])
                self.assertEqual(outcome['client_count'], 1)

    def test_entry_refuses_direct_leak_or_dns(self):
        b, cfg = self.configured('entry')
        for mutation in (
            lambda x: x['outbounds'].insert(0, {'tag':'DIRECT','protocol':'freedom'}),
            lambda x: x.update(dns={'servers':['1.1.1.1']}),
            lambda x: x['routing'].update(domainStrategy='IPOnDemand'),
            lambda x: x['routing']['rules'].append({'type':'field', 'outboundTag':'DIRECT'}),
            lambda x: x['outbounds'][1]['settings']['vnext'][0].update(address='8.8.8.8'),
            lambda x: x['inbounds'].append({'tag':'ROGUE', 'protocol':'vless'}),
        ):
            with self.subTest(mutation=mutation):
                p = copy.deepcopy(cfg); mutation(p)
                self.assertReject(b, p)

    def test_exit_refuses_unexpected_client_and_entry_refuses_bridge(self):
        b, cfg = self.configured('exit')
        p = copy.deepcopy(cfg)
        p['inbounds'][0]['settings']['clients'].append({'id':str(uuid.uuid4())})
        self.assertReject(b, p, 'EXIT_MUST_HAVE_ONLY_BRIDGE_USER')
        b, cfg = self.configured('entry')
        cfg['inbounds'][0]['settings']['clients']=[{'id':b['bridge']['service_user_uuid']}]
        self.assertReject(b,cfg,'ENTRY_MUST_NOT_ADMIT_BRIDGE_USER')

    def test_no_empty_or_duplicate_users(self):
        for role in ('entry','exit'):
            b,cfg=self.configured(role)
            p=copy.deepcopy(cfg);p['inbounds'][0]['settings']['clients']=[]
            self.assertReject(b,p,'COMPUTED_NO_ASSIGNED_USERS')
            p=copy.deepcopy(cfg)
            p['inbounds'][0]['settings']['clients'].append(dict(p['inbounds'][0]['settings']['clients'][0]))
            self.assertReject(b,p,'COMPUTED_DUPLICATE_CLIENT')

    def test_local_api_must_be_explicit_and_reviewable(self):
        b,cfg=self.configured('entry')
        p=copy.deepcopy(cfg)
        p['api']={'tag':'api','services':['HandlerService','StatsService','RoutingService']}
        p['inbounds'].insert(0, {'tag':'REMNAWAVE_API_INBOUND', 'protocol':'dokodemo-door',
                                 'listen':'127.0.0.1', 'port':10085})
        p['routing']['rules'].insert(0, {'type':'field', 'inboundTag':['REMNAWAVE_API_INBOUND'],
                                         'outboundTag':'api'})
        result=panel.audit(b,p)
        self.assertTrue(result['api_local'])
        for bad in (
            lambda x: x['inbounds'][0].update(listen='0.0.0.0'),
            lambda x: x['routing']['rules'][0].update(outboundTag='DIRECT'),
            lambda x: x['inbounds'][0].update(port=443),
            lambda x: x['api'].update(tag='TO_EXIT_VLESS'),
        ):
            with self.subTest(bad=bad):
                changed=copy.deepcopy(p);bad(changed)
                self.assertReject(b,changed)

    def test_cli_profile_read_failure_and_no_secret_output(self):
        b,p=self.configured('exit')
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            bundle=fpriv(root/'role-bundle.json',b)
            cfg=fpriv(root/'computed.json',p)
            from subprocess import run
            args=[sys.executable,str(ROOT/'integrations/cascade_panel_audit.py'),
                  '--role-bundle',str(bundle),'--computed-profile',str(cfg)]
            result=run(args,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('CASCADE_COMPUTED_PROFILE=PASS',result.stdout)
            self.assertNotIn(b['bridge']['service_user_uuid'],result.stdout+result.stderr)
            cfg.unlink()
            cfg.symlink_to(root/'role-bundle.json')
            result=run(args,capture_output=True,text=True,timeout=10)
            self.assertNotEqual(result.returncode,0)
            self.assertNotIn(b['self']['private_key'],result.stdout+result.stderr)


if __name__ == '__main__':
    unittest.main()
