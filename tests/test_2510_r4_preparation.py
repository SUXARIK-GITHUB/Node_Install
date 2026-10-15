"""Offline r4 guard tests. No hosts/panel, no real firewall or Nginx touched."""
import base64
import contextlib
import io
from copy import deepcopy
import datetime as dt
import json
from pathlib import Path
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

from common import ROOT, module
sys.path.insert(0,str(ROOT/'integrations'))
sys.path.insert(0,str(ROOT/'scripts'))
import cascade_profiles as cp
import panel_acl_audit as acl
import staging_acceptance as gate
import nginx_proxy_plan as proxy
import cover_variants as cover


def key(index):
    return base64.urlsafe_b64encode(bytes([index])*32).decode().rstrip('=')


def fixture():
    return {'schema': 1,
            'entry': {'domain':'entry.example.org','ipv4':'8.8.4.4',
                      'private_key':key(1),'public_key':key(2),
                      'short_id':'01aabbcc','inbound_tag':'VK_ENTRY_ABC123'},
            'exit': {'domain':'exit.example.org','ipv4':'1.1.1.1',
                      'private_key':key(3),'public_key':key(4),
                      'short_id':'deafbeef','inbound_tag':'VK_EXIT_DEF456'},
            'bridge':{'service_user_uuid':str(uuid.UUID(int=200))}}


class CascadeOffline(unittest.TestCase):
    def test_profiles_are_distinct_and_entry_is_fail_closed(self):
        cfg=cp.checked_config(fixture())
        entry,exitnode=cp.entry_profile(cfg),cp.exit_profile(cfg)
        self.assertTrue(cp.audit(entry,'entry'))
        self.assertTrue(cp.audit(exitnode,'exit'))
        self.assertEqual([o['tag'] for o in entry['outbounds']],['BLOCK','TO_EXIT_VLESS'])
        self.assertNotIn('dns',entry)
        self.assertEqual(entry['routing']['domainStrategy'],'AsIs')
        self.assertEqual(exitnode['routing']['rules'][-1]['outboundTag'],'DIRECT')
        self.assertEqual(entry['outbounds'][1]['settings']['vnext'][0]['users'][0]['id'],
                         cfg['bridge']['service_user_uuid'])

    def test_entry_rejects_dns_and_direct_and_rule_reordering(self):
        entry=cp.entry_profile(cp.checked_config(fixture()))
        variations=[lambda p:p['outbounds'].append({'tag':'DIRECT','protocol':'freedom'}),
                    lambda p:p['routing'].update(domainStrategy='IPOnDemand'),
                    lambda p:p.update(dns={'servers':['8.8.8.8']}),
                    lambda p:p['outbounds'][0].update(protocol='freedom'),
                    lambda p:p['routing']['rules'].pop(),
                    lambda p:p['routing']['rules'].reverse(),
                    lambda p:p['outbounds'][1].update(sendThrough='0.0.0.0'),
                    lambda p:p['routing'].update(balancers=[{'tag':'bad'}])]
        for m in variations:
            altered=deepcopy(entry);m(altered)
            with self.subTest(m=m),self.assertRaises(cp.Invalid):
                cp.audit(altered,'entry')

    def test_exit_rejects_removed_final_rules(self):
        prof=cp.exit_profile(cp.checked_config(fixture()))
        prof['outbounds'][0]['settings'].pop('finalRules')
        with self.assertRaises(cp.Invalid):cp.audit(prof,'exit')

    def test_disallow_duplicate_roles_private_peer(self):
        changes=[('entry','domain','bad_name!'),('entry','ipv4','127.0.0.1'),
                 ('entry','private_key','oops'),('entry','short_id','badgg'),
                 ('exit','ipv4','198.51.100.20'),('exit','domain','entry.example.org'),
                 ('exit','public_key',key(2)),('exit','inbound_tag','VK_ENTRY_ABC123'),
                 ('bridge','service_user_uuid','00000000-0000-0000-0000-000000000000')]
        for top,k,v in changes:
            obj=fixture();obj[top][k]=v
            with self.subTest(top=top,k=k),self.assertRaises(cp.Invalid):cp.checked_config(obj)

    def test_private_io_atomic_no_overwrite_or_leak(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            inp=root/'private.json';inp.write_text(json.dumps(fixture()));inp.chmod(0o600)
            p=cp.make(cp.read_private(inp),root/'generated')
            self.assertEqual({x.name for x in p.iterdir()},
                             {'entry-profile.json','exit-profile.json','panel-plan.json','SHA256SUMS'})
            self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o700)
            for f in p.iterdir():
                self.assertEqual(stat.S_IMODE(f.stat().st_mode),0o600)
            self.assertNotIn(fixture()['bridge']['service_user_uuid'],
                             (p/'panel-plan.json').read_text())
            self.assertEqual((p/'entry-profile.json').read_text().count(fixture()['exit']['private_key']),0)
            with self.assertRaises(FileExistsError):cp.make(fixture(),p)
            inp.chmod(0o644)
            with self.assertRaises(cp.Invalid):cp.read_private(inp)
            inp.unlink();inp.symlink_to(root/'generated/entry-profile.json')
            with self.assertRaises(cp.Invalid):cp.read_private(inp)

    def test_cli_does_not_echo_config_or_key(self):
        with tempfile.TemporaryDirectory() as t:
            d=Path(t);cfg=d/'input.json';cfg.write_text(json.dumps(fixture()));cfg.chmod(0o600)
            proc=subprocess.run([sys.executable,str(ROOT/'integrations/cascade_profiles.py'),
                '--config',str(cfg),'--output',str(d/'out')],capture_output=True,text=True)
            self.assertEqual(proc.returncode,0,proc.stderr)
            self.assertNotIn(key(1),proc.stdout+proc.stderr)
            self.assertNotIn(fixture()['bridge']['service_user_uuid'],proc.stdout+proc.stderr)


class PanelACLAudit(unittest.TestCase):
    def test_match_and_mismatch_and_wildcard(self):
        good='''Status: active\n\nTo                         Action      From\n--                         ------      ----\n2222/tcp                   ALLOW IN    8.8.8.8\n22/tcp                     ALLOW IN    Anywhere\n'''
        self.assertTrue(acl.audit(good,2222,{'8.8.8.8'}))
        for text in (good.replace('8.8.8.8','Anywhere'),
                     good.replace('8.8.8.8','1.1.1.1'),
                     good.replace('2222/tcp','2222/udp'),
                     good.replace('Status: active','Status: inactive'),
                     good+'2222/tcp (v6)             ALLOW IN    Anywhere (v6)\n'):
            with self.subTest(text=text),self.assertRaises(acl.ACLProblem):
                acl.audit(text,2222,{'8.8.8.8'})

    def test_config_must_be_canonical(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'config.json'
            p.write_text(json.dumps({'installation_mode':'secret-key-only',
                    'node_port':2222,'panel_ipv4':['8.8.8.8']}))
            p.chmod(0o600)
            self.assertEqual(acl.config(p),(2222,{'8.8.8.8'}))
            p.chmod(0o644)
            with self.assertRaises(acl.ACLProblem):acl.config(p)
            p.chmod(0o600)
            p.write_text(json.dumps({'installation_mode':'secret-key-only',
                    'node_port':2222,'panel_ipv4':['192.168.1.1']}))
            with self.assertRaises(acl.ACLProblem):acl.config(p)


class EvidenceGate(unittest.TestCase):
    def test_never_accepts_missing_or_claimed_checks(self):
        o=gate.template('ordinary','a'*64)
        self.assertEqual(gate.evaluate(o)['pass'],0)
        o['status']='ACCEPTED'
        with self.assertRaises(gate.EvidenceError):gate.evaluate(o)
        o['status']='NOT_ACCEPTED'
        entry=o['checks']['snapshot_restore']
        entry.update({'result':'PASS','tested_at_utc':'2026-10-15T00:00:00Z',
                      'evidence_reference':'evidence/vps-1.txt','operator':'example_op'})
        self.assertEqual(gate.evaluate(o)['pass'],1)
        entry.pop('operator')
        with self.assertRaises(gate.EvidenceError):gate.evaluate(o)

    def test_cascade_extra_gates(self):
        o=gate.template('cascade','b'*64)
        self.assertIn('entry_no_direct_during_exit_outage',o['checks'])
        self.assertIn('24h_soak',o['checks'])
        self.assertGreater(len(o['checks']),len(gate.ORDINARY))


class PreviewAndProxy(unittest.TestCase):
    def test_exactly_six_complete_static_sites_without_external_deps(self):
        self.assertEqual(len(cover.NAMES),6)
        titles=[]
        for name in cover.NAMES:
            html=(ROOT/'cover-variants'/name/'index.html').read_text()
            css=(ROOT/'cover-variants'/name/'style.css').read_text()
            self.assertIn('viewport',html)
            self.assertIn('Content-Security-Policy',html)
            self.assertIn('max-width:700px',css)
            self.assertNotIn('http://',html)
            self.assertNotIn('https://',html)
            self.assertNotIn('<script',html)
            titles.append(html.split('<title>')[1].split('</title>')[0])
        self.assertEqual(len(set(titles)),6)

    def test_preview_never_overwrites(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'preview'
            self.assertEqual(cover.main(['--name',cover.NAMES[0], '--output',str(p)]),0)
            self.assertEqual(cover.main(['--name',cover.NAMES[0], '--output',str(p)]),1)

    def test_proxy_loopback_only_and_restricts_ports(self):
        for mode in ('http','tcp'):
            result=proxy.generate(mode,'9000','9100')
            self.assertIn('127.0.0.1:9000',result)
            self.assertIn('127.0.0.1:9100',result)
            self.assertNotIn('listen 0.0.0.0:',result)
            self.assertNotIn('listen 443;',result)
        for args in (('http',443,8000),('tcp',8000,2222),('http',8000,8000)):
            with self.subTest(args=args),self.assertRaises(ValueError):proxy.generate(*args)


class RKNContentCheckpoint(unittest.TestCase):
    """Fault-free simulated kernel transaction, including unchanged-list semantics."""

    def test_last_content_change_is_not_last_download(self):
        for old_marker, old, new, expect in (
            ('2026-01-01T01:00:00+00:00', ['8.8.8.0/24'], ['8.8.8.0/24'], 'preserved'),
            (None, ['8.8.8.0/24'], ['8.8.8.0/24'], 'unknown'),
            ('2026-01-01T01:00:00+00:00', ['8.8.8.0/24'],
             ['8.8.8.0/24','9.9.9.0/24'], 'changed'),
        ):
            with self.subTest(expect=expect),tempfile.TemporaryDirectory() as t:
                m=module('VK_RKN_GUARD_PY')
                m.ROOT=Path(t)/'guard'
                m.ROOT.mkdir()
                m.CACHE=m.ROOT/'current-v4.txt'
                m.CHECKED=m.ROOT/'last-check.json'
                m.UFW_FILE=Path(t)/'before.rules'
                m.CACHE.write_text(''.join(x+'\n' for x in old))
                m.CHECKED.write_text(json.dumps({'checked_at_utc':'2026-01-02T01:00:00+00:00',
                    'content_changed_at_utc':old_marker}))
                m.UFW_FILE.write_text(m.BEGIN)
                with (patch.object(m,'require_node'),
                      patch.object(m,'prepare',return_value=True),
                      patch.object(m,'download',return_value='fixture'),
                      patch.object(m,'parse_networks',return_value=new),
                      patch.object(m,'restore_cached',return_value=old),
                      patch.object(m,'live_block_set',side_effect=[old,new]),
                      patch.object(m,'ipset_stage'),
                      patch.object(m,'run',return_value=''),
                      patch.object(m,'check_ufw_jump'),
                      contextlib.redirect_stdout(io.StringIO())):
                    m.update()
                stamped=json.loads(m.CHECKED.read_text())
                self.assertEqual(stamped['changed'],old!=new)
                if expect=='preserved':
                    self.assertEqual(stamped['content_changed_at_utc'],old_marker)
                elif expect=='unknown':
                    self.assertIsNone(stamped['content_changed_at_utc'])
                else:
                    self.assertNotEqual(stamped['content_changed_at_utc'],old_marker)
                    self.assertIsNotNone(stamped['content_changed_at_utc'])
                self.assertIn('checked_at_utc',stamped)


class NightlyCascadeGuard(unittest.TestCase):
    def test_cascade_skips_before_restart_and_before_marker(self):
        night=module('VK_NIGHT_MAINT_PY')
        now=dt.datetime(2026,10,15,0,30,tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as t:
            from unittest.mock import patch
            state=Path(t)
            (state/'INSTALL_COMPLETE').write_text('test')
            with patch.object(night,'STATE',state),patch.object(night,'LOCK',state/'lock'),\
                 patch.object(night,'RESULT',state/'maintenance-last.json'),\
                 patch.object(night,'role',return_value='cascade-entry'),\
                 patch.object(night,'call',side_effect=AssertionError('unexpected host mutation')):
                self.assertEqual(night.do_run(now),0)
                self.assertFalse((state/'maintenance-last.json').exists())

if __name__=='__main__':unittest.main()
