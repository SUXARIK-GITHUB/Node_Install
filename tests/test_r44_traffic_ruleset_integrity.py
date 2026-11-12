"""r44: synthetic nftables JSON acceptance/fail-closed regression tests.

No nft binaries, kernel firewall, services, root or host networking are touched.
The fake records use the documented libnftables-json object/expr schema.
"""
import contextlib
import copy
import io
import json
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

from common import ROOT
sys.path.insert(0,str(ROOT/'integrations'))
import traffic_limits as traffic


def config(in_mbps=50,out_mbps=100,in_gib=200,out_gib=300):
    return {'schema':1,'interface':'ens3','exempt_ports':[22,2222],
            'limits':{'in_mbps':in_mbps,'out_mbps':out_mbps,
                      'in_gib':in_gib,'out_gib':out_gib}}


def nft_json(cfg):
    """Construct the accepted shape from documented nft JSON AST fields."""
    result=[{'metainfo':{'json_schema_version':1}},
            {'table':{'family':'inet','name':traffic.TABLE,'handle':1}}]
    for side in ('in','out'):
        name='incoming' if side=='in' else 'outgoing'
        result.append({'chain':{'family':'inet','table':traffic.TABLE,'name':name,
                   'type':'filter','hook':'input' if side=='in' else 'output',
                   'prio':10,'policy':'accept','handle':2 if side=='in' else 3}})
        result.append({'counter':{'family':'inet','table':traffic.TABLE,'name':name+'_count',
                       'packets':2,'bytes':42,'comment':traffic.MARKER if side=='in' else '',
                       'handle':4 if side=='in' else 5}})
        quota=cfg['limits'][side+'_gib']
        if quota:
            result.append({'quota':{'family':'inet','table':traffic.TABLE,
                      'name':name+'_quota','bytes':quota*1024**3,'used':41,
                      'inv':True,'handle':6 if side=='in' else 7}})
        direction='iifname' if side=='in' else 'oifname'
        tcp='dport' if side=='in' else 'sport'
        iface={'match':{'op':'==','left':{'meta':{'key':direction}},'right':cfg['interface']}}
        ports={'match':{'op':'==','left':{'payload':{'protocol':'tcp','field':tcp}},
                        'right':{'set':cfg['exempt_ports']}}}
        actions=[[iface,ports,{'accept':None}],
                 [iface,{'counter':name+'_count'}]]
        if quota:actions.append([iface,{'quota':name+'_quota'},{'drop':None}])
        if cfg['limits'][side+'_mbps']:
            actions.append([iface,{'limit':{'rate':cfg['limits'][side+'_mbps']*125000,
                     'rate_unit':'bytes','per':'second','burst':0,'inv':True}},
                     {'drop':None}])
        for index,expr in enumerate(actions):
            result.append({'rule':{'family':'inet','table':traffic.TABLE,'chain':name,
                            'expr':expr,'handle':10+index+(20 if side=='out' else 0)}})
    return {'nftables':result}


def patched_nft(json_obj):
    return mock.patch.object(traffic.subprocess,'run',return_value=SimpleNamespace(
        returncode=0,stdout=json.dumps(json_obj),stderr=''))


class TrafficRuleIntegrity(unittest.TestCase):
    def read(self,cfg=None,raw=None):
        cfg=cfg or config()
        with patched_nft(raw if raw is not None else nft_json(cfg)) as command:
            objects=traffic.nft_objects()
            self.assertEqual(command.call_args.args[0][:3],['nft','-j','-n'])
        return objects

    def invalid(self,raw,cfg=None):
        objects=self.read(cfg,raw)
        with self.assertRaisesRegex(traffic.SafeStop,'FOREIGN_OR_MODIFIED_NFT_TABLE'):
            traffic.verify_nft(cfg or config(),objects)

    def test_valid_ruleset_verifies_both_directions_and_optional_limits(self):
        for options in [(50,100,200,300),(25,0,0,0),(0,7,0,12),
                        (0,0,30,40),(0,20,10,0)]:
            with self.subTest(options=options):
                cfg=config(*options)
                obj=self.read(cfg)
                self.assertIs(obj,traffic.verify_nft(cfg,obj))

    def test_empty_chains_do_not_count_as_active(self):
        raw=nft_json(config())
        raw['nftables']=[row for row in raw['nftables'] if 'rule' not in row]
        self.invalid(raw)

    def test_missing_or_extra_expressions_stop(self):
        original=nft_json(config())
        cases=[]
        def variant(change):
            raw=copy.deepcopy(original)
            change(raw['nftables'])
            cases.append(raw)
        variant(lambda rows:rows.__setitem__(slice(None),[r for r in rows
                          if r.get('rule',{}).get('chain')!='outgoing']))
        variant(lambda rows:next(r for r in rows if 'rule' in r)['rule']['expr'].pop())
        variant(lambda rows:next(r for r in rows if 'rule' in r)['rule']['expr'][0]
                 ['match'].__setitem__('right','eth0'))
        variant(lambda rows:next(r for r in rows if 'rule' in r)['rule']['expr'][1]
                 ['match'].__setitem__('right',{'set':[22,2022]}))
        variant(lambda rows:next(r for r in rows if 'rule' in r)['rule']['expr']
                 .__setitem__(-1,{'drop':None}))
        variant(lambda rows:rows.append({'rule':copy.deepcopy(next(r for r in rows if 'rule' in r)['rule'])}))
        variant(lambda rows:next(r for r in rows if r.get('rule',{}).get('chain')=='incoming'
                  and any('limit' in x for x in r['rule']['expr']))['rule']['expr']
                  .__setitem__(-1,{'accept':None}))
        variant(lambda rows:next(r for r in rows if r.get('rule',{}).get('chain')=='incoming'
                  and any('limit' in x for x in r['rule']['expr']))['rule']['expr'][1]
                  ['limit'].__setitem__('inv',False))
        variant(lambda rows:next(r for r in rows if r.get('rule',{}).get('chain')=='incoming'
                  and any('limit' in x for x in r['rule']['expr']))['rule']['expr'][1]
                  ['limit'].__setitem__('rate',111))
        variant(lambda rows:next(r for r in rows if r.get('rule',{}).get('chain')=='incoming'
                  and any('limit' in x for x in r['rule']['expr']))['rule']['expr'][1]
                  ['limit'].__setitem__('burst',10000000))
        variant(lambda rows:next(r for r in rows if r.get('rule',{}).get('chain')=='incoming'
                  and any('quota' in x for x in r['rule']['expr']))['rule']['expr'][1]
                  .__setitem__('quota','outgoing_quota'))
        for i,raw in enumerate(cases):
            with self.subTest(case=i):self.invalid(raw)

    def test_tampered_chain_quota_counter_and_unknown_objects_stop(self):
        orig=nft_json(config()); cases=[]
        for key,value in [('hook','forward'),('prio',0),('policy','drop'),('type','route')]:
            raw=copy.deepcopy(orig);next(r for r in raw['nftables'] if 'chain' in r)['chain'][key]=value
            cases.append(raw)
        for key,value in [('bytes',1),('inv',False),('used',-1)]:
            raw=copy.deepcopy(orig);next(r for r in raw['nftables'] if 'quota' in r)['quota'][key]=value
            cases.append(raw)
        for key,value in [('comment','wrong-marker'),('bytes',-3)]:
            raw=copy.deepcopy(orig);next(r for r in raw['nftables'] if 'counter' in r)['counter'][key]=value
            cases.append(raw)
        raw=copy.deepcopy(orig);raw['nftables'].append({'set':{'family':'inet','table':traffic.TABLE,
                                                        'name':'extra','type':'ipv4_addr'}});cases.append(raw)
        raw=copy.deepcopy(orig);raw['nftables'].append(copy.deepcopy(next(r for r in orig['nftables'] if 'chain' in r)));cases.append(raw)
        raw=copy.deepcopy(orig);next(r for r in raw['nftables'] if 'rule' in r)['rule']['family']='ip';cases.append(raw)
        for i,raw in enumerate(cases):
            with self.subTest(case=i):
                with self.assertRaises(traffic.SafeStop):
                    traffic.verify_nft(config(),self.read(config(),raw))

    def test_modified_configuration_also_fails(self):
        installed=self.read()
        for changed in (config(51,100,200,300),config(50,100,201,300)):
            with self.assertRaisesRegex(traffic.SafeStop,'FOREIGN_OR_MODIFIED_NFT_TABLE'):
                traffic.verify_nft(changed,installed)
        changed=config();changed['exempt_ports']=[22,3333]
        with self.assertRaisesRegex(traffic.SafeStop,'FOREIGN_OR_MODIFIED_NFT_TABLE'):
            traffic.verify_nft(changed,installed)

    def test_apply_does_not_replace_untrusted_table_or_change_usage(self):
        with mock.patch.object(traffic,'network_identity',return_value=('ens3',[22,2222])), \
             mock.patch.object(traffic,'run') as command:
            obj=self.read(config())
            obj[('rule','incoming')]=[]
            with mock.patch.object(traffic,'nft_objects',return_value=obj), \
                 self.assertRaisesRegex(traffic.SafeStop,'FOREIGN_OR_MODIFIED_NFT_TABLE'):
                traffic.nft_apply(config())
            command.assert_not_called()

    def test_status_returns_stop_not_false_active(self):
        with mock.patch.object(traffic.os,'geteuid',return_value=0), \
             mock.patch.object(traffic,'read_private',return_value=json.dumps(config())), \
             patched_nft(nft_json(config())):
            raw=self.read();raw[('rule','outgoing')].clear()
            with mock.patch.object(traffic,'nft_objects',return_value=raw), \
                 contextlib.redirect_stdout(io.StringIO()) as printed, \
                 self.assertRaisesRegex(traffic.SafeStop,'FOREIGN_OR_MODIFIED_NFT_TABLE'):
                traffic.main(['status'])
            self.assertNotIn('TRAFFIC_LIMITS=ACTIVE',printed.getvalue())

    def test_snapshot_and_reset_never_write_if_rules_invalid(self):
        bad=self.read();bad[('rule','incoming')].clear()
        with mock.patch.object(traffic,'nft_objects',return_value=bad), \
             mock.patch.object(traffic,'read_private',return_value=json.dumps(config())), \
             mock.patch.object(traffic,'atomic_private') as writer, \
             mock.patch.object(traffic,'network_identity',return_value=('ens3',[22,2222])), \
             mock.patch.object(traffic,'run') as command:
            with self.assertRaisesRegex(traffic.SafeStop,'FOREIGN_OR_MODIFIED_NFT_TABLE'):
                traffic.snapshot()
            with self.assertRaisesRegex(traffic.SafeStop,'FOREIGN_OR_MODIFIED_NFT_TABLE'):
                traffic.reset_quotas(config())
            writer.assert_not_called();command.assert_not_called()

    def test_good_status_and_restart_do_not_reapply_or_clear_usage(self):
        good=self.read()
        with mock.patch.object(traffic,'nft_objects',return_value=good), \
             mock.patch.object(traffic,'network_identity',return_value=('ens3',[22,2222])), \
             mock.patch.object(traffic,'run') as command:
            self.assertEqual(traffic.nft_apply(config()),'ALREADY_ACTIVE')
            command.assert_not_called()
        with mock.patch.object(traffic.os,'geteuid',return_value=0), \
             mock.patch.object(traffic,'nft_objects',return_value=good), \
             mock.patch.object(traffic,'network_identity',return_value=('ens3',[22,2222])), \
             mock.patch.object(traffic,'read_private',return_value=json.dumps(config())), \
             mock.patch.object(traffic,'restore_counts',return_value={'in':41,'out':52}), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(traffic.main(['status']),0)
            self.assertIn('TRAFFIC_LIMITS=ACTIVE',out.getvalue())

    def test_unavailable_nft_never_looks_like_inactive(self):
        with mock.patch.object(traffic.subprocess,'run',side_effect=OSError('missing')):
            with self.assertRaisesRegex(traffic.SafeStop,'NFT_TABLE_QUERY_FAILED'):
                traffic.nft_objects()
        with mock.patch.object(traffic.subprocess,'run',return_value=SimpleNamespace(
             returncode=1,stdout='',stderr='Operation not permitted')):
            with self.assertRaisesRegex(traffic.SafeStop,'NFT_TABLE_QUERY_FAILED'):
                traffic.nft_objects()


if __name__=='__main__': unittest.main()
