"""Fail-closed FinalMask outbound export; no Node/Panel/client mutation."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy

from common import ROOT
sys.path.insert(0, str(ROOT/'integrations'))
import finalmask_profile as fm


def client():
    return {
      'log': {'loglevel':'warning'},
      'inbounds': [{'tag':'local', 'protocol':'socks','listen':'127.0.0.1','port':10808}],
      'outbounds': [
        {'tag':'proxy','protocol':'vless','settings':{'vnext':[{'address':'node.example.test','port':443,'users':[{'id':'test-secret'}]}]},
         'streamSettings':{'network':'raw','security':'reality','realitySettings':{'serverName':'node.example.test'}}},
        {'tag':'direct','protocol':'freedom'},
      ],
      'routing': {'rules':[{'outboundTag':'proxy'}]}
    }


class FinalMaskConfig(unittest.TestCase):
    def test_enabled_is_single_outbound_and_disable_restores(self):
        source=client()
        enabled=fm.transform(source,tag='proxy',enabled=True)
        self.assertEqual(source,client())
        stream=enabled['outbounds'][0]['streamSettings']
        self.assertEqual(stream['finalmask']['tcp'][0]['settings'],
                         {'packets':'tlshello','lengths':['80-160'],
                          'delays':['0-5'],'maxSplit':'2-4'})
        self.assertEqual(enabled['outbounds'][1],source['outbounds'][1])
        self.assertEqual(fm.transform(enabled,tag='proxy',enabled=False), source)
        self.assertEqual(fm.transform(source,tag='proxy',enabled=False),source)

    def test_configurable_numbers_and_idempotency(self):
        source=client()
        changed=fm.transform(source, tag='proxy', enabled=True,
                             lengths='100-120,160-240',delays='0,2-4', max_split='4')
        self.assertEqual(fm.transform(changed,tag='proxy',enabled=True, lengths='100-120,160-240',
                                       delays='0,2-4',max_split='4'),changed)
        st=changed['outbounds'][0]['streamSettings']['finalmask']['tcp'][0]['settings']
        self.assertEqual(st['lengths'], ['100-120', '160-240'])
        xhttp=client();xhttp['outbounds'][0]['streamSettings']['network']='xhttp'
        self.assertIn('finalmask', fm.transform(xhttp,tag='proxy',enabled=True)['outbounds'][0]['streamSettings'])

    def test_reject_invalid_or_excessive_numbers(self):
        for item in ('0','-1','3-1','0-120','1-1501','12, ','12,../3', '10'*300, '1-999999'):
            with self.subTest(value=item), self.assertRaises(fm.Invalid):
                fm.tcp_fragment(lengths=item)
        for item in ('201','0-999','-2','1-0'):
            with self.subTest(value=item), self.assertRaises(fm.Invalid):
                fm.tcp_fragment(delays=item)
        for item in ('0','17','1-40', '2,4'):
            with self.subTest(value=item), self.assertRaises(fm.Invalid):
                fm.tcp_fragment(max_split=item)

    def test_reject_wrong_direction_or_unmanaged_masks(self):
        base=client()
        cases=[]
        x=deepcopy(base);x['outbounds'][0]['protocol']='freedom';cases.append(x)
        x=deepcopy(base);x['outbounds'][0]['streamSettings']['security']='none';cases.append(x)
        x=deepcopy(base);x['outbounds'][0]['streamSettings']['network']='hysteria';cases.append(x)
        x=deepcopy(base);x['outbounds'][0]['streamSettings']['finalmask']={'udp':[{'type':'salamander','settings':{'password':'x'}}]};cases.append(x)
        x=deepcopy(base);x['outbounds'][0]['streamSettings']['finalmask']={'tcp':[{'type':'sudoku','settings':{}}]};cases.append(x)
        x=deepcopy(base);x['outbounds'][0]['streamSettings']['finalmask']={'tcp':[{'type':'fragment','settings':{}}]};cases.append(x)
        for i,config in enumerate(cases):
            with self.subTest(index=i),self.assertRaises(fm.Invalid):
                fm.transform(config,tag='proxy',enabled=True)
        x=deepcopy(base);x['outbounds'].append(deepcopy(x['outbounds'][0]))
        with self.assertRaisesRegex(fm.Invalid,'NOT_UNIQUE'):
            fm.transform(x,tag='proxy',enabled=False)
        with self.assertRaisesRegex(fm.Invalid,'NOT_UNIQUE'):
            fm.transform(base,tag='unknown',enabled=False)

    def test_private_cli_export_and_disable(self):
        with tempfile.TemporaryDirectory() as td:
            parent=Path(td)
            p=parent/'client.json'
            p.write_text(json.dumps(client()))
            p.chmod(0o600)
            out=parent/'enabled.json'
            cmd=['bash',str(ROOT/'install.sh'),'--finalmask','enable','--input',str(p),
                 '--output',str(out),'--outbound-tag','proxy','--lengths','90-180',
                 '--delays','0-3','--max-split','2-3']
            run=subprocess.run(cmd,capture_output=True,text=True,timeout=12)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertEqual(out.stat().st_mode & 0o777,0o600)
            self.assertNotIn('test-secret',run.stdout + run.stderr)
            self.assertIn('finalmask',json.loads(out.read_text())['outbounds'][0]['streamSettings'])
            status=subprocess.run(['bash',str(ROOT/'install.sh'),'--finalmask','status','--input',str(out),'--outbound-tag','proxy'],capture_output=True,text=True,timeout=12)
            self.assertEqual(status.returncode,0,status.stderr)
            self.assertIn('lengths=90-180',status.stdout)
            self.assertNotIn('test-secret',status.stdout)
            again=subprocess.run(cmd,capture_output=True,text=True,timeout=12)
            self.assertEqual(again.returncode,2)
            self.assertIn('FileExistsError',again.stderr)
            off=parent/'disabled.json'
            cmd=['bash',str(ROOT/'install.sh'),'--finalmask','disable','--input',str(out),
                 '--output',str(off),'--outbound-tag','proxy']
            run=subprocess.run(cmd,capture_output=True,text=True,timeout=12)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertEqual(json.loads(off.read_text()),client())
            self.assertTrue(p.exists())

    def test_unsafe_input_and_output_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            parent=Path(td);source=parent/'source.json';source.write_text(json.dumps(client()))
            source.chmod(0o644)
            with self.assertRaisesRegex(fm.Invalid,'PRIVATE'):
                fm._read_private_json(source)
            source.chmod(0o600)
            (parent/'link.json').symlink_to(source)
            with self.assertRaisesRegex(fm.Invalid,'SYMLINK'):
                fm._read_private_json(parent/'link.json')
            with self.assertRaisesRegex(fm.Invalid,'REPOSITORY'):
                fm._write_new_private(ROOT/'private.json',b'{}')
            parent.chmod(0o755)
            with self.assertRaisesRegex(fm.Invalid,'0700'):
                fm._write_new_private(parent/'out.json',b'{}')
            parent.chmod(0o700)
            preexisting=parent/'out.json';preexisting.write_text('preserve')
            with self.assertRaises(FileExistsError):
                fm._write_new_private(preexisting,b'{}')
            self.assertEqual(preexisting.read_text(),'preserve')

    def test_private_snippet_requires_no_client_and_is_not_a_full_profile(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'snippet.json'
            cmd=['bash',str(ROOT/'install.sh'),'--finalmask','snippet','--output',str(path),
                 '--lengths','70-120','--delays','0-4','--max-split','2-3']
            p=subprocess.run(cmd,capture_output=True,text=True,timeout=10)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            self.assertEqual(json.loads(path.read_text())['finalmask']['tcp'][0]['settings']['lengths'],['70-120'])
            self.assertNotIn('NODE=CHANGED',p.stdout)

    def test_cli_is_readonly_without_arguments_and_noninteractive_menu_denied(self):
        p=subprocess.run(['bash',str(ROOT/'install.sh'),'--finalmask','defaults'],
                         capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('OFF_BY_DEFAULT',p.stdout)
        p=subprocess.run(['bash',str(ROOT/'install.sh'),'--finalmask','menu'],
                         capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,2)


if __name__=='__main__': unittest.main()
