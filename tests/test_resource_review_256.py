"""Unverified observations must not vanish behind an exit code of zero."""
import copy
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
from common import ROOT, module


class ResourceReview256(unittest.TestCase):
    def setUp(self):
        self.m = module('VK_RESOURCES_PY')
        self.good = {'cpu': {'busy_percent': 1}, 'memory': {'MemAvailable_MiB': 1000},
                     'root_disk': {'status': 'OK', 'inode_status': 'OK'},
                     'container': {'verified': True, 'status': 'OK'},
                     'conntrack': {'verified': True, 'status': 'OK'},
                     'daemon_fds': {'verified': True,'processes':[{'status':'OK'}]},
                     'pressure': {k:{'some':{'avg10':0}} for k in ('cpu','memory','io')},
                     'selfsteal_socket_queue': {'verified':True,'present':True},
                     **{k:{'count':0} for k in ('tcp_delta','tcp_ext_delta','vm_delta')}}

    def test_all_observations_known_is_ok(self):
        s=self.m.review_summary(self.good)
        self.assertEqual(s['finding_count'],0);self.assertFalse(s['review_required'])

    def test_exact_reported_partial_fd_snapshot_requires_review(self):
        self.good['daemon_fds'].update(verified=False,unreadable_or_changed=1)
        s=self.m.review_summary(self.good)
        self.assertTrue(s['review_required']);self.assertEqual(s['status'],'REVIEW_REQUIRED')
        self.assertIn({'section':'resources.daemon_fds','reason':'NOT_VERIFIED'},s['findings'])

    def test_nested_fd_critical_and_inode_warning_surface(self):
        self.good['daemon_fds']['processes'][0]['status']='CRITICAL'
        self.good['root_disk']['inode_status']='WARN'
        s=self.m.review_summary(self.good)
        self.assertEqual(s['finding_count'],2)

    def test_missing_pressure_and_counter_reset_surface(self):
        self.good['pressure']['memory']=None
        self.good['tcp_delta']['count']=None
        self.assertEqual(self.m.review_summary(self.good)['finding_count'],2)

    def test_no_matching_daemons_is_not_verified_empty_success(self):
        import tempfile
        with tempfile.TemporaryDirectory() as p:
            self.assertFalse(self.m.fd_snapshot(Path(p))['verified'])

    def test_stopped_container_is_critical(self):
        response=subprocess.CompletedProcess([],0,json.dumps({'running':False,'restarting':False,'oom_killed':False,'restarts':0}).encode())
        with patch.object(self.m.shutil,'which',return_value='/fake'),patch.object(self.m.subprocess,'run',return_value=response):
            self.assertEqual(self.m.container_state()['status'],'CRITICAL')

    def test_main_strict_returns_two_for_partial_facts_default_keeps_compatibility(self):
        import contextlib,io
        for strict in (False,True):
            with self.subTest(strict=strict), \
                 patch.object(self.m.sys,'argv',['resources']+(['--strict'] if strict else [])), \
                 patch.object(self.m,'sample',return_value={}), \
                 patch.object(self.m.time,'sleep'), \
                 patch.object(self.m,'summarize',return_value=self.good), \
                 patch.object(self.m,'text',return_value=''), \
                 patch.object(self.m,'memory_info',return_value={'MemAvailable_MiB': 1}), \
                 patch.object(self.m,'pressure',return_value={'some':{'avg10':0}}), \
                 patch.object(self.m,'container_state',return_value={'verified':True}), \
                 patch.object(self.m,'fd_snapshot',return_value={'verified':False,'unreadable_or_changed':1}), \
                 patch.object(self.m,'socket_queue',return_value={'verified':True,'present':True}), \
                 patch.object(self.m,'conntrack_snapshot',return_value={'verified':True}), \
                 patch.object(self.m,'disk_snapshot',return_value={'status':'OK'}), \
                 contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(self.m.main(),2 if strict else 0)
                self.assertTrue(json.loads(out.getvalue())['review_summary']['review_required'])


if __name__ == '__main__':
    unittest.main()
