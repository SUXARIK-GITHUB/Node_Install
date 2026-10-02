"""Private /proc fixtures. No fd targets, environment, cmdlines or client addresses."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from common import module


class Resource230Tests(unittest.TestCase):
    def setUp(self):
        self.h=module('VK_RESOURCES_PY');self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)

    def process(self, pid='42', comm='rw-core', soft='100', hard='200'):
        p=self.root/pid;p.mkdir();(p/'comm').write_text(comm+'\n')
        (p/'stat').write_text(pid+' ('+comm+') S '+'0 '*18+'12345 '+'0 '*8)
        (p/'limits').write_text('Max open files            '+soft+'                 '+hard+'                 files\n')
        (p/'fd').mkdir()
        for n in range(3):(p/'fd'/str(n)).symlink_to('/SECRET_CLIENT_CANARY')
        return p

    def test_fd_count_and_limit_without_dereferencing_targets(self):
        self.process();s=self.h.fd_snapshot(self.root)
        self.assertTrue(s['verified']);r=s['processes'][0]
        self.assertEqual((r['open_fds'],r['soft_limit'],r['soft_limit_percent']),(3,100,3.0))
        self.assertNotIn('SECRET',json.dumps(s))

    def test_unlimited_limit_does_not_become_zero_or_false_percentage(self):
        self.process(soft='unlimited',hard='unlimited')
        r=self.h.fd_snapshot(self.root)['processes'][0]
        self.assertIsNone(r['soft_limit']);self.assertIsNone(r['soft_limit_percent'])

    def test_non_daemon_not_inspected(self):
        self.process(comm='other-process')
        self.assertEqual(self.h.fd_snapshot(self.root)['processes'],[])

    def test_missing_limit_not_a_verified_snapshot(self):
        (self.process()/'limits').unlink()
        r=self.h.fd_snapshot(self.root)
        self.assertFalse(r['verified']);self.assertEqual(r['unreadable_or_changed'],1)

    def test_changed_pid_snapshot_discarded(self):
        self.process()
        with patch.object(self.h,'process_identity',side_effect=[1,2]):
            r=self.h.fd_snapshot(self.root)
        self.assertFalse(r['verified']);self.assertEqual(r['processes'],[])

    def test_snapshot_cap_explicit(self):
        self.process('42');self.process('43')
        r=self.h.fd_snapshot(self.root,limit=1)
        self.assertTrue(r['truncated']);self.assertFalse(r['verified'])

    def test_queue_only_known_socket_and_no_peer_addresses(self):
        raw='u_str LISTEN 2 511 /run/vkarmani-selfsteal/nginx.sock 789 * 0\nu_str LISTEN 0 5 /private-other 12 * 0\n'
        self.assertEqual(self.h.parse_socket_queue(raw),[{'pending_connections':2,'backlog':511}])

    def test_queue_format_error_and_command_failure_not_zero_success(self):
        with self.assertRaises(ValueError):self.h.parse_socket_queue('bad /run/vkarmani-selfsteal/nginx.sock')
        for response in (subprocess.CompletedProcess([],1,'','SECRET_CANARY'),subprocess.CompletedProcess([],0,'u_str LISTEN bad 5 /dev/shm/nginx.sock')):
            r=self.h.socket_queue(lambda *a,**k:response)
            self.assertFalse(r['verified']);self.assertNotIn('SECRET',json.dumps(r))

    def test_no_socket_is_verified_absence_not_target_health(self):
        r=self.h.socket_queue(lambda *a,**k:subprocess.CompletedProcess([],0,''))
        self.assertTrue(r['verified']);self.assertFalse(r['present'])
