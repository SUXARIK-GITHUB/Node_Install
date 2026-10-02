"""Foreign 443 must not become a false Xray PASS. Only safe process metadata."""
import json
import subprocess
import unittest
from common import module, payload


class ListenerOwner230Tests(unittest.TestCase):
    def setUp(self):
        self.h=module('PY_XRAY_LISTENER_OWNER')
        self.state={'id':'a'*64,'running':True,'network':'host','pid':100}
        self.top='PID COMMAND\n100 rw-node\n200 rw-core\n'
        self.ss='LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("rw-core",pid=200,fd=7))\n'
        self.calls=[]

    def fake_run(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[0]=='systemctl':result=''
        elif 'inspect' in argv:result=json.dumps(self.state)
        elif 'top' in argv:result=self.top
        elif argv[0]=='ss':result=self.ss
        else:raise AssertionError('unrecognized command')
        return subprocess.CompletedProcess(argv,0,result,'')

    def test_owned_listener_passes_without_client_auth_claim(self):
        rc,message=self.h.verify(self.fake_run)
        self.assertEqual(rc,0);self.assertIn('USER_AUTH=NOT_TESTED',message)
        self.assertNotIn('secret',message)
        for a in self.calls:
            if a[0]=='docker':self.assertEqual(a[1:3],['--host','unix:///var/run/docker.sock'])

    def test_foreign_nginx_listener_is_not_xray(self):
        self.ss=self.ss.replace('rw-core','nginx').replace('pid=200','pid=500')
        self.assertEqual(self.h.verify(self.fake_run)[0],1)

    def test_rw_node_control_process_cannot_be_mistaken_for_core(self):
        self.ss=self.ss.replace('pid=200','pid=100')
        self.assertEqual(self.h.verify(self.fake_run)[0],1)

    def test_listener_without_pid_is_unverified(self):
        self.ss='LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*\n'
        with self.assertRaises(self.h.Unverified):self.h.verify(self.fake_run)

    def test_no_public_listener_remains_explicit_incomplete_state(self):
        self.ss=''
        self.assertEqual(self.h.verify(self.fake_run),(3,'XRAY_PUBLIC_LISTENER=NOT_LISTENING'))

    def test_invalid_or_non_host_container_refused(self):
        for update in ({'running':False},{'pid':0},{'network':'bridge'},{'id':'invalid'}):
            original=dict(self.state);self.state.update(update)
            with self.subTest(update=update),self.assertRaises(self.h.Unverified):self.h.verify(self.fake_run)
            self.state=original

    def test_secondary_foreign_address_cannot_hide_after_owned_listener(self):
        self.ss+='LISTEN 0 4096 198.51.100.1:443 0.0.0.0:* users:(("nginx",pid=500,fd=5))\n'
        self.assertEqual(self.h.verify(self.fake_run)[0],1)

    def test_changed_process_snapshot_not_a_pass(self):
        calls=[0]
        def changing(argv, **kwargs):
            if 'top' in argv:
                calls[0]+=1
                if calls[0]==2:self.top=self.top.replace('200','300')
            return self.fake_run(argv,**kwargs)
        with self.assertRaisesRegex(self.h.Unverified,'CHANGED'):self.h.verify(changing)

    def test_inactive_docker_checked_before_inspect(self):
        def stopped(argv, **kwargs):
            self.calls.append(argv);return subprocess.CompletedProcess(argv,3,'','')
        with self.assertRaises(self.h.Unverified):self.h.verify(stopped)
        self.assertEqual(len(self.calls),1);self.assertEqual(self.calls[0][0],'systemctl')

    def test_unexpected_ss_port_not_accepted(self):
        self.ss=self.ss.replace(':443',':444')
        with self.assertRaises(self.h.Unverified):self.h.verify(self.fake_run)

    def test_no_private_runtime_source_or_full_environment_in_payload(self):
        p=payload('PY_XRAY_LISTENER_OWNER')
        for bad in ('Config.Env','cmdline','get-config','SECRET_KEY','privkey'):
            self.assertNotIn(bad,p)
