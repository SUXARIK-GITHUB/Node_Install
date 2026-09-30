"""Validate only supplied Xray JSON. No claim of live panel/Host compliance."""
import copy
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from common import module

class ProfilePolicyTests(unittest.TestCase):
    def setUp(self):
        self.h=module('PY_HELPER')
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.h.ETC=Path(self.tmp.name)
        self.c={'domain':'node.example.test','public_ipv4':'8.8.4.4','panel_ipv4':['1.1.1.1']}
        with patch.object(self.h,'detect_local_public_ipv4s',return_value={'8.8.4.4':'eth0'}):
            _,_,self.p=self.h.make_keys_profile(self.c)
        self.r=self.p['inbounds'][0]['streamSettings']['realitySettings']
    def reject(self):
        with self.assertRaises(self.h.Failure):self.h.validate_profile(self.p,self.c)
    def test_generated_profile_matches_policy(self): self.assertTrue(self.h.validate_profile(self.p,self.c))
    def test_foreign_sni(self): self.r['serverNames']=['other.example.test'];self.reject()
    def test_additional_sni(self): self.r['serverNames'].append('other.example.test');self.reject()
    def test_foreign_target(self): self.r['target']='other.example.test:443';self.reject()
    def test_remote_ip_target(self): self.r['target']='9.9.9.9:443';self.reject()
    def test_conflicting_dest_alias(self): self.r['dest']='other.example.test:443';self.reject()
    def test_legacy_local_dest_alias(self):
        self.r['dest']=self.r.pop('target');self.assertTrue(self.h.validate_profile(self.p,self.c))
    def test_missing_target(self): self.r.pop('target');self.reject()
    def test_no_proxy_header(self): self.r['xver']=0;self.reject()
    def test_bool_proxy_version_rejected(self): self.r['xver']=True;self.reject()
    def test_xhttp_refused(self): self.p['inbounds'][0]['streamSettings']['network']='xhttp';self.reject()
    def test_ws_refused(self): self.p['inbounds'][0]['streamSettings']['network']='ws';self.reject()
    def test_tls_instead_of_reality_refused(self): self.p['inbounds'][0]['streamSettings']['security']='tls';self.reject()
    def test_second_inbound_refused(self): self.p['inbounds'].append(copy.deepcopy(self.p['inbounds'][0]));self.reject()
    def test_trojan_refused(self): self.p['inbounds'][0]['protocol']='trojan';self.reject()
    def test_fallback_target_refused(self): self.p['inbounds'][0]['settings']['fallbacks']=[{'dest':'other.example.test:443'}];self.reject()
    def test_tunnel_outbound_requires_manual_audit(self): self.p['outbounds'][0]['protocol']='vless';self.reject()
    def test_unrelated_wrapper_is_not_raw_xray_json(self): self.p={'response':self.p};self.reject()
    def test_client_flow_is_not_silently_changed(self):
        for flow in ('','xtls-rprx-vision'):
            self.p['inbounds'][0]['settings']['clients']=[{'id':'00000000-0000-4000-8000-000000000001','flow':flow}]
            before=copy.deepcopy(self.p);self.h.validate_profile(self.p,self.c);self.assertEqual(self.p,before)

    def test_method_alias_cannot_override_raw_with_xhttp(self):
        self.p['inbounds'][0]['streamSettings']['method'] = 'xhttp'
        self.reject()

    def test_method_raw_alias_is_allowed(self):
        stream = self.p['inbounds'][0]['streamSettings']
        stream['method'] = stream.pop('network')
        self.assertTrue(self.h.validate_profile(self.p, self.c))

    def test_tcp_network_alias_is_allowed(self):
        self.p['inbounds'][0]['streamSettings']['network'] = 'tcp'
        self.assertTrue(self.h.validate_profile(self.p, self.c))

    def test_missing_transport_field_is_not_implicitly_trusted(self):
        self.p['inbounds'][0]['streamSettings'].pop('network')
        self.reject()
