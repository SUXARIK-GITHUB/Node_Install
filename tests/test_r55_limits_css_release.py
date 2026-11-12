"""R55 offline regression: traffic cap identity safety, CSS overlay and release evidence."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

from common import ROOT
sys.path.insert(0, str(ROOT/'scripts'))
sys.path.insert(0, str(ROOT/'integrations'))
import cover_variants
import traffic_limits as traffic
from test_r44_traffic_ruleset_integrity import config as traffic_config, nft_json


class TrafficIdentityRegression(unittest.TestCase):
    def test_ipv6_egress_on_other_nic_refuses_new_cap_activation(self):
        for v6_dev, rejected in (('ens3',False),('ens6',True),(None,False)):
            with self.subTest(ipv6_nic=v6_dev):
                commands=[]
                def run(args, **kwargs):
                    commands.append(tuple(args))
                    if args[:3]==['ip','-j','-4']:
                        return json.dumps([{'dst':'default','dev':'ens3'}])
                    if args[:3]==['ip','-j','-6']:
                        return json.dumps([{'dst':'default','dev':v6_dev}] if v6_dev else [])
                    self.fail('unexpected external command')
                def private(path,*args):
                    if path==traffic.SSH_PORTS:return '22\n2222\n'
                    if path==traffic.NODE_CONFIG:return json.dumps({'node_port':2222})
                    self.fail('unexpected private file')
                with mock.patch.object(traffic,'run',side_effect=run), \
                     mock.patch.object(traffic,'read_private',side_effect=private):
                    if rejected:
                        with self.assertRaisesRegex(traffic.SafeStop,'DIFFERENT_IPV6_EGRESS'):
                            traffic.network_identity()
                    else:
                        self.assertEqual(traffic.network_identity(),('ens3',[22,2222]))
                self.assertIn(('ip','-j','-6','route','show','default'),commands)

    def test_malformed_v6_routes_refused(self):
        def run(args,**kwargs):
            return json.dumps([{'dev':'ens3'}]) if '-4' in args else '{}'
        with mock.patch.object(traffic,'run',side_effect=run):
            with self.assertRaisesRegex(traffic.SafeStop,'BAD_IPV6_DEFAULT_ROUTE'):
                traffic.network_identity()

    def test_status_never_reports_active_if_nic_or_management_port_drifts(self):
        cfg=traffic_config()
        for identity in [('ens4',[22,2222]),('ens3',[22,3333])]:
            with self.subTest(identity=identity), \
                 mock.patch.object(traffic.os,'geteuid',return_value=0), \
                 mock.patch.object(traffic,'read_private',return_value=json.dumps(cfg)), \
                 mock.patch.object(traffic,'nft_objects',return_value=self.good_nft(cfg)), \
                 mock.patch.object(traffic,'network_identity',return_value=identity), \
                 contextlib.redirect_stdout(io.StringIO()) as output, \
                 self.assertRaisesRegex(traffic.SafeStop,'NETWORK_OR_SSH_PORTS_CHANGED_REFUSE'):
                traffic.main(['status'])
            self.assertNotIn('TRAFFIC_LIMITS=ACTIVE',output.getvalue())

    @staticmethod
    def good_nft(cfg):
        from test_r44_traffic_ruleset_integrity import patched_nft
        with patched_nft(nft_json(cfg)):
            return traffic.nft_objects()

    def test_snapshot_must_not_write_if_network_identity_changed(self):
        cfg=traffic_config()
        with mock.patch.object(traffic,'read_private',return_value=json.dumps(cfg)), \
             mock.patch.object(traffic,'network_identity',return_value=('ens4',[22,2222])), \
             mock.patch.object(traffic,'nft_objects') as nft, \
             mock.patch.object(traffic,'atomic_private') as writer, \
             self.assertRaisesRegex(traffic.SafeStop,'NETWORK_OR_SSH_PORTS_CHANGED_REFUSE'):
            traffic.snapshot()
        writer.assert_not_called()
        nft.assert_not_called()

    def test_reset_must_not_touch_kernel_if_identity_changed(self):
        cfg=traffic_config()
        with mock.patch.object(traffic,'network_identity',return_value=('ens4',[22,2222])), \
             mock.patch.object(traffic,'nft_objects',return_value=self.good_nft(cfg)), \
             mock.patch.object(traffic,'run') as executor, \
             mock.patch.object(traffic,'atomic_private') as writer, \
             self.assertRaisesRegex(traffic.SafeStop,'NETWORK_OR_SSH_PORTS_CHANGED_REFUSE'):
            traffic.reset_quotas(cfg)
        executor.assert_not_called()
        writer.assert_not_called()

    def test_private_config_rejects_unsorted_or_duplicate_exempt_ports(self):
        for ports in ([2222,22],[22,22,2222],[22,2222,2222]):
            with self.subTest(ports=ports):
                cfg=traffic_config()
                cfg['exempt_ports']=ports
                with self.assertRaisesRegex(traffic.SafeStop,'BAD_EXEMPT_PORTS'):
                    traffic.validate_config(cfg)

    def test_rate_and_quota_calculation_and_order_are_explicit(self):
        cfg=traffic_config()
        text=traffic.rules(cfg,{'in':1234,'out':5678})
        self.assertIn('limit rate over 6250000 bytes/second drop',text)
        self.assertIn('limit rate over 12500000 bytes/second drop',text)
        self.assertIn('quota incoming_quota { over 214748364800 bytes used 1234 bytes; }',text)
        self.assertIn('quota outgoing_quota { over 322122547200 bytes used 5678 bytes; }',text)
        for chain in ('incoming','outgoing'):
            start=text.index('chain '+chain)
            end=text.index('\n  }',start)
            rules=text[start:end]
            self.assertLess(rules.index('counter name'),rules.index('quota name'))
            self.assertLess(rules.index('quota name'),rules.index('limit rate over'))
        self.assertNotIn('flush ruleset',text)


class CSSRegression(unittest.TestCase):
    def test_static_source_and_rendered_css_have_one_effective_domain_overlay(self):
        for name in cover_variants.NAMES:
            with self.subTest(theme=name):
                css=(ROOT/'cover-variants'/name/'style.css').read_bytes()
                self.assertEqual(css.count(b':root{--accent:hsl('),1)
                self.assertTrue(cover_variants.GENERATED_VARS.search(css))
                base=cover_variants.remove_generated_vars(css)
                self.assertEqual(base.count(b':root{--accent:hsl('),0)
                for domain in ('preview.example.test','docs.example.org','photo.example.net'):
                    out=cover_variants.render(name,domain)['style.css']
                    self.assertEqual(out.count(b':root{--accent:hsl('),1)
                    self.assertTrue(out.startswith(base))
                    self.assertEqual(out,cover_variants.render(name,domain)['style.css'])

    def test_normalization_idempotent_and_does_not_erase_handcrafted_css(self):
        source=(ROOT/'cover-variants'/'01-atelier'/'style.css').read_bytes()
        base=cover_variants.remove_generated_vars(source)
        self.assertEqual(cover_variants.remove_generated_vars(base),base)
        self.assertEqual(cover_variants.remove_generated_vars(base+source[len(base):]*4),base)
        self.assertTrue(base.startswith(b':root{--paper:'))
        self.assertIn(b'@media',base)


class ReleaseMetadataRegression(unittest.TestCase):
    def test_current_status_does_not_pretend_to_be_old_validation(self):
        m=json.loads((ROOT/'BUILD_MANIFEST.json').read_text())
        status=json.loads((ROOT/'docs/RELEASE_VALIDATION.json').read_text())
        historic=json.loads((ROOT/'docs/history/RELEASE_VALIDATION_2.5.10_r7c.json').read_text())
        self.assertEqual(status['build_id'],m['build_id'])
        self.assertEqual(status['version'],m['version'])
        self.assertEqual(status['status'],'INCOMPLETE_STAGING_ONLY')
        self.assertEqual(historic['version'],'2.5.10')
        self.assertIn('EXTERNALLY',status['offline_suite'])
        self.assertEqual(status['real_vps_install_reboot_backup_restore'],'NOT_PERFORMED')


if __name__=='__main__':unittest.main()
