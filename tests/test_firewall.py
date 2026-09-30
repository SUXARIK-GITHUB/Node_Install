"""Fault injection into the actual read-only firewall validator; no rules applied."""
import copy
import unittest
from common import module

CFG = {'node_port': 2222, 'public_ipv4': '8.8.4.4', 'panel_ipv4': ['1.1.1.1']}
JUMPS = ['ufw-before-logging-input','ufw-before-input','ufw-after-input',
         'ufw-after-logging-input','ufw-reject-input','ufw-track-input']
INPUT = '-P INPUT DROP\n' + ''.join('-A INPUT -j '+x+'\n' for x in JUMPS)
RULES = ('-N ufw-user-input\n'
         '-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT\n'
         '-A ufw-user-input -d 8.8.4.4/32 -p tcp -m tcp --dport 80 -j ACCEPT\n'
         '-A ufw-user-input -d 8.8.4.4/32 -p tcp -m tcp --dport 443 -j ACCEPT\n'
         '-A ufw-user-input -s 1.1.1.1/32 -p tcp -m tcp --dport 2222 -j ACCEPT\n')

class FirewallFaultTests(unittest.TestCase):
    def setUp(self):
        self.h=module('PY_FIREWALL_CHECK')

    def validate(self, rules=RULES, input_rules=INPUT, cfg=None, ssh=('22',)):
        return self.h.validate_rules(cfg or CFG,ssh,rules,input_rules)

    def rejected(self,rules=RULES,input_rules=INPUT,cfg=None,ssh=('22',)):
        with self.assertRaises((ValueError,TypeError)):
            self.validate(rules,input_rules,cfg,ssh)

    def test_exact_policy(self): self.assertTrue(self.validate())
    def test_missing_ssh_rule(self): self.rejected('\n'.join(x for x in RULES.splitlines() if '--dport 22 ' not in x))
    def test_missing_acme_rule(self): self.rejected('\n'.join(x for x in RULES.splitlines() if '--dport 80 ' not in x))
    def test_missing_reality_rule(self): self.rejected('\n'.join(x for x in RULES.splitlines() if '--dport 443 ' not in x))
    def test_missing_panel_rule(self): self.rejected('\n'.join(x for x in RULES.splitlines() if '--dport 2222 ' not in x))
    def test_public_api_refused(self): self.rejected(RULES.replace('-s 1.1.1.1/32 ',''))
    def test_panel_subnet_instead_of_host_refused(self): self.rejected(RULES.replace('1.1.1.1/32','1.1.1.0/24'))
    def test_ssh_ip_allowlist_refused(self): self.rejected(RULES.replace('-p tcp -m tcp --dport 22 ', '-s 1.1.1.1/32 -p tcp -m tcp --dport 22 '))
    def test_wrong_node_destination_refused(self): self.rejected(RULES.replace('8.8.4.4/32','8.8.8.8/32'))
    def test_reality_udp_is_not_tcp_success(self): self.rejected(RULES.replace('-p tcp -m tcp --dport 443','-p udp --dport 443'))
    def test_extra_open_port_refused(self): self.rejected(RULES+'-A ufw-user-input -p tcp --dport 8080 -j ACCEPT\n')
    def test_blanket_accept_refused(self): self.rejected(RULES+'-A ufw-user-input -j ACCEPT\n')
    def test_default_accept_refused(self): self.rejected(input_rules=INPUT.replace('-P INPUT DROP','-P INPUT ACCEPT'))
    def test_early_input_bypass_refused(self): self.rejected(input_rules=INPUT.replace('-A INPUT','-A INPUT -j ACCEPT\n-A INPUT',1))
    def test_removed_ufw_jump_refused(self): self.rejected(input_rules=INPUT.replace('-A INPUT -j ufw-before-input\n',''))
    def test_unreviewed_extension_refused(self): self.rejected(RULES.replace('--dport 443','-m mark --mark 1 --dport 443'))
    def test_negated_source_refused(self): self.rejected(RULES.replace('-s 1.1.1.1','! -s 1.1.1.1'))
    def test_duplicate_accept_refused(self): self.rejected(RULES+RULES.splitlines()[-1]+'\n')
    def test_comment_supported(self): self.assertTrue(self.validate(RULES.replace('-j ACCEPT','-m comment --comment "local test" -j ACCEPT')))
    def test_fail2ban_scoped_drop_supported(self): self.assertTrue(self.validate(RULES+'-A ufw-user-input -s 9.9.9.9/32 -p tcp --dport 22 -j DROP\n'))
    def test_fail2ban_blanket_drop_refused(self): self.rejected(RULES+'-A ufw-user-input -s 9.9.9.9/32 -j DROP\n')
    def test_multiport_ssh_ban_supported(self):
        rules=RULES+'-A ufw-user-input -p tcp --dport 2200 -j ACCEPT\n-A ufw-user-input -s 9.9.9.9/32 -p tcp -m multiport --dports 22,2200 -j DROP\n'
        self.assertTrue(self.validate(rules,ssh=('22','2200')))
    def test_second_panel_host_must_be_present(self):
        cfg=copy.deepcopy(CFG);cfg['panel_ipv4'].append('1.0.0.1')
        self.rejected(cfg=cfg)
        self.assertTrue(self.validate(RULES+'-A ufw-user-input -s 1.0.0.1/32 -p tcp --dport 2222 -j ACCEPT\n',cfg=cfg))
