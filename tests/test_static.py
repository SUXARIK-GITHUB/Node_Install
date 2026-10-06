import ast
import configparser
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from common import ROOT, SCRIPT, heredocs, module, payload, template


class StaticTests(unittest.TestCase):
    def test_bash_syntax_and_generated_scripts(self):
        subprocess.run(['bash', '-n', str(ROOT / 'install.sh')], check=True)
        count = 0
        for tag, _, body in heredocs():
            if body.startswith(('#!/usr/bin/env bash', '#!/bin/bash', '#!/bin/sh')):
                subprocess.run(['bash', '-n'], input=body, text=True, check=True, capture_output=True)
                count += 1
        self.assertGreaterEqual(count, 5)

    def test_all_python_payloads_compile(self):
        count = 0
        for tag, command, body in heredocs():
            if (body.startswith('#!/usr/bin/env python3') or 'python3 ' in command):
                compile(body, f'install.sh::{tag}::{count}', 'exec')
                count += 1
        self.assertGreaterEqual(count, 14)

    def test_cli_help_version_and_rejection_are_inert(self):
        for arg in ('--version', '--help'):
            result = subprocess.run(['bash', str(ROOT / 'install.sh'), arg], text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('2.5.0', result.stdout)
        result = subprocess.run(['bash', str(ROOT / 'install.sh'), '--invalid'], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 2)

    def test_source_guard_does_not_install(self):
        result = subprocess.run(['bash', '-c', 'source "$1"; declare -F vkarmani_main; printf "SOURCE_OK\\n"', '_',
                                 str(ROOT / 'install.sh')], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'vkarmani_main\nSOURCE_OK\n')

    def test_only_three_interactive_prompts_in_required_order(self):
        prompts = re.findall(r"printf '\[([123])/3\] ([^']+)", SCRIPT)
        self.assertEqual([number for number, _ in prompts], ['1', '2', '3'])
        self.assertIn('SECRET_KEY', prompts[0][1])
        self.assertIn('Домен', prompts[1][1])
        self.assertIn('IPv4 технички', prompts[2][1])

    def test_no_mass_upgrades_or_docker_prune(self):
        active = '\n'.join(x for x in SCRIPT.splitlines() if not x.lstrip().startswith('#'))
        self.assertNotRegex(active, r'(?m)^\s*(?:apt-get|apt|apt_run)\b[^\n]*\b(?:full-upgrade|dist-upgrade|autoremove)\b')
        self.assertNotRegex(active, r'docker\s+(?:system|image|volume|container)\s+prune')
        self.assertNotIn('curl -k', active)
        self.assertNotIn('--insecure', active)
        self.assertIn('NO_REBOOT=0', SCRIPT)
        self.assertIn('WEEKLY_REBOOT=0', SCRIPT)

    def test_default_compose_has_net_admin_and_no_published_ports(self):
        import yaml
        text = template('"$OPT/compose.yaml"')
        text = text.replace('$DIGEST', 'remnawave/node@sha256:' + 'a' * 64)
        text = text.replace('$ETC', '/etc/vkarmani-node')
        obj = yaml.safe_load(text)
        self.assertEqual(set(obj['services']), {'remnanode'})
        node = obj['services']['remnanode']
        self.assertEqual(node['network_mode'], 'host')
        self.assertEqual(node['restart'], 'always')
        self.assertNotIn('ports', node)
        self.assertEqual(node['cap_add'], ['NET_ADMIN'])
        self.assertEqual(node['cap_drop'], ['NET_RAW'])
        self.assertIn('no-new-privileges:true', node['security_opt'])
        mount = node['volumes'][0]
        self.assertEqual((mount['source'], mount['target'], mount['read_only']),
                         ('/run/vkarmani-selfsteal', '/dev/shm', True))
        self.assertIs(mount['bind']['create_host_path'], False)
        self.assertEqual(node['env_file'], ['/etc/vkarmani-node/remnanode.env'])
        self.assertNotIn('SECRET_KEY', text)

    def test_net_admin_is_new_install_default_and_runtime_policy(self):
        self.assertIn('ALLOW_NET_ADMIN=1', SCRIPT)
        self.assertIn("'allow_net_admin': True", SCRIPT)
        self.assertIn('      - NET_ADMIN', template('"$OPT/compose.yaml"'))
        checker = payload('VK_PAYLOAD_VK_WRITE_ACCEPTANCE')
        self.assertIn('pass NODE_NET_ADMIN', checker)
        self.assertNotIn("warn NODE_NET_ADMIN 'explicit opt-in", checker)

    def test_fail2ban_action_is_always_ssh_port_scoped(self):
        config = configparser.ConfigParser(interpolation=None)
        config.read_string(payload('VK_F2B_ACTION'))
        for name in ('actionban', 'actionunban'):
            action = config['Definition'][name]
            self.assertIn('to any port <port> proto tcp', action)
            self.assertIn('from <ip>', action)
            self.assertNotIn('app ', action)
            self.assertNotIn('kill', action)
        jail = template('/etc/fail2ban/jail.d/99-vkarmani-sshd.local')
        self.assertIn('ignoreip = 127.0.0.1/8', jail)
        self.assertNotIn('$ADMIN_IP', jail)
        self.assertNotIn('$PANEL_IP', jail)

    def test_boot_has_one_node_owner(self):
        unit = payload('VK_PAYLOAD_VK_WRITE_NODE_UNIT')
        self.assertNotIn('Requires=nginx', unit)
        self.assertNotIn('ExecStartPre=', unit)
        self.assertNotIn('Restart=always', unit)
        self.assertNotRegex(unit, r'(?m)^\[Install\]$')
        self.assertIn('systemctl disable vkarmani-node.service', SCRIPT)

    def test_no_dynamic_install_execution_in_tests(self):
        for file in (ROOT / 'tests').glob('test_*.py'):
            ast.parse(file.read_text())
        self.assertIn('flock -x 7', template('/usr/local/sbin/vkarmani-network-rollback'))
        self.assertIn('network-rollback-running', SCRIPT)

    def test_nginx_http_redirect_and_acme_template(self):
        config = template('/etc/nginx/conf.d/10-vkarmani-http.conf')
        self.assertIn('listen $PUBLIC_IP:80;', config)
        self.assertIn('location ^~ /.well-known/acme-challenge/', config)
        self.assertIn('return 301 https://$DOMAIN', config)
        self.assertNotIn('listen 443', config)


if __name__ == '__main__':
    unittest.main()
