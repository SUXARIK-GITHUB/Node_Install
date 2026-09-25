#!/usr/bin/env python3
"""Offline static/config checks. Does NOT start any service or run the installer."""
import ast
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
BUILD=ROOT/'build'
subprocess.run(['python3',str(BUILD/'rebuild.py')],check=True)
s=(ROOT/'install.sh').read_text()
results=[]

def run(args):
    r=subprocess.run(args,capture_output=True,text=True,timeout=40)
    if r.returncode:
        raise RuntimeError('FAILED: '+repr(args)+'\n'+r.stdout+r.stderr)
    return r.stdout+r.stderr

run(['bash','-n',str(ROOT/'install.sh')]);results.append('PASS bash -n assembled installer')
run(['bash','-n',str(BUILD/'collect-input.sh')]);results.append('PASS bash -n input collector')
run(['bash','-n',str(BUILD/'health.sh')]);results.append('PASS bash -n health script')
run(['bash',str(ROOT/'install.sh'),'--help']);results.append('PASS --help (no system mutation)')
ast.parse((BUILD/'node_helper.py').read_text());results.append('PASS Python helper AST')
# Extract heredocs using the literal delimiter declared on each starting line.
blocks=[]
lines=s.splitlines();i=0
while i<len(lines):
    m=re.search(r"<<\s*'?([A-Z][A-Z_0-9]*)'?\s*$",lines[i])
    if not m:i+=1;continue
    head=lines[i];delim=m.group(1);body=[];i+=1
    while i<len(lines) and lines[i]!=delim:body.append(lines[i]);i+=1
    if i==len(lines):raise RuntimeError('Unterminated heredoc '+head)
    blocks.append((head,'\n'.join(body)+'\n'));i+=1
shell_count=python_count=0
with tempfile.TemporaryDirectory(prefix='vkarmani-static-') as temporary:
    tmp=Path(temporary)
    for number,(head,body) in enumerate(blocks):
        if body.startswith('#!/bin/') or body.startswith('#!/usr/bin/env bash'):
            p=tmp/f'block-{number}.sh';p.write_text(body)
            run(['bash','-n',str(p)]);shell_count+=1
        if head.endswith("<<'PY'") or head.endswith("<<'PY_HELPER'"):
            ast.parse(body);python_count+=1
    # Unit syntax verification with stub dependencies, never start them.
    unitroot=tmp/'systemd-root';units=unitroot/'etc/systemd/system';units.mkdir(parents=True)
    (unitroot/'etc/os-release').write_text('ID=debian\nVERSION_ID=12\n')
    names=[]
    for head,body in blocks:
        m=re.search(r'/etc/systemd/system/([a-z0-9.-]+)',head)
        if m:
            names.append(m.group(1));(units/m.group(1)).write_text(body)
    deps=set()
    for name in names:
        for line in (units/name).read_text().splitlines():
            if line.startswith(('After=','Before=','Requires=','Wants=','WantedBy=')):
                deps.update(line.split('=',1)[1].split())
    deps.update({'sysinit.target','basic.target','shutdown.target','sockets.target','timers.target','default.target'})
    for name in deps-set(names):
        (units/name).write_text('[Unit]\nDescription=Offline dependency stub\n'+
                               ('[Service]\nType=oneshot\nExecStart=/bin/true\nRemainAfterExit=yes\n' if name.endswith('.service') else ''))
    commands={'/bin/true','/bin/sh'}
    for name in names:
        commands.update(re.findall(r'^Exec\w+=([^\s]+)',(units/name).read_text(),re.M))
    for cmd in commands:
        p=unitroot/cmd.lstrip('/');p.parent.mkdir(parents=True,exist_ok=True);p.write_text('#!/bin/sh\nexit 0\n');p.chmod(0o755)
    output=run(['systemd-analyze','--root='+str(unitroot),'verify','--man=no']+[str(units/x) for x in names])
    (BUILD/'systemd-test-results.txt').write_text('OFFLINE: generated units, stub dependencies and executables; nothing started.\n'+
                                               'Units: '+', '.join(names)+'\nExit: 0\n'+output)
    results.append(f'PASS systemd unit verification: {len(names)} units (stubs; NOT runtime)')
    # Real nginx syntax/config validation using a temporary self-signed cert only.
    if shutil.which('nginx'):
        tls=tmp/'tls';tls.mkdir()
        run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2',
             '-subj','/CN=ee1.example.com','-keyout',str(tls/'privkey.pem'),'-out',str(tls/'fullchain.pem')])
        servers=[]
        for head,body in blocks:
            if '/etc/nginx/conf.d/' not in head:continue
            body=body.replace('$DOMAIN','ee1.example.com').replace('\\$','$')
            body=body.replace('/etc/letsencrypt/live/ee1.example.com',str(tls))
            body=body.replace('/var/www/vkarmani-node',str(tmp/'www'))
            servers.append(body)
        conf=tmp/'nginx.conf';conf.write_text(f'pid {tmp}/nginx.pid;\nerror_log {tmp}/error.log;\nevents {{}}\nhttp {{ access_log off;\n'+''.join(servers)+'\n}\n')
        output=run(['nginx','-t','-p',str(tmp),'-c',str(conf)])
        (BUILD/'nginx-test-results.txt').write_text('OFFLINE nginx -t: temporary paths and self-signed test certificate; no listener started.\n'+output)
        results.append('PASS nginx -t: generated HTTP and TLS cover configs (temp test certificate)')
    else:results.append('NOT RUN nginx -t: nginx unavailable')
    # The kernel/OS changes below are only presence guards, not live-host tests.
    for token in ['vk_collect_inputs','NODE_PORT_DEFAULT=2222',
                  '--register-unsafely-without-email','OnCalendar=Mon *-*-* 04:00:00 Europe/Moscow',
                  'ipv6.disable=1','full-upgrade','autoremove --purge','NODE_SETUP=PASS',
                  'VPN_STATUS=WAITING_FOR_PANEL_PROFILE','network_mode: host']:
        if token not in s:raise RuntimeError('Missing expected behavior '+token)
    for token in ['PANEL_IPV4_DEFAULT', 'def ask_secret(', 'def ask_domain(', 'helper provision','helper panel-check','--email "$EMAIL"','API token Remnawave']:
        if token in s:raise RuntimeError('Old API code remains '+token)
    if 'ports:' in next(body for head,body in blocks if '$OPT/compose.yaml' in head):
        raise RuntimeError('Docker bridge port publishing must not be introduced')
    if any(token in s for token in ['docker system prune','docker volume prune','PubkeyAuthentication no']):
        raise RuntimeError('Unsafe destructive/auth behavior found')
    if 'ufw allow proto tcp from "$panel" to any port "$NODE_PORT"' not in s:
        raise RuntimeError('Expected panel-only UFW rule not found')
    if re.search(r'ufw allow (?:[\"\']?\$NODE_PORT|2222)', s):
        raise RuntimeError('Unrestricted node control-port allow found')
    assert s.index('\nvk_collect_inputs\n') < s.index('\napt-get update\n'), 'Inputs must precede APT'
    results.append('PASS invariant checks: three-input mode, no panel API, no global control-port allow, no volume pruning')
results.append(f'PASS extracted shell heredocs: {shell_count}; Python heredocs: {python_count}')
calendar=run(['systemd-analyze','calendar','--iterations=3','Mon *-*-* 04:00:00 Europe/Moscow'])
(BUILD/'timer-test-results.txt').write_text(calendar)
results.append('PASS systemd Monday 04:00 Europe/Moscow calendar')
(BUILD/'static-results.txt').write_text('\n'.join(results)+'\n')
print('\n'.join(results))
