#!/usr/bin/env python3
"""Generate LOCAL-ONLY HTTP or TCP Nginx proxy fragments for a new staging config.

This script DOES NOT apply, reload or modify Nginx. TCP stream config must be
included at the top level of nginx.conf (not /etc/nginx/conf.d inside http).
Public port 80/443 cannot be hijacked away from existing ACME/Xray flows.
"""
import argparse
from pathlib import Path
import sys

RESERVED={22,80,443,2222}


def port(value):
    try: n=int(value)
    except (TypeError,ValueError) as exc: raise ValueError('invalid port') from exc
    if n<1025 or n>65535 or n in RESERVED:
        raise ValueError('port restricted to unprivileged non-reserved range')
    return n


def generate(kind, listen, backend):
    l,b=port(listen),port(backend)
    if l == b:
        raise ValueError('proxy recursion forbidden')
    if kind == 'http':
        return f'''# Local-only, staged include under http {{}} after ownership/port audit.
server {{
    listen 127.0.0.1:{l};
    server_name _;
    access_log off;
    server_tokens off;
    location / {{
        proxy_pass http://127.0.0.1:{b};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_connect_timeout 5s;
        proxy_read_timeout 30s;
        proxy_send_timeout 30s;
    }}
}}
'''
    if kind == 'tcp':
        return f'''# Include at TOP-LEVEL nginx.conf, NOT inside http {{}}.
# Requires nginx stream module enabled; test against staging Nginx binary.
stream {{
    server {{
        listen 127.0.0.1:{l};
        proxy_pass 127.0.0.1:{b};
        proxy_connect_timeout 5s;
        proxy_timeout 30s;
    }}
}}
'''
    raise ValueError('invalid kind')


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kind',choices=['http','tcp'],required=True)
    p.add_argument('--listen',required=True)
    p.add_argument('--backend',required=True)
    p.add_argument('--output',type=Path,required=True,help='new .conf file, never an existing file')
    a=p.parse_args(argv)
    try:
        output=generate(a.kind,a.listen,a.backend)
        if a.output.suffix!='.conf' or not a.output.parent.is_dir():
            raise ValueError('output must be a new .conf file in an existing directory')
        with a.output.open('x',encoding='utf-8') as f:
            f.write(output)
        a.output.chmod(0o600)
    except (ValueError,OSError) as exc:
        print('PROXY_PLAN=FAIL '+type(exc).__name__,file=sys.stderr)
        return 1
    print('PROXY_PLAN=PASS LOCAL_LOOPBACK_ONLY NO_DEPLOYMENT NO_NGINX_RELOAD')
    return 0


if __name__=='__main__':sys.exit(main())
