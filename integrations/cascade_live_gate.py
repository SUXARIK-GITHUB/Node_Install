#!/usr/bin/env python3
"""Read-only audit of RemnaNode *cold* config (live container CLI or supplied JSON).

Does not mutate host/panel/core. Cold config != effective running sessions. Use
external clients and packet captures to close full staging acceptance.
"""
import argparse
import json
import os
import subprocess
from pathlib import Path
import sys

import cascade_deployment as cd
import cascade_panel_audit as panel
import cascade_profiles as profiles

DOCKER_WRAPPER = '/usr/local/sbin/vkarmani-docker-local'
MAX_OUTPUT = 2*1024*1024


def capture_cold(command=DOCKER_WRAPPER):
    if os.geteuid() != 0:
        raise ValueError('ROOT_REQUIRED_FOR_LIVE_CONTAINER_AUDIT')
    if command != DOCKER_WRAPPER:
        raise ValueError('UNTRUSTED_DOCKER_COMMAND')
    proc=subprocess.run([command, 'exec', 'remnanode', 'cli', '--dump-config'],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=25, check=False,
        env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
             'LC_ALL':'C','LANG':'C','HOME':'/root','DOCKER_CONFIG':'/dev/null'})
    if proc.returncode or len(proc.stdout)>MAX_OUTPUT or len(proc.stderr)>MAX_OUTPUT:
        raise ValueError('NODE_COLD_CONFIG_CLI_FAILED_OR_TOO_LARGE')
    try:
        return json.loads(proc.stdout.decode('utf-8'),
                          object_pairs_hook=profiles.no_duplicates,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE')))
    except (ValueError, UnicodeError) as exc:
        raise ValueError('NODE_COLD_CONFIG_INVALID_JSON') from exc


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--role-bundle',required=True)
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument('--live-cold',action='store_true')
    group.add_argument('--computed-json',type=Path)
    ns=p.parse_args(argv)
    try:
        bundle=cd.read_role(ns.role_bundle)
        computed=capture_cold() if ns.live_cold else cd.read_profile(ns.computed_json)
        result=panel.audit(bundle,computed)
    except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired,
            cd.DeploymentError, profiles.Invalid) as exc:
        print('CASCADE_COLD_AUDIT=FAIL reason='+(
            str(exc) if isinstance(exc, (ValueError, cd.DeploymentError, profiles.Invalid))
            else type(exc).__name__),file=sys.stderr)
        return 1
    print('CASCADE_COLD_AUDIT=PASS role='+result['role']+' users='+str(result['client_count']))
    print('SCOPE=COLD_NODE_CONFIG_ONLY; CORE_LIVE_SESSIONS_DNS_TCP_UDP_NOT_VERIFIED')
    return 0


if __name__=='__main__':
    sys.exit(main())
