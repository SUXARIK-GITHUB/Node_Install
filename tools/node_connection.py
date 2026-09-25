#!/usr/bin/env python3
"""Local-only, secret-safe inspection/reconciliation for owned VKarmani installs.

No firewall flushing, raw log printing, private-key printing, panel API writes,
network/kernel tuning or remote telemetry. Runtime inspection stays in memory.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile

ETC = Path('/etc/vkarmani-node')
OPT = Path('/opt/vkarmani-node')
LIB = Path(os.environ.get('VKARMANI_DIAG_LIB', '/usr/local/lib/vkarmani-node'))
TLS = Path(os.environ.get('VKARMANI_DIAG_TLS', '/usr/local/sbin/vkarmani-node-tls-check'))
OFFICIAL = re.compile(r'(?:remnawave/node|ghcr\.io/remnawave/node)(?::[A-Za-z0-9_.-]+)?(?:@sha256:[a-f0-9]{64})?\Z')


class Error(Exception):
    pass


def command(argv, timeout=25):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Error('COMMAND_UNAVAILABLE_OR_TIMEOUT: ' + argv[0]) from exc
    if r.returncode:
        # Docker/Compose errors may include environment contents; don't echo them.
        raise Error('COMMAND_FAILED: ' + argv[0])
    return r.stdout


def atomic_text(path, text, mode=0o600):
    path = Path(path)
    fd, tmp = tempfile.mkstemp(prefix=path.name + '.', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def modules():
    helper = runpy.run_path(str(LIB / 'node_helper.py'))
    tls = runpy.run_path(str(TLS))
    cfg = helper['normalize_config'](helper['read_json'](ETC / 'config.json'))
    helper['check_secret'](cfg)
    return cfg, helper, tls


def expected_env():
    return dict(line.split('=', 1) for line in (ETC / 'remnanode.env').read_text().splitlines()
                if line and not line.startswith('#'))


def runtime_matches(inspect, expected):
    actual = dict(x.split('=', 1) for x in inspect.get('Config', {}).get('Env', []) if '=' in x)
    return {key: actual.get(key) == expected[key] for key in ('NODE_PORT', 'SECRET_KEY', 'TZ')}


def reconcile_compose(doc, cfg, digest):
    if not OFFICIAL.fullmatch(digest) or '@sha256:' not in digest:
        raise Error('OFFICIAL_DIGEST_REQUIRED')
    if set(doc.get('services', {})) != {'remnanode'}:
        raise Error('STOP_UNEXPECTED_COMPOSE_SERVICES')
    service = doc['services']['remnanode']
    if not OFFICIAL.fullmatch(str(service.get('image', ''))):
        raise Error('STOP_UNOFFICIAL_IMAGE')
    # Keep custom legitimate settings. Remove only options incompatible with host mode.
    service['image'] = digest
    service['container_name'] = 'remnanode'
    service['network_mode'] = 'host'
    service.pop('ports', None)
    service.pop('networks', None)
    service['restart'] = 'always'
    service['stop_grace_period'] = '30s'
    caps = service.setdefault('cap_add', [])
    if 'NET_ADMIN' not in caps:
        caps.append('NET_ADMIN')
    # Compose's normalized JSON contains expanded env. Remove the three managed
    # entries so env_file is the only source; an old environment override must
    # not silently shadow a newly saved key or management port.
    env = service.get('environment') or {}
    if not isinstance(env, dict):
        raise Error('UNEXPECTED_ENVIRONMENT_SHAPE')
    for key in ('SECRET_KEY', 'NODE_PORT', 'TZ'):
        env.pop(key, None)
    service['environment'] = {key: value.replace('$', '$$') if isinstance(value, str) else value
                              for key, value in env.items()}
    service['env_file'] = [str(ETC / 'remnanode.env')]
    volumes = service.setdefault('volumes', [])
    if not isinstance(volumes, list) or any(not isinstance(v, dict) for v in volumes):
        raise Error('UNEXPECTED_NORMALIZED_VOLUMES')
    matches = [v for v in volumes if v.get('target') == '/dev/shm']
    if matches:
        if len(matches) != 1 or matches[0].get('source') != '/dev/shm' or matches[0].get('type') != 'bind':
            raise Error('STOP_UNEXPECTED_SELFSTEAL_MOUNT')
    else:
        volumes.append({'type': 'bind', 'source': '/dev/shm', 'target': '/dev/shm'})
    doc['name'] = 'vkarmani-node'
    return doc


def safe_node_version():
    # Read-only banner parsing; never print raw Docker logs or live Xray config.
    try:
        logs = command(['docker', 'logs', '--tail', '150', 'remnanode'], 10)
        clean = re.sub(r'\x1b\[[0-9;]*m', '', logs)
        matches = re.findall(r'(?:Remnawave\s*Node|Node\s*Version|Node\s*version)[^\n0-9]{0,30}v?(\d+\.\d+\.\d+)', clean, re.I)
        return matches[-1] if matches else 'UNKNOWN'
    except Error:
        return 'UNKNOWN'


def inspect_runtime():
    rows = json.loads(command(['docker', 'inspect', 'remnanode']))
    if len(rows) != 1:
        raise Error('NODE_INSPECT_UNEXPECTED')
    return rows[0]


def audit():
    cfg, helper, tls = modules()
    failures = 0
    print('SECRET_KEY_VALID=PASS')
    # Public fingerprints identify wrong-panel credentials without revealing them.
    material, ca, _ = tls['load_material']()
    import ssl
    print('CA_SHA256=' + hashlib.sha256(ssl.PEM_cert_to_DER_cert(ca)).hexdigest())
    print('API_SNI=DERIVED (not the Selfsteal domain)')
    print('NODE_ADDRESS=' + cfg['public_ipv4'] + ':' + str(cfg['node_port']))
    print('PANEL_SOURCE_ALLOWLIST=' + ','.join(cfg['panel_ipv4']))
    try:
        node = inspect_runtime()
        checks = runtime_matches(node, expected_env())
        for name, ok in checks.items():
            print('RUNTIME_' + name + '_MATCH=' + ('PASS' if ok else 'FAIL'))
            failures += not ok
        for name, actual, expected in (
            ('HOST_NETWORK', node['HostConfig'].get('NetworkMode'), 'host'),
            ('RESTART_POLICY', node['HostConfig'].get('RestartPolicy', {}).get('Name'), 'always'),
            ('RUNNING', node.get('State', {}).get('Running'), True),
        ):
            print(name + '=' + ('PASS' if actual == expected else 'FAIL'))
            failures += actual != expected
        print('OOM_KILLED=' + str(bool(node.get('State', {}).get('OOMKilled'))))
        print('RESTART_COUNT=' + str(int(node.get('RestartCount', 0))))
        image = node['Config'].get('Image', '')
        print('IMAGE=' + (image if OFFICIAL.fullmatch(image) else 'UNEXPECTED_IMAGE'))
        env = dict(x.split('=', 1) for x in node['Config'].get('Env', []) if '=' in x)
        sni = env.get('SNI_VERIFICATION', '(image default)')
        print('SNI_VERIFICATION=' + (sni if sni in ('true', 'false', '(image default)') else 'INVALID'))
        version = safe_node_version()
        print('NODE_VERSION=' + version)
        if version.startswith('3.3.'):
            print('NODE_COMPATIBILITY=WARNING_3_3_REQUIRES_NEW_PANEL_SNI; use --repair-connection --refresh-image')
    except (Error, KeyError, ValueError):
        print('RUNTIME_INSPECTION=FAIL (details withheld to protect environment)')
        failures += 1
    # No DNS, Nginx, GRUB, certbot or BBR dependency: this diagnoses management only.
    result = subprocess.run([str(TLS), '--all-local'], check=False)
    failures += bool(result.returncode)
    print('NODE_MANAGEMENT_LOCAL=' + ('FAIL' if failures else 'PASS'))
    print('PANEL_CONNECTION=NOT_VERIFIED; run --diagnose-panel on the panel server')
    print('No configuration or service state was changed by this audit.')
    return 1 if failures else 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['audit', 'reconcile', 'verify-runtime'])
    p.add_argument('digest', nargs='?')
    args = p.parse_args()
    if os.geteuid() != 0:
        raise Error('ROOT_REQUIRED')
    if args.action == 'audit':
        return audit()
    cfg, helper, tls = modules()
    if args.action == 'verify-runtime':
        matches = runtime_matches(inspect_runtime(), expected_env())
        if not all(matches.values()):
            raise Error('RUNTIME_ENV_MISMATCH')
        return 0
    raw = command(['docker', 'compose', '-f', str(OPT / 'compose.yaml'), 'config', '--format', 'json'])
    doc = reconcile_compose(json.loads(raw), cfg, args.digest or '')
    atomic_text(OPT / 'compose.yaml', json.dumps(doc, indent=2) + '\n')
    print('COMPOSE_RECONCILED=PASS (managed credentials remain in env_file)')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Error as exc:
        print('CONNECTION_CHECK=FAIL ' + str(exc), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('CONNECTION_CHECK=FAIL CONFIG_OR_RUNTIME_ERROR (no credentials printed)', file=sys.stderr)
        sys.exit(1)
