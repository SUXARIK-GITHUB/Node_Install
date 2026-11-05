#!/usr/bin/env python3
"""Read-only, secret-redacting Xray transport/Reality/profile audit.

Validates *structure*, not Xray compatibility, panel deployment or client
connectivity. Only supported production profiles (RAW+REALITY+Vision and
XHTTP+REALITY) are classified PASS. Experimental transport/profile combinations
are REVIEW. Never sends network traffic or changes the host/panel.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys

MAX_BYTES = 2 * 1024 * 1024
DNS_NAME = re.compile(r'(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
PATH = re.compile(r'/[A-Za-z0-9_.~/-]{1,160}\Z')


def secret_free_json(path):
    """Only reads a named, regular, non-linked file; never prints contents."""
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > MAX_BYTES:
            raise ValueError('PROFILE_NOT_REGULAR_OR_SIZE_INVALID')
        with os.fdopen(fd, 'rb') as handle:
            fd = -1
            content = handle.read(MAX_BYTES + 1)
        if len(content) > MAX_BYTES:
            raise ValueError('PROFILE_TOO_LARGE')
        def no_duplicates(pairs):
            d = {}
            for k, v in pairs:
                if k in d:
                    raise ValueError('PROFILE_DUPLICATE_JSON_KEY')
                d[k] = v
            return d
        def no_nonfinite(_):
            raise ValueError('PROFILE_NONFINITE_JSON_VALUE')
        return json.loads(content.decode('utf-8'), object_pairs_hook=no_duplicates,
                          parse_constant=no_nonfinite)
    finally:
        if fd >= 0:
            os.close(fd)


def _valid_sni(value):
    return isinstance(value, str) and DNS_NAME.fullmatch(value) is not None and value == value.lower()


def _valid_path(value):
    return (isinstance(value, str) and PATH.fullmatch(value) is not None and
            not value.startswith('//') and '..' not in value.split('/') and
            '/./' not in value and '//' not in value)


def audit(profile, expected_domain=None):
    errors, reviews, modes = [], [], []
    if expected_domain is not None and not _valid_sni(expected_domain):
        return {'status':'FAIL', 'modes': [], 'issues':['EXPECTED_DOMAIN_INVALID'],
                'observations': [], 'actions_performed':'NONE'}
    if not isinstance(profile, dict):
        errors.append('PROFILE_NOT_OBJECT')
        inbound_list = []
    else:
        inbound_list = profile.get('inbounds')
        if not isinstance(inbound_list, list) or not (1 <= len(inbound_list) <= 32):
            errors.append('INBOUNDS_MISSING_OR_INVALID')
            inbound_list = []
    for inbound in inbound_list:
        if not isinstance(inbound, dict):
            errors.append('INVALID_INBOUND')
            continue
        if inbound.get('protocol') == 'hysteria':
            settings=inbound.get('settings')
            stream=inbound.get('streamSettings')
            if not isinstance(settings,dict) or not isinstance(stream,dict):
                errors.append('HYSTERIA_SETTINGS_MISSING'); continue
            if settings.get('version') != 2 or stream.get('security') != 'tls':
                errors.append('HYSTERIA2_REQUIRES_V2_AND_TLS')
            if stream.get('method',stream.get('network')) != 'hysteria':
                errors.append('HYSTERIA2_TRANSPORT_METHOD_INVALID')
            hs=stream.get('hysteriaSettings')
            if not isinstance(hs,dict) or hs.get('version') != 2:
                errors.append('HYSTERIA2_TRANSPORT_VERSION_INVALID')
            auths=settings.get('users')
            if (not isinstance(auths,list) or not auths or len(auths)>32 or
                any(not isinstance(u,dict) or not isinstance(u.get('auth'),str) or
                    len(u['auth'])<32 for u in auths)):
                errors.append('HYSTERIA2_AUTH_INVALID')
            tls=stream.get('tlsSettings')
            certs=tls.get('certificates') if isinstance(tls,dict) else None
            if (not isinstance(certs,list) or len(certs)!=1 or
                not isinstance(certs[0],dict) or
                not all(isinstance(certs[0].get(k),str) and
                        certs[0][k].startswith('/etc/letsencrypt/live/') and
                        '..' not in certs[0][k].split('/')
                        for k in ('certificateFile','keyFile'))):
                errors.append('HYSTERIA2_CERTIFICATE_MOUNT_REQUIRES_REVIEW')
            p=inbound.get('port')
            if type(p) is not int or not 1<=p<=65535:
                errors.append('HYSTERIA2_UDP_PORT_INVALID')
            modes.append({'network':'hysteria','security':'tls'})
            reviews.append('HYSTERIA2_OPTIONAL_UDP_TLS_REQUIRES_RUNTIME_AND_FIREWALL_GATES')
            continue
        if inbound.get('protocol') != 'vless':
            reviews.append('NON_VLESS_INBOUND_NOT_AUDITED')
            continue
        settings = inbound.get('settings')
        stream = inbound.get('streamSettings')
        if not isinstance(settings, dict) or not isinstance(stream, dict):
            errors.append('VLESS_SETTINGS_OR_STREAM_MISSING')
            continue
        if settings.get('decryption') != 'none':
            errors.append('VLESS_DECRYPTION_NOT_NONE')
        if settings.get('fallbacks'):
            reviews.append('EXPLICIT_FALLBACK_REQUIRES_SEPARATE_REVIEW')
        net, security = stream.get('network'), stream.get('security')
        if net not in ('raw','xhttp'):
            reviews.append('TRANSPORT_OUTSIDE_NODE_INSTALL_SUPPORTED_SET')
        local_h2 = (net == 'xhttp' and security == 'none' and
                    inbound.get('listen') == '127.0.0.1' and
                    type(inbound.get('port')) is int and 1025<=inbound['port']<=65535)
        if security not in ('reality','tls') and not local_h2:
            errors.append('UNSUPPORTED_TRANSPORT_SECURITY')
        elif local_h2:
            reviews.append('XHTTP_PLAINTEXT_ALLOWED_ONLY_AS_LOCAL_TLS_TERMINATED_BACKEND')
        modes.append({'network': net if net in ('raw','xhttp') else 'other',
                      'security': security if security in ('reality','tls') or local_h2 else 'other'})
        if net == 'raw':
            if settings.get('flow') != 'xtls-rprx-vision':
                errors.append('RAW_VISION_FLOW_MISSING_OR_INCORRECT')
            if security == 'tls':
                reviews.append('RAW_TLS_NOT_NODE_INSTALL_DEFAULT')
        if net == 'xhttp':
            if settings.get('flow') not in ('', None):
                errors.append('XHTTP_MUST_NOT_USE_VISION_FLOW')
            xhttp = stream.get('xhttpSettings')
            if not isinstance(xhttp, dict):
                errors.append('XHTTP_SETTINGS_MISSING')
            else:
                if not _valid_path(xhttp.get('path')):
                    errors.append('XHTTP_PATH_INVALID')
                if xhttp.get('mode') not in ('auto','packet-up','stream-up','stream-one'):
                    errors.append('XHTTP_MODE_INVALID')
                if not _valid_sni(xhttp.get('host')):
                    errors.append('XHTTP_HOST_INVALID')
            if security in ('tls','none'):
                reviews.append('XHTTP_TLS_REVERSE_PROXY_REQUIRES_LIVE_TEST')
        if security == 'reality':
            reality = stream.get('realitySettings')
            if not isinstance(reality, dict):
                errors.append('REALITY_SETTINGS_MISSING')
            else:
                names = reality.get('serverNames')
                if not isinstance(names,list) or not names or len(names)>16 or not all(_valid_sni(s) for s in names):
                    errors.append('REALITY_SNI_LIST_INVALID')
                    names = []
                if expected_domain and expected_domain not in names:
                    reviews.append('REALITY_SNI_DIFFERS_FROM_EXPECTED_DOMAIN')
                target = reality.get('target',reality.get('dest'))
                if target == '/dev/shm/nginx.sock':
                    if type(reality.get('xver')) is not int or reality['xver'] != 1:
                        errors.append('SELFSTEAL_UNIX_PROXY_PROTOCOL_VERSION_MISMATCH')
                elif isinstance(target,str) and target.startswith('/'):
                    reviews.append('UNRECOGNIZED_SELFSTEAL_UNIX_PATH')
                else:
                    reviews.append('REALITY_TARGET_NOT_OWN_REVIEWED_SOCKET')
                if net == 'xhttp' and isinstance(stream.get('xhttpSettings'),dict) and names:
                    if stream['xhttpSettings'].get('host') not in names:
                        reviews.append('XHTTP_HOST_SNI_MISMATCH_REVIEW')
        sniffing=inbound.get('sniffing')
        if isinstance(sniffing,dict) and sniffing.get('enabled') is True and sniffing.get('routeOnly') is not True:
            reviews.append('SNIFFING_ROUTE_ONLY_REVIEW')
    outbounds = profile.get('outbounds') if isinstance(profile,dict) else None
    if not isinstance(outbounds,list):
        errors.append('OUTBOUNDS_NOT_ARRAY')
    elif any(isinstance(i,dict) and str(i.get('tag','')).startswith('VK_CASCADE_ENTRY') for i in inbound_list):
        tags={o.get('tag') for o in outbounds if isinstance(o,dict)}
        if 'DIRECT' in tags or not {'BLOCK','TO_EXIT_VLESS'}<=tags:
            errors.append('CASCADE_ENTRY_FAIL_CLOSED_OUTBOUNDS_MISMATCH')
    if not modes and not errors:
        reviews.append('NO_VLESS_PROFILE_TO_AUDIT')
    return {'status':'FAIL' if errors else ('REVIEW' if reviews else 'STATIC_PASS'),
            'modes':modes, 'issues':sorted(set(errors)),
            'observations':sorted(set(reviews)),
            'limitations':['Static structural check, not Xray syntax validation or a client handshake',
                           'Does not prove DPI resistance, throughput, censorship bypass or Panel compatibility',
                           'No host, routes, firewall or live profiles modified'],
            'actions_performed':'NONE'}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('profile',type=Path)
    parser.add_argument('--expected-domain')
    parser.add_argument('--strict',action='store_true')
    args=parser.parse_args(argv)
    try:
        report=audit(secret_free_json(args.profile),args.expected_domain)
    except (OSError,ValueError,UnicodeError,TypeError):
        report={'status':'FAIL','modes':[],'issues':['PROFILE_FILE_UNREADABLE_OR_INVALID'],
                'observations':[], 'actions_performed':'NONE'}
    print(json.dumps(report,sort_keys=True,ensure_ascii=False,indent=2))
    if report['status']=='FAIL':return 1
    if args.strict and report['status']!='STATIC_PASS':return 2
    return 0


if __name__=='__main__':sys.exit(main())
