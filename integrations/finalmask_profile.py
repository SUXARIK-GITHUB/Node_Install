#!/usr/bin/env python3
"""Opt-in FinalMask TCP fragment selection for a PRIVATE Xray client outbound.

This is an offline CONFIG EXPORT, not a RemnaNode/Panel mutation. The operator
can enable, disable or interactively choose conservative numeric ranges. No
automatic client rollout, Core download, runtime restart or firewall change.
Do not enable on the server inbound to "fragment client ClientHello": that
packet is emitted by the client, not by a RemnaNode inbound.

Upstream specification: https://xtls.github.io/en/config/transports/finalmask.html
"""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LENGTHS = '80-160'
DEFAULT_DELAYS = '0-5'
DEFAULT_SPLIT = '2-4'
MAX_INPUT_BYTES = 1024 * 1024
RANGE = re.compile(r'([0-9]{1,4})(?:-([0-9]{1,4}))?\Z')
TAG = re.compile(r'[A-Za-z0-9_.:-]{1,96}\Z')


class Invalid(Exception):
    pass


def parse_ranges(text, *, name, minimum, maximum, limit=8):
    """Whitelist comma-separated Int32Range fragments; never execute input."""
    if not isinstance(text, str):
        raise Invalid('RANGE_' + name.upper() + '_INVALID')
    parts = text.split(',')
    if not 1 <= len(parts) <= limit:
        raise Invalid('RANGE_' + name.upper() + '_COUNT_INVALID')
    for part in parts:
        match = RANGE.fullmatch(part)
        if match is None:
            raise Invalid('RANGE_' + name.upper() + '_SYNTAX_INVALID')
        low = int(match.group(1))
        high = int(match.group(2) or match.group(1))
        if not minimum <= low <= high <= maximum:
            raise Invalid('RANGE_' + name.upper() + '_LIMIT_INVALID')
    return parts


def tcp_fragment(lengths=DEFAULT_LENGTHS, delays=DEFAULT_DELAYS,
                 max_split=DEFAULT_SPLIT, packets='tlshello'):
    # Conservative range limits are a staging guardrail, not a speed/stealth claim.
    if packets != 'tlshello':
        raise Invalid('ONLY_TLSHELLO_SUPPORTED')
    return {
        'type': 'fragment',
        'settings': {
            'packets': 'tlshello',
            'lengths': parse_ranges(lengths, name='lengths', minimum=1, maximum=1400),
            'delays': parse_ranges(delays, name='delays', minimum=0, maximum=200),
            'maxSplit': parse_ranges(max_split, name='max_split', minimum=1, maximum=16, limit=1)[0],
        },
    }


def _select_outbound(config, tag):
    if not isinstance(config, dict) or not isinstance(config.get('outbounds'), list):
        raise Invalid('XRAY_OUTBOUNDS_REQUIRED')
    if not isinstance(tag, str) or TAG.fullmatch(tag) is None:
        raise Invalid('OUTBOUND_TAG_INVALID')
    found = [item for item in config['outbounds'] if isinstance(item, dict) and item.get('tag') == tag]
    if len(found) != 1:
        raise Invalid('OUTBOUND_TAG_NOT_UNIQUE')
    target = found[0]
    if target.get('protocol') != 'vless':
        raise Invalid('ONLY_VLESS_CLIENT_OUTBOUND_SUPPORTED')
    stream = target.get('streamSettings')
    if not isinstance(stream, dict):
        raise Invalid('STREAM_SETTINGS_REQUIRED')
    if stream.get('network', stream.get('method')) not in ('raw', 'tcp', 'xhttp'):
        raise Invalid('ONLY_TCP_RAW_OR_XHTTP_SUPPORTED')
    if stream.get('security') not in ('reality', 'tls'):
        raise Invalid('ENCRYPTED_TCP_SECURITY_REQUIRED')
    return stream


def _check_managed_mask(finalmask):
    if finalmask is None:
        return
    if not isinstance(finalmask, dict) or set(finalmask) != {'tcp'} or not isinstance(finalmask['tcp'], list):
        raise Invalid('UNMANAGED_FINALMASK_PRESENT')
    if len(finalmask['tcp']) != 1 or not isinstance(finalmask['tcp'][0], dict):
        raise Invalid('UNMANAGED_FINALMASK_PRESENT')
    entry = finalmask['tcp'][0]
    if entry.get('type') != 'fragment' or not isinstance(entry.get('settings'), dict):
        raise Invalid('UNMANAGED_FINALMASK_PRESENT')
    if set(entry) != {'type', 'settings'} or set(entry['settings']) != {'packets', 'lengths', 'delays', 'maxSplit'}:
        raise Invalid('UNMANAGED_FINALMASK_PRESENT')
    params = entry['settings']
    if params['packets'] != 'tlshello' or not isinstance(params['lengths'], list) or not isinstance(params['delays'], list):
        raise Invalid('UNMANAGED_FINALMASK_PRESENT')
    try:
        tcp_fragment(','.join(params['lengths']), ','.join(params['delays']), str(params['maxSplit']))
    except (Invalid, TypeError) as exc:
        raise Invalid('UNMANAGED_FINALMASK_PRESENT') from exc


def transform(config, *, tag, enabled, lengths=DEFAULT_LENGTHS,
              delays=DEFAULT_DELAYS, max_split=DEFAULT_SPLIT):
    output = copy.deepcopy(config)
    stream = _select_outbound(output, tag)
    _check_managed_mask(stream.get('finalmask'))
    if enabled:
        stream['finalmask'] = {'tcp': [tcp_fragment(lengths, delays, max_split)]}
    else:
        stream.pop('finalmask', None)
    return output


def _read_private_json(path):
    path = Path(path).absolute()
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise Invalid('INPUT_SYMLINK_FORBIDDEN')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise Invalid('INPUT_NOT_READABLE') from exc
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                info.st_size > MAX_INPUT_BYTES or stat.S_IMODE(info.st_mode) & 0o077 or
                info.st_uid != os.geteuid()):
            raise Invalid('INPUT_MUST_BE_PRIVATE_REGULAR_FILE_0600')
        chunks, remaining = [], MAX_INPUT_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b''.join(chunks)
    finally:
        os.close(fd)
    if len(raw) > MAX_INPUT_BYTES:
        raise Invalid('INPUT_TOO_LARGE')
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise Invalid('DUPLICATE_JSON_FIELD')
            obj[key] = value
        return obj
    try:
        config = json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                            parse_constant=lambda _: (_ for _ in ()).throw(Invalid('NONFINITE_JSON_NUMBER')))
    except (UnicodeError, ValueError) as exc:
        raise Invalid('INVALID_INPUT_JSON') from exc
    return config


def _write_new_private(path, content):
    path = Path(path).absolute()
    parent = path.parent
    if ROOT == path or ROOT in path.parents:
        raise Invalid('PRIVATE_OUTPUT_INSIDE_REPOSITORY_FORBIDDEN')
    if (not parent.is_dir() or any(p.is_symlink() for p in (path, parent, *parent.parents)) or
            stat.S_IMODE(parent.stat().st_mode) & 0o077 or parent.stat().st_uid != os.geteuid()):
        raise Invalid('PRIVATE_OUTPUT_DIRECTORY_REQUIRED_0700')
    fd = None
    created = False
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        created = True
        with os.fdopen(fd, 'wb') as f:
            fd = None
            os.fchmod(f.fileno(), 0o600)
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        pfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(pfd)
        finally:
            os.close(pfd)
    except BaseException:
        if fd is not None:
            os.close(fd)
        # Never remove an existing output file; O_EXCL guarantees it was ours.
        if created and path.exists():
            path.unlink()
        raise


def _menu(args):
    if not sys.stdin.isatty():
        raise Invalid('MENU_REQUIRES_TERMINAL')
    print('FinalMask TCP fragment — экспорт клиентского Xray outbound, НЕ изменение ноды/панели.')
    print('1 — Включить; 2 — Выключить; 0 — Отмена')
    answer = input('Выбор: ').strip()
    if answer == '0':
        return None
    if answer not in ('1', '2'):
        raise Invalid('INVALID_MENU_CHOICE')
    if answer == '1':
        for field, default in (('lengths', DEFAULT_LENGTHS), ('delays', DEFAULT_DELAYS), ('max_split', DEFAULT_SPLIT)):
            description = {'lengths':'Размер фрагментов, байт','delays':'Задержка, мс','max_split':'Максимум разбиений'}[field]
            value = input(f'{description} [{default}]: ').strip()
            setattr(args, field, value or default)
    return answer == '1'


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=['enable', 'disable', 'menu', 'status', 'snippet', 'defaults'])
    p.add_argument('--input', type=Path, help='PRIVATE 0600 client Xray JSON; required except defaults')
    p.add_argument('--output', type=Path, help='NEW private output file in owned 0700 directory')
    p.add_argument('--outbound-tag', help='exact unique outbound tag of VLESS client')
    p.add_argument('--lengths', default=DEFAULT_LENGTHS, help='e.g. 80-160,160-240 bytes')
    p.add_argument('--delays', default=DEFAULT_DELAYS, help='e.g. 0-5 milliseconds')
    p.add_argument('--max-split', default=DEFAULT_SPLIT, help='e.g. 2-4, bounded to 1..16')
    args = p.parse_args(argv)
    if args.mode == 'defaults':
        print(f'FINALMASK=OFF_BY_DEFAULT lengths={DEFAULT_LENGTHS} delays={DEFAULT_DELAYS} maxSplit={DEFAULT_SPLIT}')
        print('EXPERIMENTAL_CLIENT_OUTBOUND_ONLY; no proven DPI benefit; no node changes')
        return 0
    try:
        if args.mode == 'snippet':
            if not args.output or args.input:
                raise Invalid('SNIPPET_REQUIRES_ONLY_OUTPUT')
            fragment = tcp_fragment(args.lengths, args.delays, args.max_split)
            _write_new_private(args.output, (json.dumps({'finalmask':{'tcp':[fragment]}}, indent=2)+'\n').encode())
            print('FINALMASK=FRAGMENT_SNIPPET_ONLY CLIENT_CONFIG=NOT_MODIFIED NODE=UNCHANGED')
            return 0
        if args.mode == 'status':
            if not args.input or not args.outbound_tag:
                raise Invalid('INPUT_AND_OUTBOUND_TAG_REQUIRED')
            stream = _select_outbound(_read_private_json(args.input), args.outbound_tag)
            _check_managed_mask(stream.get('finalmask'))
            if 'finalmask' not in stream:
                print('FINALMASK=DISABLED NODE=UNCHANGED')
            else:
                params = stream['finalmask']['tcp'][0]['settings']
                print('FINALMASK=ENABLED lengths='+','.join(params['lengths'])+
                      ' delays='+','.join(params['delays'])+' maxSplit='+str(params['maxSplit'])+
                      ' NODE=UNCHANGED')
            return 0
        if not args.input or not args.output or not args.outbound_tag:
            raise Invalid('INPUT_OUTPUT_AND_OUTBOUND_TAG_REQUIRED')
        enabled = _menu(args) if args.mode == 'menu' else args.mode == 'enable'
        if enabled is None:
            print('FINALMASK=UNCHANGED')
            return 0
        config = _read_private_json(args.input)
        output = transform(config, tag=args.outbound_tag, enabled=enabled,
                           lengths=args.lengths, delays=args.delays, max_split=args.max_split)
        content = (json.dumps(output, ensure_ascii=False, indent=2, allow_nan=False)+'\n').encode('utf-8')
        _write_new_private(args.output, content)
    except (Invalid, OSError, ValueError, TypeError) as exc:
        reason = str(exc) if isinstance(exc, Invalid) else type(exc).__name__
        print('FINALMASK=STOP '+reason, file=sys.stderr)
        return 2
    print('FINALMASK='+('ENABLED' if enabled else 'DISABLED')+' EXPORT=CREATED'
          ' NODE=UNCHANGED PANEL=UNCHANGED CLIENT=NOT_ACTIVATED XRAY_RUNTIME=NOT_VERIFIED')
    return 0


if __name__ == '__main__':
    sys.exit(main())
