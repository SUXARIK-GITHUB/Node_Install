#!/usr/bin/env python3
"""Read-only RemnaNode bundled Core vs upstream Xray release metadata.

No downloads of executables, no writes, no Docker mutations and no secrets.
The display is advisory: RemnaNode can lag upstream for compatibility reasons.
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
from urllib import request
from urllib.error import URLError, HTTPError
from urllib.parse import urlsplit

FEED = 'https://api.github.com/repos/XTLS/Xray-core/releases?per_page=5'
STABLE = 'https://api.github.com/repos/XTLS/Xray-core/releases/latest'
LIMIT = 2 * 1024 * 1024
VERSION = re.compile(r'^v?((?:0|[1-9][0-9]{0,2}))\.((?:0|[1-9][0-9]?))\.((?:0|[1-9][0-9]?))$')
CORE_LINE = re.compile(r'^Xray\s+v?([0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)', re.I)


class UpstreamError(Exception):
    pass


def parse_version(tag):
    if not isinstance(tag, str):
        return None
    match = VERSION.fullmatch(tag)
    return tuple(map(int, match.groups())) if match else None


def readable_version(value):
    return '.'.join(map(str, value)) if value else 'NOT_VERIFIED'


def release_info(item):
    if not isinstance(item, dict) or item.get('draft') is not False:
        return None
    ver = parse_version(item.get('tag_name'))
    if not ver or type(item.get('prerelease')) is not bool:
        return None
    return ver, item['prerelease']


def load_metadata(url, opener=None):
    if url not in (FEED, STABLE):
        raise UpstreamError('UNREVIEWED_SOURCE')
    if opener is None:
        opener = request.urlopen
    req = request.Request(url, headers={
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'vkarmani-node-install-read-only-release-check/2.5.5',
        'X-GitHub-Api-Version': '2022-11-28',
    })
    try:
        with opener(req, timeout=9) as response:
            final = urlsplit(response.geturl())
            if final.scheme != 'https' or final.hostname != 'api.github.com':
                raise UpstreamError('REDIRECT_HOST_NOT_ALLOWED')
            content = response.read(LIMIT + 1)
            if len(content) > LIMIT:
                raise UpstreamError('RELEASE_RESPONSE_TOO_LARGE')
    except (URLError, HTTPError, TimeoutError, OSError) as exc:
        raise UpstreamError('RELEASE_SOURCE_UNAVAILABLE') from exc
    try:
        return json.loads(content)
    except (ValueError, UnicodeError) as exc:
        raise UpstreamError('RELEASE_METADATA_INVALID') from exc


def get_upstream(load=load_metadata):
    items = load(FEED)
    latest = load(STABLE)
    if not isinstance(items, list) or len(items) > 10:
        raise UpstreamError('RELEASE_LIST_INVALID')
    versions = [x for i in items if (x := release_info(i))]
    stable = release_info(latest)
    if not versions or stable is None or stable[1]:
        raise UpstreamError('RELEASE_VERSIONS_UNVERIFIED')
    return max(versions, key=lambda x:x[0]), stable[0]


def installed_version(runner=None):
    if not shutil.which('docker'):
        return None
    if runner is None:
        runner = subprocess.run
    try:
        result = runner(['docker', 'exec', 'remnanode', 'rw-core', 'version'],
                        text=True, capture_output=True, timeout=8, check=False)
        if result.returncode != 0:
            return None
        first_line = result.stdout.splitlines()[0] if result.stdout else ''
        match = CORE_LINE.match(first_line)
        return parse_version(match.group(1)) if match else None
    except (OSError, subprocess.SubprocessError, IndexError):
        return None


def main(argv=None):
    p = argparse.ArgumentParser(description='Read-only version comparison; no Xray update')
    p.add_argument('--offline', action='store_true', help='Check installed version only')
    args = p.parse_args(argv)
    installed = installed_version()
    print('XRAY_INSTALLED=' + readable_version(installed))
    if args.offline:
        print('XRAY_UPSTREAM=NOT_QUERIED_OFFLINE')
    else:
        try:
            latest, stable = get_upstream()
            print('XRAY_UPSTREAM_NEWEST=' + readable_version(latest[0]))
            print('XRAY_UPSTREAM_NEWEST_CHANNEL=' + ('PRERELEASE' if latest[1] else 'STABLE'))
            print('XRAY_UPSTREAM_STABLE=' + readable_version(stable))
            if installed:
                print('XRAY_UPSTREAM_NEWER=' + ('YES' if latest[0] > installed else 'NO'))
        except UpstreamError as exc:
            print('XRAY_UPSTREAM=NOT_VERIFIED_' + str(exc))
            print('XRAY_UPDATE_ACTION=NONE')
            return 1
    print('XRAY_UPDATE_ACTION=NONE')
    print('XRAY_UPDATE_POLICY=PIN_IMAGE_OR_REVIEW_PANEL_GEODATA_CORE_SHA256')
    print('XRAY_NODE_AND_PANEL=UNCHANGED')
    return 0


if __name__ == '__main__':
    sys.exit(main())
