#!/usr/bin/env python3
"""Verify all files of a VKarmani source ZIP staging candidate, offline.

The in-archive manifest is not a digital signature: use a trusted release hash
from an independent channel and still perform functional staging acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import unicodedata
import zipfile

MANIFEST = 'BUILD_MANIFEST.json'
SUMS = 'SHA256SUMS'
SKIPPED = {MANIFEST, SUMS}
REQUIRED = {'install.sh', 'README.md', 'CHANGELOG.md', '.gitattributes',
            '.gitignore', '.github/workflows/check.yml',
            'integrations/docker_local.sh', 'integrations/nightly_maintenance.py',
            'integrations/rkn_guard.py', 'tests/test_r2_critical.py',
            'scripts/verify_release.py', 'docs/STAGING_CANDIDATE_2.5.7.md',
            'docs/EDGE_HARDENING_2.5.8.md', 'tests/test_edge_security_258.py',
            'tests/test_259_fault_regressions.py', 'docs/RKN_FAILSAFE_2.5.9.md', 'docs/CASCADE_REFERENCE_2.5.10.md',
            'examples/cascade-entry-profile.reference.json', 'examples/cascade-exit-profile.reference.json',
            'tests/test_2510_menu_cascade_docs.py',
            'docs/R4_8_POINT_ENGINEERING_20261015.md',
            'docs/COVER_VARIANTS_AND_PROXY_R4.md',
            'integrations/cascade_profiles.py',
            'integrations/panel_acl_audit.py',
            'scripts/staging_acceptance.py',
            'scripts/cover_variants.py',
            'scripts/nginx_proxy_plan.py',
            'tests/test_2510_r4_preparation.py',
            'cover-variants/01-atelier/index.html',
            'cover-variants/01-atelier/style.css',
            'cover-variants/02-archive/index.html',
            'cover-variants/02-archive/style.css',
            'cover-variants/03-observatory/index.html',
            'cover-variants/03-observatory/style.css',
            'cover-variants/04-fieldnotes/index.html',
            'cover-variants/04-fieldnotes/style.css',
            'cover-variants/05-readingroom/index.html',
            'cover-variants/05-readingroom/style.css',
            'cover-variants/06-foundry/index.html',
            'cover-variants/06-foundry/style.css',
            'integrations/cascade_deployment.py',
            'integrations/cascade_panel_audit.py',
            'tests/test_2510_r5_cascade_roles.py',
            'tests/test_2510_r5_cascade_panel.py',
            'docs/CASCADE_R5_ROLE_INSTALL_AND_PANEL.md',
            'docs/R5_CASCADE_QA.md',
            'docs/R6_CASCADE_OPERATIONS_AND_GATES.md',
            'integrations/cascade_live_gate.py',
            'integrations/cascade_panel_inventory.py',
            'integrations/cascade_recovery.py',
            'tests/test_2510_r6_remaining_gates.py',
            'scripts/staging_web_deploy.py', 'scripts/cascade_live_probe.py',
            'tests/test_2510_r7_web_deploy.py', 'tests/test_2510_r7_live_probe.py',
            'docs/R7_SITES_TCP_AND_LIVE_PROBES.md',
            'docs/R8_INTEGRATION_REVIEW_20261018.md', 'tests/test_2510_r9_reviewed_fixes.py',
            'docs/RELEASE_2.5.11_R10_REVIEW.md', 'tests/test_2511_r10_lowmem_and_site.py',
    'docs/RELEASE_2.5.12_R11_REVIEW.md', 'tests/test_2512_r11_ready_profiles_and_cover.py',
    'docs/RELEASE_2.5.13_R12_SITES.md', 'tests/test_2513_r12_twelve_sites.py',}


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def verify_name(value):
    # Zero tolerance for traversal, Unicode normalization aliases, and malformed
    # filenames: packaging the checked-in tree should never require these.
    if not value or '\\' in value or '\x00' in value:
        raise ValueError('unsafe path ' + repr(value))
    p = PurePosixPath(value)
    if value != unicodedata.normalize('NFC', value):
        raise ValueError('noncanonical Unicode path ' + repr(value))
    if p.is_absolute() or str(p) != value or any(x in ('', '.', '..') for x in value.split('/')):
        raise ValueError('unsafe path ' + repr(value))
    if any(x.startswith('.git/') for x in (value,)) or value.startswith('.git/') or value == '.git':
        raise ValueError('git directory must not be distributed')
    return value


def verify_manifest(m):
    if m.get('version') != '2.5.13' or m.get('release_status') != 'INCOMPLETE_STAGING_ONLY':
        raise ValueError('wrong release version or safety status')
    commit = m.get('source_commit')
    if not isinstance(commit, str) or not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('invalid source commit')
    if not isinstance(m.get('build_id'), str) or not re.fullmatch('[A-Za-z0-9_.-]{8,96}', m['build_id']):
        raise ValueError('invalid build ID')
    if m.get('excluded_from_manifest') != sorted(SKIPPED):
        raise ValueError('self-exclusion policy drift')
    items = m.get('files')
    if not isinstance(items, list) or not items:
        raise ValueError('empty or invalid files list')
    checks = {}
    for item in items:
        if not isinstance(item, dict) or set(item) != {'path', 'size', 'sha256', 'mode'}:
            raise ValueError('bad manifest row')
        name = verify_name(item['path'])
        if name in checks or name in SKIPPED:
            raise ValueError('duplicate or excluded manifest path: ' + name)
        size, digest, mode = item['size'], item['sha256'], item['mode']
        if type(size) is not int or size < 0 or not re.fullmatch('[0-9a-f]{64}', digest):
            raise ValueError('bad size or hash: ' + name)
        if mode not in ('0644', '0755'):
            raise ValueError('unexpected mode: ' + name)
        checks[name] = item
    if not REQUIRED <= set(checks):
        raise ValueError('missing required source files ' + repr(REQUIRED - set(checks)))
    return checks


def parse_sums(data):
    checks = {}
    for line in data.decode('utf-8').splitlines():
        part = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not part:
            raise ValueError('invalid SHA256SUMS format')
        digest, name = part.groups()
        verify_name(name)
        if name in checks or name == SUMS:
            raise ValueError('duplicate or self-referential SHA256SUMS')
        checks[name] = digest
    return checks


def verify_bytes(files):
    m = json.loads(files[MANIFEST].decode('utf-8'))
    checks = verify_manifest(m)
    expected = set(checks) | SKIPPED
    if set(files) != expected:
        raise ValueError('missing/unexpected supplied files: ' + repr(sorted(set(files) ^ expected)))
    for name, meta in checks.items():
        if len(files[name]) != meta['size'] or sha256(files[name]) != meta['sha256']:
            raise ValueError('file checksum/size mismatch: ' + name)
    s = parse_sums(files[SUMS])
    if set(s) != (set(files) - {SUMS}):
        raise ValueError('SHA256SUMS does not cover every file')
    for name, digest in s.items():
        if sha256(files[name]) != digest:
            raise ValueError('SHA256SUMS failed: ' + name)
    installer = files['install.sh'].decode('utf-8')
    if not re.search(r'(?m)^INSTALLER_VERSION=2\.5\.13$', installer):
        raise ValueError('version of installer differs from manifest')
    readme = files['README.md'].decode('utf-8')
    if '2.5.13' not in readme or 'текущая staging-сборка' not in readme:
        raise ValueError('README release state/version inconsistent')
    expected_archive = 'Node_Install_2.5.13-docs-menu_' + m['build_id'] + '.zip'
    if expected_archive not in readme.split('---', 1)[0]:
        raise ValueError('README release command/build ID inconsistent')
    for word in ('vk_rkn_safe_shutdown()', 'vk_write_docker_local()', 'vk_write_nightly_maintenance()'):
        if word not in installer:
            raise ValueError('required executable change missing: ' + word)
    return m, checks


def read_disk(root):
    all_files = {}
    for entry in root.rglob('*'):
        rel = entry.relative_to(root)
        if '.git' in rel.parts or '__pycache__' in rel.parts or '.pytest_cache' in rel.parts:
            continue
        if entry.is_symlink():
            raise ValueError('symlink found: ' + str(entry))
        if entry.is_file():
            name = verify_name(rel.as_posix())
            all_files[name] = entry.read_bytes()
        elif not entry.is_dir():
            raise ValueError('special file found: ' + str(entry))
    return all_files


def inspect_zip(path):
    with zipfile.ZipFile(path) as arc:
        if arc.testzip() is not None:
            raise ValueError('bad ZIP CRC')
        collected, names = {}, set()
        for ent in arc.infolist():
            if ent.is_dir():
                verify_name(ent.filename.rstrip('/'))
                continue
            if not ent.filename.startswith('Node_Install/'):
                raise ValueError('archive entry outside Node_Install/')
            name = verify_name(ent.filename.removeprefix('Node_Install/'))
            if name in names or name.casefold() in {x.casefold() for x in names}:
                raise ValueError('duplicate zip name: ' + name)
            mode = (ent.external_attr >> 16) & 0o170000
            if mode and mode != stat.S_IFREG:
                raise ValueError('symlink/special ZIP member: ' + name)
            collected[name] = arc.read(ent)
            names.add(name)
        m, items = verify_bytes(collected)
        for name, meta in items.items():
            ent = arc.getinfo('Node_Install/' + name)
            actual = (ent.external_attr >> 16) & 0o777
            if actual != int(meta['mode'], 8):
                raise ValueError('ZIP permission drift: ' + name)
    return m, collected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--zip', type=Path)
    ns = parser.parse_args()
    if ns.zip:
        manifest, contents = inspect_zip(ns.zip)
    else:
        contents = read_disk(ns.root)
        manifest, _ = verify_bytes(contents)
    print('RELEASE_VERIFY=PASS VERSION=' + manifest['version'] +
          ' BUILD_ID=' + manifest['build_id'] + ' FILES=' + str(len(contents)))
    if ns.zip:
        print('ARCHIVE_SHA256=' + sha256(ns.zip.read_bytes()))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
        print('RELEASE_VERIFY=FAIL: ' + str(exc), file=sys.stderr)
        sys.exit(1)
