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
    if m.get('version') != '2.5.18' or m.get('release_status') != 'INCOMPLETE_STAGING_ONLY':
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
    if not re.search(r'(?m)^INSTALLER_VERSION=2\.5\.18$', installer):
        raise ValueError('version of installer differs from manifest')
    readme = files['README.md'].decode('utf-8')
    if '2.5.18' not in readme or 'текущая staging-сборка' not in readme:
        raise ValueError('README release state/version inconsistent')
    if m['build_id'].startswith('20261021-r14-'):
        expected = {'docs/RELEASE_2.5.13_R14_HYBRID_SELFSTEAL_20261021.md',
                    'tests/test_2513_r14_hybrid_selfsteal.py'}
        if not expected.issubset(files):
            raise ValueError('missing r14 hybrid runbook or offline tests')
    if m['build_id'].startswith('20261021-r15-'):
        expected = {'docs/RELEASE_2.5.14_R15_GITHUB_INSTALL_20261021.md',
                    'tests/test_2514_r15_release_and_readme.py'}
        if not expected.issubset(files):
            raise ValueError('missing r15 release notes or install regression')
    if m['build_id'].startswith('20261021-r16-'):
        expected = {'docs/RELEASE_2.5.15_R16_STABILITY_20261021.md',
                    'tests/test_2515_r16_stability.py'}
        if not expected.issubset(files):
            raise ValueError('missing r16 release notes or diagnostics regression')
    if m['build_id'].startswith('20261021-r17-'):
        expected = {'docs/RELEASE_2.5.16_R17_CI_NETWORK_20261021.md',
                    'tests/test_2516_r17_github_and_network_audit.py',
                    'integrations/node_diagnostics.py'}
        if not expected.issubset(files):
            raise ValueError('missing r17 files or diagnostics')
    if m['build_id'].startswith('20261021-r18-'):
        expected = {'docs/RELEASE_2.5.17_R18_RELIABILITY_20261021.md',
                    'tests/test_2517_r18_reliability.py',
                    'integrations/connection_quality.py'}
        if not expected.issubset(files):
            raise ValueError('missing r18 reliability files')
    if m['build_id'].startswith('20261021-r19-'):
        expected = {'docs/RELEASE_2.5.18_R19_HYBRID_HOTFIX_20261021.md',
                    'tests/test_2518_r19_hybrid_permissions.py'}
        if not expected.issubset(files):
            raise ValueError('missing r19 hybrid hotfix files')
    if m['build_id'].startswith('20261105-r20-'):
        expected = {'docs/RELEASE_2.5.18_R20_RICH_SITES_NETWORK.md',
                    'integrations/network_health.py',
                    'scripts/cover_rich.py',
                    'scripts/site_audit.py',
                    'tests/test_r20_network_health.py',
                    'tests/test_r20_rich_site.py'}
        if not expected.issubset(files):
            raise ValueError('missing r20 rich site/network source or offline tests')
        if '--diagnose-network' not in installer or '--rich-pages' not in files['scripts/staging_web_deploy.py'].decode():
            raise ValueError('missing r20 CLI hooks')
    if m['build_id'].startswith('20261105-r21-'):
        important = {
            'docs/RELEASE_2.5.18_R21_CATALOG_AND_SAFETY.md',
            'scripts/site_catalog.py', 'scripts/build_site_gallery.py',
            'integrations/selfsteal_health.py',
            'tests/test_r21_site_catalog.py', 'tests/test_r21_site_change.py',
            'tests/test_r21_host_diagnostics.py', 'tests/test_r21_gallery_release.py',
            'preview/site-gallery/index.html',
            'integrations/network_health.py', 'scripts/site_audit.py',
            'scripts/staging_web_deploy.py',
        }
        if not important <= files.keys():
            raise ValueError('R21_REQUIRED_SOURCE_MISSING: ' + repr(sorted(important-files.keys())))
        files_per_site = {'index.html', 'journal.html', 'about.html', 'questions.html',
                          '404.html', 'style.css', 'favicon.svg', 'robots.txt', 'sitemap.xml'}
        catalog = {}
        for name in files:
            if name.startswith('site-catalog/'):
                match = re.fullmatch(r'site-catalog/([0-9]{2,3}-[a-z0-9-]+)/([^/]+)',name)
                if not match:
                    raise ValueError('R21_INVALID_CATALOG_PATH: '+name)
                catalog.setdefault(match[1],set()).add(match[2])
        if len(catalog)!=96 or any(fs != files_per_site for fs in catalog.values()):
            raise ValueError('R21_CATALOG_INCOMPLETE: expected 96 sites x 9 files')
        if len(files['preview/site-gallery/index.html']) < 20_000:
            raise ValueError('R21_GALLERY_MISSING_OR_INCOMPLETE')
        if '--diagnose-selfsteal' not in installer or '--diagnose-network' not in installer:
            raise ValueError('R21_MISSING_READONLY_DIAGNOSTICS')
        deployed=files['scripts/staging_web_deploy.py'].decode('utf-8')
        if 'site-change' not in deployed or 'site-preview' not in deployed or 'site-catalog' not in deployed:
            raise ValueError('R21_MISSING_THEME_MANAGEMENT')
        if '108' not in readme.split('---',1)[0]:
            raise ValueError('R21_README_SITE_COUNT_MISSING')
    if m['build_id'].startswith('20261105-r22-'):
        required = {
            'docs/RELEASE_2.5.18_R22_SIGNATURE_SITES_TRANSPORT_NETWORK.md',
            'scripts/signature_sites.py', 'integrations/transport_profile_audit.py',
            'scripts/network_compare.py', 'tests/test_r22_signature_sites.py',
            'tests/test_r22_transport_profile_audit.py', 'tests/test_r22_network_compare.py',
            'scripts/site_catalog.py', 'scripts/site_audit.py', 'scripts/staging_web_deploy.py',
            'preview/site-gallery/index.html'
        }
        if not required <= files.keys():
            raise ValueError('R22_REQUIRED_SOURCE_MISSING: '+repr(sorted(required-files.keys())))
        expected_per_site = {'index.html', 'journal.html', 'about.html', 'questions.html',
                             '404.html', 'style.css', 'favicon.svg', 'robots.txt', 'sitemap.xml'}
        catalog = {}
        for path in files:
            if path.startswith('site-catalog/'):
                match = re.fullmatch(r'site-catalog/([0-9]{2,3}-[a-z0-9-]+)/([^/]+)',path)
                if not match:
                    raise ValueError('R22_BAD_CATALOG_PATH')
                catalog.setdefault(match[1],set()).add(match[2])
        if len(catalog)!=108 or any(entries!=expected_per_site for entries in catalog.values()):
            raise ValueError('R22_CATALOG_INCOMPLETE: expected 108 x 9')
        bespoke = {p for p in catalog if int(p.split('-',1)[0]) in range(109,121)}
        if len(bespoke)!=12:
            raise ValueError('R22_BESPOKE_CATALOG_INCOMPLETE')
        gallery = files['preview/site-gallery/index.html']
        if gallery.count(b'../../site-catalog/') < 108:
            raise ValueError('R22_GALLERY_MISSING_NEW_SITES')
        if '120' not in readme.split('---',1)[0] or 'r22' not in readme.split('---',1)[0]:
            raise ValueError('R22_README_BUILD_ID_OR_COUNT_INCONSISTENT')
        transport = files['integrations/transport_profile_audit.py']
        if b'SELFSTEAL_UNIX_PROXY_PROTOCOL_VERSION_MISMATCH' not in transport or b'CASCADE_ENTRY_FAIL_CLOSED' not in transport:
            raise ValueError('R22_TRANSPORT_AUDITOR_MISSING_GATES')
    if m['build_id'].startswith('20261105-r24-'):
        required = {
            'scripts/site_manager.py', 'integrations/selfsteal_chain.py',
            'integrations/path_mtu_diagnostics.py',
            'tests/test_r24_phase1_site_selfsteal_mtu.py',
            'docs/RELEASE_2.5.18_R24_PHASE1_SITES_SELFSTEAL_NETWORK.md',
            'scripts/staging_web_deploy.py', 'integrations/transport_profile_audit.py',
            'preview/site-gallery/index.html',
        }
        if not required <= files.keys():
            raise ValueError('R24_MISSING_PHASE1_SOURCES')
        for flag in ('--site-manager', '--site-theme', '--selfsteal-verify',
                     '--path-mtu', '--transport-audit'):
            if flag not in installer:
                raise ValueError('R24_MISSING_PHASE1_CLI_' + flag)
        manager = files['scripts/site_manager.py'].decode('utf-8')
        if 'installer_lock' not in manager or '--confirm-staging' not in manager:
            raise ValueError('R24_SITE_MANAGER_TRANSACTION_GATES_MISSING')
        if 'r24' not in readme.split('---',1)[0] or '120' not in readme.split('---',1)[0]:
            raise ValueError('R24_README_STATUS_OR_CATALOG_MISSING')
        # The user explicitly requires password login on nodes; no new key login.
        if 'PubkeyAuthentication no' not in installer or 'PasswordAuthentication yes' not in installer:
            raise ValueError('R24_PASSWORD_SSH_COMPATIBILITY_BROKEN')
    if m['build_id'].startswith('20261105-r29-'):
        expected={'scripts/terminal_ui.py','integrations/vps_connectivity.py',
                  'tests/test_r29_tui_full_vps.py',
                  'docs/RELEASE_2.5.18_R29_TERMINAL_RETRY_FULL_VPS.md'}
        if not expected <= files.keys():
            raise ValueError('R29_TERMINAL_OR_VPS_FILES_MISSING')
        if 'r29' not in readme.split('---', 1)[0] or 'full' not in files['integrations/vps_connectivity.py'].decode():
            raise ValueError('R29_MENU_OR_FULL_CHECK_MISSING')
    if m['build_id'].startswith('20261105-r28-'):
        needed = {'docs/RELEASE_2.5.18_R28_CI_PORTABILITY.md',
                  'tests/test_r28_ci_portability.py',
                  'tests/test_r23_transport_network_visual.py',
                  'tests/test_r26_runtime_gate.py'}
        if not needed <= files.keys():
            raise ValueError('R28_CI_PORTABILITY_SOURCES_MISSING')
        if 'r28' not in readme.split('---', 1)[0]:
            raise ValueError('R28_README_RELEASE_MISSING')
    expected_archive = 'Node_Install_2.5.18-docs-menu_' + m['build_id'] + '.zip'
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
