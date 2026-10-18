#!/usr/bin/env python3
"""Build a deterministic, safety-labelled complete source ZIP from THIS tree.

Intentionally excludes .git, local credentials, caches and unknown non-baseline files.
Never publishes or runs the installer. An output directory must be outside repo.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile

from verify_release import MANIFEST, SUMS, inspect_zip, sha256, verify_name, verify_bytes, read_disk

ROOT = Path(__file__).resolve().parents[1]
UNTRACKED_ALLOWED = {
    'docs/STAGING_CANDIDATE_2.5.7.md',
    'docs/TZ_R2_IMPLEMENTATION_MATRIX.md',
    'docs/history/RELEASE_VALIDATION_2.5.6.json',
    'integrations/docker_local.sh',
    'integrations/nightly_maintenance.py',
    'tests/test_r2_critical.py',
    'tests/test_release_packaging_r2.py',
    'scripts/build_staging_archive.py',
    'scripts/verify_release.py',
    'docs/EDGE_HARDENING_2.5.8.md',
    'tests/test_edge_security_258.py',
    'tests/test_259_fault_regressions.py',
    'docs/RKN_FAILSAFE_2.5.9.md',
    'docs/CASCADE_REFERENCE_2.5.10.md',
    'examples/cascade-entry-profile.reference.json',
    'examples/cascade-exit-profile.reference.json',
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
    'scripts/staging_web_deploy.py',
    'scripts/cascade_live_probe.py',
    'tests/test_2510_r7_web_deploy.py',
    'tests/test_2510_r7_live_probe.py',
    'docs/R7_SITES_TCP_AND_LIVE_PROBES.md',
    'docs/R8_INTEGRATION_REVIEW_20261018.md', 'tests/test_2510_r9_reviewed_fixes.py',
    'docs/RELEASE_2.5.11_R10_REVIEW.md', 'tests/test_2511_r10_lowmem_and_site.py',
}


def baseline_manifest():
    """The source ZIP has no .git; preserve its recorded, verified Git provenance.

    Fail on missing or additional files rather than trusting an invented HEAD or
    silently packaging local material that was not present in the input archive.
    """
    data = json.loads((ROOT / MANIFEST).read_text(encoding='utf-8'))
    commit = data.get('source_commit')
    if not isinstance(commit, str) or not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('missing source commit provenance')
    return data


def paths():
    baseline = baseline_manifest()
    declared = {item['path'] for item in baseline['files']}
    present = set(read_disk(ROOT)) - {MANIFEST, SUMS}
    missing = declared - present
    extra = present - declared
    if missing:
        raise ValueError('files lost from source package: ' + repr(sorted(missing)))
    if extra - UNTRACKED_ALLOWED:
        raise ValueError('unreviewed files found; refusing to package: ' + repr(sorted(extra - UNTRACKED_ALLOWED)))
    required = {'docs/EDGE_HARDENING_2.5.8.md', 'tests/test_edge_security_258.py', 'tests/test_259_fault_regressions.py', 'docs/RKN_FAILSAFE_2.5.9.md'}
    if not required <= present:
        raise ValueError('required new files missing: ' + repr(sorted(required - present)))
    for name in present:
        verify_name(name)
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('missing/non-regular/symlink source file: ' + name)
        if path.stat().st_nlink != 1:
            raise ValueError('hardlinked file: ' + name)
    return sorted(present)


def write_atomic(path, data):
    fd, name = tempfile.mkstemp(prefix='.vk-build-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(name, 0o644)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def build(out_dir, build_id):
    if not re.fullmatch(r'[A-Za-z0-9_.-]{8,96}', build_id):
        raise ValueError('bad build ID')
    if ROOT in out_dir.resolve().parents or ROOT == out_dir.resolve():
        raise ValueError('output directory must be outside source tree')
    source_commit = baseline_manifest()['source_commit']
    names = paths()
    entries = []
    for name in names:
        p = ROOT / name
        mode = stat.S_IMODE(p.stat().st_mode)
        if mode not in (0o644, 0o755):
            raise ValueError('unsupported source permissions: ' + name)
        data = p.read_bytes()
        entries.append({'path':name, 'size':len(data), 'sha256':sha256(data), 'mode':f'{mode:04o}'})
    manifest = {
        'version': '2.5.11',
        'build_id': build_id,
        'source_commit': source_commit,
        'release_status': 'INCOMPLETE_STAGING_ONLY',
        'source_tree_has_local_changes': True,  # base archive has no .git; current bytes differ from input
        'excluded_from_manifest': sorted([MANIFEST, SUMS]),
        'files': entries,
    }
    manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True)+'\n').encode()
    sums = {row['path']:row['sha256'] for row in entries}
    sums[MANIFEST] = sha256(manifest_bytes)
    sums_bytes = ''.join(f'{digest}  {name}\n' for name,digest in sorted(sums.items())).encode()
    write_atomic(ROOT / MANIFEST, manifest_bytes)
    write_atomic(ROOT / SUMS, sums_bytes)
    data = {x: (ROOT/x).read_bytes() for x in names}
    data[MANIFEST] = manifest_bytes
    data[SUMS] = sums_bytes
    verify_bytes(data)
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / f'Node_Install_2.5.11-docs-menu_{build_id}.zip'
    if dest.exists():
        raise FileExistsError('already built; use a new unique build ID')
    fd, tmp = tempfile.mkstemp(prefix='.node-install-staging-', suffix='.zip', dir=out_dir)
    os.close(fd)
    try:
        with zipfile.ZipFile(tmp, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=7, allowZip64=True) as arc:
            for name, content in sorted(data.items()):
                entry = zipfile.ZipInfo('Node_Install/' + name, (2026,10,15,0,0,0))
                entry.compress_type = zipfile.ZIP_DEFLATED
                entry.create_system = 3
                filemode = int(next((item['mode'] for item in entries if item['path'] == name),'0644'), 8)
                entry.external_attr = (stat.S_IFREG | filemode) << 16
                arc.writestr(entry, content, compress_type=zipfile.ZIP_DEFLATED, compresslevel=7)
        _, zipdata = inspect_zip(Path(tmp))
        if set(zipdata) != set(data) or any(zipdata[k] != data[k] for k in data):
            raise ValueError('archive bytes differ from actual worktree')
        os.replace(tmp, dest)
        os.chmod(dest, 0o644)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    # A clean extraction is the source of the *next* full test execution.
    digest = sha256(dest.read_bytes())
    sums_path = out_dir / (dest.name + '.sha256')
    sums_path.write_text(digest + '  ' + dest.name + '\n')
    print('ARCHIVE=' + str(dest))
    print('BYTES=' + str(dest.stat().st_size))
    print('SHA256=' + digest)
    print('FILES=' + str(len(data)))
    print('BUILD_ID=' + build_id)
    print('UNPUBLISHED=YES; CASCADE_ROLES_STAGING_CODE=YES; PANEL_AND_LIVE_UNVERIFIED=YES')
    return dest


def main():
    import datetime
    parser = argparse.ArgumentParser()
    parser.add_argument('--out-dir', type=Path, required=True)
    parser.add_argument('--build-id', default=datetime.datetime.now(datetime.timezone.utc).strftime('qa-20261015T%H%M%SZ'))
    ns = parser.parse_args()
    build(ns.out_dir, ns.build_id)


if __name__ == '__main__':
    main()
