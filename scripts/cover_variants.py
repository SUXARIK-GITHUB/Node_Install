#!/usr/bin/env python3
"""Prepare one of six standalone cover themes, offline only; never deploy to VPS."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SITES = ROOT / 'cover-variants'
NAMES = ('01-atelier','02-archive','03-observatory',
         '04-fieldnotes','05-readingroom','06-foundry')


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--list',action='store_true')
    p.add_argument('--name',choices=NAMES)
    p.add_argument('--output',type=Path)
    ns=p.parse_args(argv)
    if ns.list and not ns.name and ns.output is None:
        print('\n'.join(NAMES))
        return 0
    if not ns.name or ns.output is None or ns.list:
        p.error('use --list OR --name NAME --output NEW_DIR')
    source=SITES/ns.name
    if not source.is_dir() or source.is_symlink():
        print('COVER=FAIL MISSING_SOURCE',file=sys.stderr);return 1
    dest=ns.output
    if dest.exists() or dest.is_symlink() or not dest.parent.is_dir():
        print('COVER=FAIL DESTINATION_MUST_NOT_EXIST',file=sys.stderr);return 1
    try:
        for name in ('index.html','style.css'):
            if not (source/name).is_file() or (source/name).is_symlink():
                raise RuntimeError('source invalid')
        dest.mkdir(mode=0o755)
        for name in ('index.html','style.css'):
            data=(source/name).read_bytes()
            dst=dest/name
            with dst.open('xb') as f: f.write(data)
            dst.chmod(0o644)
    except (OSError,RuntimeError):
        for name in ('index.html','style.css'):
            (dest/name).unlink(missing_ok=True)
        if dest.exists():dest.rmdir()
        print('COVER=FAIL CREATE_ABORTED',file=sys.stderr);return 1
    print('COVER=PREPARED_OFFLINE',ns.name,'OUTPUT='+str(dest))
    print('LIVE_NGINX=UNTOUCHED')
    return 0


if __name__ == '__main__':
    sys.exit(main())
