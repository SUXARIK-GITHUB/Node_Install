#!/usr/bin/env python3
"""Best-effort repository scan; never print a discovered secret. Not a security guarantee."""
import argparse
import base64
import json
from pathlib import Path
import re
import sys

PATTERNS = {
    'private PEM key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'),
    'GitHub token': re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b'),
}
SKIP_DIRS = {'.git', '__pycache__', '.venv', '.pytest_cache'}
RUNTIME_NAMES = {'remnanode.env','profile.json','reality.json','PANEL-SETUP.txt', 'reality-keys.txt', '.env'}

def inspect(text):
    for name, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            yield text.count('\n', 0, match.start())+1, name
    # Remnawave SECRET_KEY has no fixed token prefix: inspect encoded JSON payloads.
    for match in re.finditer(r'(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{200,}={0,2}', text):
        value = match.group()
        if len(value) > 200000: continue
        try:
            obj=json.loads(base64.b64decode(value+'='*(-len(value)%4), altchars=b'-_', validate=True))
        except (ValueError, UnicodeError): continue
        if isinstance(obj,dict) and ('nodeKeyPem' in obj or 'privateKey' in obj):
            yield text.count('\n',0,match.start())+1,'encoded private-key payload'

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',nargs='?',default=str(Path(__file__).resolve().parents[1]))
    args=parser.parse_args(); root=Path(args.directory).resolve()
    count=0;files=0
    for path in sorted(root.rglob('*')):
        rel=path.relative_to(root)
        if any(p in SKIP_DIRS for p in rel.parts) or not path.is_file(): continue
        if path.is_symlink(): print(f'{rel}: symlink (review separately)');count+=1;continue
        files+=1
        if path.name in RUNTIME_NAMES or path.suffix.lower() in {'.pfx','.p12','.key','.pem'}:
            print(f'{rel}: runtime/credential filename');count+=1
        try: text=path.read_text(encoding='utf-8')
        except UnicodeError: continue
        for line,kind in inspect(text):
            print(f'{rel}:{line}: {kind} [VALUE REDACTED]');count+=1
    print(f'PUBLICATION_SCAN: files={files}, findings={count}')
    return 1 if count else 0

if __name__=='__main__':sys.exit(main())
