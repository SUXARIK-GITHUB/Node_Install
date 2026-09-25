#!/usr/bin/env python3
"""Print a deployment command for this public GitHub repository. No network requests."""
import argparse
import re
import subprocess
import sys

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('repository',nargs='?',help='OWNER/REPO or public GitHub repository URL; default: git origin')
    parser.add_argument('--ref',default='main',help='branch, tag or full commit SHA')
    a=parser.parse_args()
    value=a.repository
    if not value:
        r=subprocess.run(['git','config','--get','remote.origin.url'],capture_output=True,text=True)
        if r.returncode: parser.error('Pass OWNER/REPO or configure remote.origin.url.')
        value=r.stdout.strip()
    value=value.removeprefix('https://github.com/').removeprefix('git@github.com:').rstrip('/')
    value=value.removesuffix('.git')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+',value):
        parser.error('Expected OWNER/REPO or https://github.com/OWNER/REPO')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]*',a.ref):parser.error('Invalid Git ref')
    print(f'bash <(curl -fsSL https://raw.githubusercontent.com/{value}/{a.ref}/install.sh)')

if __name__=='__main__':main()
