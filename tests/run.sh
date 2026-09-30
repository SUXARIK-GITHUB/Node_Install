#!/usr/bin/env bash
# Offline tests only. Never run install.sh without --help/--version/invalid flag.
set -Eeuo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
export PYTHONDONTWRITEBYTECODE=1
bash -n install.sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
