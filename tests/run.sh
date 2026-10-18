#!/usr/bin/env bash
# Offline tests only. Never run install.sh without --help/--version/invalid flag.
set -Eeuo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
export PYTHONDONTWRITEBYTECODE=1
bash -n install.sh
# Every test module in its own interpreter to prevent global stub/mock state from
# leaking between unrelated Nginx, APT, NTP and TLS integration fixtures.
# Still executes ALL test_*.py files, failing immediately on any unsuccessful case.
for test_file in tests/test_*.py; do
    printf '\n===== OFFLINE TEST MODULE %s =====\n' "${test_file##*/}"
    python3 -B -m unittest discover -s tests -p "${test_file##*/}" -v
done
