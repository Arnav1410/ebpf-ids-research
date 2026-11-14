#!/usr/bin/env bash
set -euo pipefail
tc_repo_root=$(cd -- "$(dirname -- "$0")" && pwd)
exec /usr/bin/python3 "$tc_repo_root/tc/demo.py" "$@"
