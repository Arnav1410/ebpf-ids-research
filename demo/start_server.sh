#!/usr/bin/env bash
# Thin local operator entry point; all lifecycle logic remains in launch.py.
set -euo pipefail
IDS_DEMO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
for IDS_DEMO_ARG in "$@"; do
    if [[ "$IDS_DEMO_ARG" == --help || "$IDS_DEMO_ARG" == -h || "$IDS_DEMO_ARG" == --dry-run ]]; then
        exec /usr/bin/python3 "$IDS_DEMO_ROOT/demo/launch.py" "$@"
    fi
done
if [[ "$(id -u)" == 0 ]]; then
    exec /usr/bin/python3 "$IDS_DEMO_ROOT/demo/launch.py" "$@"
fi
exec sudo -- /usr/bin/python3 "$IDS_DEMO_ROOT/demo/launch.py" "$@"
