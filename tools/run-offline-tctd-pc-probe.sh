#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage: run-offline-tctd-pc-probe.sh GAME_DIRECTORY COMPATDATA_DIRECTORY" >&2
    exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec "$script_dir/run-offline-integration.sh" "$1" "$2" tctd
