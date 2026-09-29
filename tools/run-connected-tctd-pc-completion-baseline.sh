#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage: run-connected-tctd-pc-completion-baseline.sh GAME_DIRECTORY COMPATDATA_DIRECTORY" >&2
    exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}" )" && pwd)

cat <<'EOF'

This read-only baseline contacts Ubisoft's normal tctd-pc service. It does not
rewrite DNS or modify traffic. Enable the network before launching the game.
Stop at the first stable menu or loading result; no gameplay is needed.

EOF

exec "$script_dir/run-offline-integration.sh" "$1" "$2" tctd-completion-baseline
