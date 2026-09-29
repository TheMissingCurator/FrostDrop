#!/usr/bin/env bash
set -euo pipefail
probe_script_dir=${BASH_SOURCE[0]%/*}
[[ $probe_script_dir != "${BASH_SOURCE[0]}" ]] || probe_script_dir=.
source "$probe_script_dir/steam-helper-env.sh"
probe_project=$(cd -- "$probe_script_dir/.." && pwd)
exec /usr/bin/python3 "$probe_project/tools/retail_forward_probe.py" "$@"
