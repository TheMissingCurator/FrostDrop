#!/usr/bin/env bash
set -euo pipefail
probe_script_dir=${BASH_SOURCE[0]%/*}
[[ $probe_script_dir != "${BASH_SOURCE[0]}" ]] || probe_script_dir=.
source "$probe_script_dir/steam-helper-env.sh"
exec /usr/bin/python3 "$probe_script_dir/retail_finalization_probe.py" "$@"
