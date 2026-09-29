#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage: run-connected-tctd-pc-capture.sh GAME_DIRECTORY COMPATDATA_DIRECTORY" >&2
    exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_dir=$(cd -- "$script_dir/.." && pwd)
game_dir=$(realpath -- "$1")
compatdata_dir=$(realpath -- "$2")
built_shim="$project_dir/dist/uplay_local/uplay_r1_loader64.dll"
active_shim="$game_dir/uplay_r1_loader64.dll"
steam_wrapper="$project_dir/tools/steam-tctd-pc-connected-wrapper.sh"

if [[ ! -f $game_dir/thedivision.exe || ! -d $compatdata_dir ]]; then
    echo "The Division game or compatdata directory is missing." >&2
    exit 2
fi
if [[ ! -f $built_shim || ! -f $active_shim ]]; then
    echo "The built or active standalone loader is missing." >&2
    exit 1
fi
if [[ $(sha256sum -- "$built_shim" | awk '{ print $1 }') != $(sha256sum -- "$active_shim" | awk '{ print $1 }') ]]; then
    echo "The standalone Project ISAC shim is not active; refusing a credential-bearing capture." >&2
    exit 1
fi
if ps -eo comm= | grep -qx 'thedivision.exe'; then
    echo "Division is already running. Exit it before starting this capture." >&2
    exit 1
fi

runtime_dir=$(mktemp -d -p /tmp project-isac-tctd-connected.XXXXXXXX)
capture_marker="$runtime_dir/capture-marker"
touch -- "$capture_marker"
trap 'rm -rf -- "$runtime_dir"' EXIT INT TERM

cat <<EOF

This capture makes one live connection to Ubisoft's tctd-pc service, but the
active standalone shim supplies only the Project ISAC development identity.
Your real Ubisoft ticket is not available to the game process.

Steam launch options must be exactly:

"$steam_wrapper" %command%

Enable the physical network, save that launch option, and close Division if it
is open. Launch only when the capture script tells you to. Stop after the first
stable menu/error or about 20 seconds of loading; no gameplay is needed.

EOF

read -r -p "Press Enter after enabling the network and saving that launch option: " _

ISAC_CAPTURE_BACKEND=1 \
ISAC_CAPTURE_BACKEND_FILTER=tctd-pc \
    "$project_dir/tools/capture-startup-linux.sh" \
        connected-tctd-pc-server-first \
        "$game_dir" \
        "$compatdata_dir"

capture_dir=$(
    find "$project_dir/evidence" \
        -maxdepth 1 \
        -type d \
        -name '*-connected-tctd-pc-server-first-linux' \
        -newer "$capture_marker" \
        -print |
        sort |
        tail -n 1
)
if [[ -z $capture_dir ]]; then
    echo "Capture completed, but its evidence directory could not be found." >&2
    exit 1
fi

pcap="$capture_dir/tctd-pc-27015.pcap"
if [[ ! -s $pcap ]]; then
    echo "The targeted port-27015 capture is missing or empty: $pcap" >&2
    exit 1
fi

"$project_dir/tools/analyze-backend-pcap.py" "$pcap" \
    > "$capture_dir/tctd-pc-metadata-analysis.txt"

private_dir="$project_dir/private/$(basename -- "$capture_dir")-flights"
"$project_dir/tools/extract-tctd-pc-flights.py" \
    "$pcap" \
    "$private_dir" \
    --summary "$capture_dir/tctd-pc-flight-summary.txt"

echo "Connected tctd-pc capture complete: $capture_dir"
echo "Metadata analysis: $capture_dir/tctd-pc-metadata-analysis.txt"
echo "Private first flights: $private_dir"
