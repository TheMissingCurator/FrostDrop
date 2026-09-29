#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_dir=$(cd -- "$script_dir/.." && pwd)
build_dir="$project_dir/build/uplay_local"
shim="$project_dir/dist/uplay_local/uplay_r1_loader64.dll"
compiler=${ISAC_MINGW_CC:-x86_64-w64-mingw32-gcc}
wine_command=${ISAC_WINE:-wine}
wineserver_command=${ISAC_WINESERVER:-${WINESERVER:-wineserver}}

"$project_dir/tools/build-uplay-local.sh"
"$compiler" \
    -O2 -Wall -Wextra -Werror \
    "$project_dir/tests/transport_startup_probe_smoke.c" \
    -lws2_32 \
    -o "$build_dir/transport_startup_probe_smoke.exe"

test_dir=$(mktemp -d -p /tmp project-isac-transport-smoke.XXXXXXXX)
test_prefix="$test_dir/wine-prefix"
trap 'rm -rf -- "$test_dir"' EXIT INT TERM
mkdir -m 700 -- "$test_prefix"
cp -- "$shim" "$test_dir/uplay_r1_loader64.dll"

WINEPREFIX="$test_prefix" WINEDEBUG=-all "$wine_command" wineboot -u \
    >/dev/null 2>&1
WINEPREFIX="$test_prefix" \
WINEDEBUG=-all \
ISAC_STACK_PROBE=1 \
ISAC_TRANSPORT_STARTUP_PROBE=1 \
ISAC_TCTD_PC_LOOPBACK=1 \
ISAC_TCTD_ECHO_LOCAL=1 \
    "$wine_command" "$build_dir/transport_startup_probe_smoke.exe" \
    "Z:\\$test_dir\\uplay_r1_loader64.dll"
WINEPREFIX="$test_prefix" "$wineserver_command" -k
WINEPREFIX="$test_prefix" "$wineserver_command" -w

stack_log="$test_dir/project-isac-stack-probe.log"
test -f "$stack_log"
rg -q '^TRANSPORT_RESOLVE .*host_class=localhost,service=55000,redirect=none,result=0,' \
    "$stack_log"
rg -q '^TRANSPORT_RESOLVE .*host_class=tctd-pc,service=27015,redirect=loopback,result=0,' \
    "$stack_log"
rg -q '^TRANSPORT_CONNECT .*port=1,scope=loopback,result=-1,' "$stack_log"
rg -q '^TRANSPORT_RESOLVE .*api=getaddrinfo-a,host_class=tctd-pc-echo,service=51000,redirect=loopback,result=0,' "$stack_log"
rg -q '^TRANSPORT_RESOLVE .*api=getaddrinfo-w,host_class=tctd-pc-echo,service=51000,redirect=loopback,result=0,' "$stack_log"
rg -q '^STACK_PROBE_READY .*transport-startup=enabled,.*tctd-pc-loopback=enabled' \
    "$stack_log"

echo "Transport startup probe assertions passed."
