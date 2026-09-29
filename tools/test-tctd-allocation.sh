#!/usr/bin/env bash
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
compiler=${ISAC_MINGW_CC:-x86_64-w64-mingw32-gcc}
test_dir=$(mktemp -d -p /tmp project-isac-allocation-test.XXXXXXXX)
trap 'rm -rf -- "$test_dir"' EXIT
"$compiler" -O2 -Wall -Wextra -Werror \
    "$project_dir/tests/tctd_allocation_smoke.c" -lws2_32 \
    -o "$test_dir/capture-smoke.exe"
umask 077
mkdir "$test_dir/tctd-allocation-smoke"
touch "$test_dir/marker" "$test_dir/tctd-allocation-smoke/records.bin"
touch "$test_dir/tctd-allocation-smoke/records.bin.dns"
touch "$test_dir/tctd-allocation-smoke/records.bin.rdata" "$test_dir/tctd-allocation-smoke/records.bin.fault"
test_windows="Z:${test_dir//\//\\}\\tctd-allocation-smoke\\records.bin"
export WINEPREFIX="$test_dir/prefix" WINEDEBUG=-all
"${ISAC_WINE:-wine}" "$test_dir/capture-smoke.exe" "$test_windows"
"${ISAC_WINESERVER:-wineserver}" -k
"${ISAC_WINESERVER:-wineserver}" -w
rg -q '^ISACDNS1$' "$test_dir/tctd-allocation-smoke/records.bin.dns"
rg -q 'example.invalid' "$test_dir/tctd-allocation-smoke/records.bin.dns"
rg -q 'other.invalid' "$test_dir/tctd-allocation-smoke/records.bin.dns"
if rg -q 'secret.invalid|limit.invalid' "$test_dir/tctd-allocation-smoke/records.bin.dns"; then
    echo "Private resolver capture did not enforce its content/record bounds." >&2
    exit 1
fi
python3 "$project_dir/tools/analyze-tctd-allocation.py" \
    --private-root "$test_dir" --since "$test_dir/marker" \
    --stack-log "$test_dir/no-stack-log" > "$test_dir/analysis.txt"
rg -q 'Records: 5;' "$test_dir/analysis.txt"
rg -q 'Parsed response matches handoff: True' "$test_dir/analysis.txt"
python3 "$project_dir/tests/test_analyze_tctd_allocation.py"
python3 "$project_dir/tools/analyze-login-handoff.py" \
    "$test_dir/tctd-allocation-smoke/records.bin.handoff.log" > "$test_dir/handoff-analysis.txt"
rg -q '^frontend-before-sync: 2 recorded transitions$' "$test_dir/handoff-analysis.txt"
rg -q 'services-state=-2147483648 auth-state=2147483647' "$test_dir/handoff-analysis.txt"
rg -q 'channel-present=0 manager-state=-2147483648$' "$test_dir/handoff-analysis.txt"
echo "Private capture roundtrip assertions passed."
