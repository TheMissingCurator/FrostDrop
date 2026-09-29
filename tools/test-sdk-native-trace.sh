#!/usr/bin/env bash
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_dir=$(mktemp -d -p /tmp project-isac-sdk-native.XXXXXXXX)
export WINEPREFIX="$test_dir/prefix"
cleanup() {
    "${ISAC_WINESERVER:-wineserver}" -k || true
    "${ISAC_WINESERVER:-wineserver}" -w || true
    rm -rf -- "$test_dir"
}
trap cleanup EXIT
"${ISAC_MINGW_CC:-x86_64-w64-mingw32-gcc}" -O2 -Wall -Wextra -Werror \
    "$project_dir/tests/sdk_native_context_smoke.c" -o "$test_dir/sdk-native.exe"
"${ISAC_MINGW_CC:-x86_64-w64-mingw32-gcc}" -O2 -Wall -Wextra -Werror \
    "$project_dir/tests/sdk_native_context_contract.c" -o "$test_dir/sdk-contract.exe"
WINEDEBUG=-all "${ISAC_WINE:-wine}" wineboot -u > /dev/null 2>&1
WINEDEBUG=-all "${ISAC_WINE:-wine}" "$test_dir/sdk-contract.exe"
WINEDEBUG=+timestamp,+pid,+tid,+virtual,+syscall "${ISAC_WINE:-wine}" \
    "$test_dir/sdk-native.exe" > "$test_dir/fixture.txt" 2> "$test_dir/steam-fixture.log"
rg '^CONTEXT_FIXTURE|^Native dispatcher fixture' "$test_dir/fixture.txt"
rg -m 6 'SysCall.*Nt(SetContextThread|ProtectVirtualMemory)|SysRet.*Nt(SetContextThread|ProtectVirtualMemory)' "$test_dir/steam-fixture.log"
python3 "$project_dir/tools/analyze-sdk-native-trace.py" "$test_dir" --fixture-check
