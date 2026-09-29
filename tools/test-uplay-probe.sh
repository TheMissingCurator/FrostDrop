#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_dir=$(cd -- "$script_dir/.." && pwd)
build_dir="$project_dir/build/uplay_probe"
probe="$project_dir/dist/uplay_probe/uplay_r1_loader64.dll"
compiler=${ISAC_MINGW_CC:-x86_64-w64-mingw32-gcc}
wine_command=${ISAC_WINE:-wine}
wineserver_command=${ISAC_WINESERVER:-${WINESERVER:-wineserver}}

if [[ ! -f $probe ]]; then
    "$project_dir/tools/build-uplay-probe.sh"
fi

python3 "$project_dir/tests/test_analyze_dispatch_probe.py"
python3 "$project_dir/tests/test_analyze_plaintext_probe.py"
python3 "$project_dir/tests/test_analyze_uplay_abi_probe.py"
python3 "$project_dir/tests/test_analyze_uplay_abi_callers.py"
python3 "$project_dir/tests/test_analyze_bootstrap_probe.py"
python3 "$project_dir/tests/test_analyze_control_probe.py"
python3 "$project_dir/tests/test_analyze_outbound_control_probe.py"
python3 "$project_dir/tests/test_analyze_code_probe.py"
python3 "$project_dir/tests/test_analyze_schema_probe.py"
python3 "$project_dir/tests/test_analyze_schema_fields.py"
python3 "$project_dir/tests/test_analyze_schema_miner.py"
python3 "$project_dir/tests/test_analyze_tctd_cert_probe.py"
python3 "$project_dir/tests/test_analyze_tctd_chain_probe.py"
python3 "$project_dir/tests/test_analyze_tctd_parser_code.py"
python3 "$project_dir/tests/test_type0088_codec.py"
python3 "$project_dir/tests/test_simple_message_codecs.py"
python3 "$project_dir/tests/test_inspect_type0003_profile.py"
python3 "$project_dir/tests/test_inspect_world_request.py"
python3 "$project_dir/tests/test_inspect_world_bootstrap.py"
python3 "$project_dir/tests/test_analyze_world_continuation.py"
python3 "$project_dir/tests/test_slice_world_bootstrap.py"
python3 "$project_dir/tests/test_tctd_pc_tls_probe.py"
python3 "$project_dir/tests/test_world_replay.py"
python3 "$project_dir/tests/test_bootstrap_state_machine.py"

"$compiler" \
    -O2 \
    -Wall \
    -Wextra \
    -Werror \
    -I"$build_dir" \
    "$project_dir/tests/uplay_probe_smoke.c" \
    -lws2_32 \
    -o "$build_dir/uplay_probe_smoke.exe"

"$compiler" \
    -O0 \
    -Wall \
    -Wextra \
    -Werror \
    "$project_dir/tests/hardware_breakpoint_smoke.c" \
    -o "$build_dir/hardware_breakpoint_smoke.exe"

"$compiler" \
    -shared \
    -O2 \
    -Wall \
    -Wextra \
    -Werror \
    "$project_dir/tests/uplay_probe_original_smoke.c" \
    "$project_dir/tests/uplay_probe_original_smoke.def" \
    -o "$build_dir/uplay_r1_loader64_isac_original.dll"

"$compiler" \
    -O2 \
    -Wall \
    -Wextra \
    -Werror \
    "$project_dir/tests/uplay_abi_probe_smoke.c" \
    -o "$build_dir/uplay_abi_probe_smoke.exe"

test_dir=$(mktemp -d -p /tmp project-isac-uplay-probe.XXXXXXXX)
test_prefix="$test_dir/wine-prefix"
trap 'rm -rf -- "$test_dir"' EXIT INT TERM

cp -- "$probe" "$test_dir/uplay_r1_loader64.dll"

WINEPREFIX="$test_prefix" WINEDEBUG=-all "$wine_command" wineboot -u \
    >/dev/null 2>&1
ISAC_STACK_PROBE=1 ISAC_CODE_PROBE=1 ISAC_DISPATCH_PROBE=1 \
    ISAC_DISPATCH_EVENT_PROBE=1 ISAC_PLAINTEXT_PROBE=1 \
    ISAC_BOOTSTRAP_PROBE=1 ISAC_CONTROL_PROBE=1 \
    WINEPREFIX="$test_prefix" WINEDEBUG=-all "$wine_command" \
    "$build_dir/uplay_probe_smoke.exe" \
    "Z:\\$test_dir\\uplay_r1_loader64.dll"
WINEPREFIX="$test_prefix" WINEDEBUG=-all "$wine_command" \
    "$build_dir/hardware_breakpoint_smoke.exe"
cp -- "$build_dir/uplay_r1_loader64_isac_original.dll" "$test_dir/"
ISAC_UPLAY_ABI_PROBE=1 \
    WINEPREFIX="$test_prefix" WINEDEBUG=-all "$wine_command" \
    "$build_dir/uplay_abi_probe_smoke.exe" \
    "Z:\\$test_dir\\uplay_r1_loader64.dll"
WINEPREFIX="$test_prefix" "$wineserver_command" -k
WINEPREFIX="$test_prefix" "$wineserver_command" -w

test -f "$test_dir/project-isac-uplay-probe.log"
rg -q '^ORIGINAL_LOAD_FAILED ' "$test_dir/project-isac-uplay-probe.log"
rg -q '^FIRST_CALL .*UPLAY_USER_IsOwned' \
    "$test_dir/project-isac-uplay-probe.log"
test -f "$test_dir/project-isac-stack-probe.log"
rg -q '^STACK_PROBE_READY .*payloads=disabled' \
    "$test_dir/project-isac-stack-probe.log"
rg -q '^STACK .*direction=send .*rvas=0x' \
    "$test_dir/project-isac-stack-probe.log"
rg -q '^STACK .*direction=recv .*rvas=0x' \
    "$test_dir/project-isac-stack-probe.log"
test -f "$test_dir/project-isac-code-probe.log"
rg -q '^CODE_PROBE_SKIPPED .*unsupported-main-image' \
    "$test_dir/project-isac-code-probe.log"
if rg -q '^CODE ' "$test_dir/project-isac-code-probe.log"; then
    echo "Code capture unexpectedly bypassed its executable-build guard." >&2
    exit 1
fi
test -f "$test_dir/project-isac-dispatch-probe.log"
rg -q '^DISPATCH_PROBE_SKIPPED .*unsupported-main-image' \
    "$test_dir/project-isac-dispatch-probe.log"
if rg -q '^DISPATCH_TARGET ' "$test_dir/project-isac-dispatch-probe.log"; then
    echo "Dispatch probe unexpectedly bypassed its executable-build guard." >&2
    exit 1
fi
if rg -q '^DISPATCH_CODE ' "$test_dir/project-isac-dispatch-probe.log"; then
    echo "Dispatch code capture bypassed its executable-build guard." >&2
    exit 1
fi
if rg -q '^DISPATCH_EVENT_READY ' "$test_dir/project-isac-dispatch-probe.log"; then
    echo "Dispatch event capture bypassed its executable-build guard." >&2
    exit 1
fi
if rg -q '^DISPATCH_EVENT ' "$test_dir/project-isac-dispatch-probe.log"; then
    echo "Dispatch events bypassed the executable-build guard." >&2
    exit 1
fi
test -f "$test_dir/project-isac-plaintext-probe.log"
rg -q '^PLAINTEXT_PROBE_SKIPPED .*unsupported-main-image' \
    "$test_dir/project-isac-plaintext-probe.log"
if rg -q '^PLAINTEXT_OUT ' "$test_dir/project-isac-plaintext-probe.log"; then
    echo "Plaintext capture bypassed its executable-build guard." >&2
    exit 1
fi
test -f "$test_dir/project-isac-uplay-abi-probe.log"
rg -q '^UPLAY_ABI_READY .*pointed-bytes=disabled .*raw-pointers=disabled' \
    "$test_dir/project-isac-uplay-abi-probe.log"
rg -q '^UPLAY_ABI_CODE .*function=UPLAY_USER_IsOwned .*bytes=[0-9a-f]+' \
    "$test_dir/project-isac-uplay-abi-probe.log"
rg -q '^UPLAY_ABI_CALL .*function=UPLAY_USER_IsOwned .*arg0=writable-' \
    "$test_dir/project-isac-uplay-abi-probe.log"
rg -q '^UPLAY_ABI_RETURN .*function=UPLAY_USER_IsOwned .*rax=scalar32:0x00001234 .*arg0_word_changed=yes' \
    "$test_dir/project-isac-uplay-abi-probe.log"

echo "Forwarding and bounded probe assertions passed."
