#!/usr/bin/env bash
set -euo pipefail
handoff_project=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
handoff_sweep=off
sdk_local=0
sdk_protect_trace=0
sdk_native_trace=0
if [[ ${1:-} == --sdk-local ]]; then
    sdk_local=1
    shift
fi
if [[ ${1:-} == --sdk-protect-trace ]]; then
    sdk_protect_trace=1
    shift
    if (( sdk_local == 0 )); then
        echo "--sdk-protect-trace requires --sdk-local." >&2
        exit 2
    fi
fi
if [[ ${1:-} == --sdk-native-trace ]]; then
    sdk_native_trace=1
    shift
    if (( sdk_local == 0 || sdk_protect_trace == 1 )); then
        echo "--sdk-native-trace requires --sdk-local and cannot combine with --sdk-protect-trace." >&2
        exit 2
    fi
fi
if [[ ${1:-} == --sweep ]]; then
    handoff_sweep=${2:-}
    if [[ $handoff_sweep != off && $handoff_sweep != on ]]; then
        echo "Expected --sweep off or --sweep on." >&2
        exit 2
    fi
    shift 2
fi
if [[ ${1:-} == --sdk-* ]]; then
    echo "Unknown, duplicated, or out-of-order SDK option." >&2
    exit 2
fi
if [[ $# -eq 0 ]]; then
    echo "Usage: steam-login-handoff-wrapper.sh [--sdk-local [--sdk-protect-trace|--sdk-native-trace]] [--sweep off|on] STEAM_COMMAND [ARGUMENT ...]" >&2
    exit 2
fi
# Host-network launch by explicit user choice. SDK_LOCAL redirects the known
# SDK template only; this wrapper does not block other external connections.
for variable in "${!ISAC_@}"; do unset "$variable"; done
export ISAC_LOGIN_HANDOFF=1
export ISAC_LOGIN_HANDOFF_SWEEP=0
if [[ $handoff_sweep == on ]]; then export ISAC_LOGIN_HANDOFF_SWEEP=1; fi
export ISAC_STACK_PROBE=1
export ISAC_LOCAL_BACKEND_BRIDGE=1
export ISAC_TRANSPORT_STARTUP_PROBE=1
export ISAC_TCTD_PC_LOOPBACK=1
export ISAC_TCTD_LOCAL_ACCEPT=1
export ISAC_TCTD_ECHO_LOCAL=1
if (( sdk_local == 1 )); then
    export ISAC_SDK_LOCAL=1
fi
export PROTON_LOG=1
export PROTON_LOG_DIR="$handoff_project/evidence/proton-logs"
mkdir -p -- "$PROTON_LOG_DIR"
# Same exception channel for both arms; do not inherit unrelated verbose tracing.
export WINEDEBUG=+timestamp,+pid,+tid,+seh
if (( sdk_native_trace == 1 )); then
    export ISAC_SDK_PROTECT_TRACE=1
    export ISAC_SDK_NATIVE_TRACE=1
    # Built-in Wine dispatcher logging, not Linux strace or Windows hardware
    # breakpoints. SysCall/SysRet print numeric argument slots/return values,
    # not pointed-to payloads. All NT call names may appear in the raw log.
    export WINEDEBUG=+timestamp,+pid,+tid,+seh,+virtual,+syscall
    exec "$@"
fi
if (( sdk_protect_trace == 1 )); then
    if ! command -v strace >/dev/null 2>&1; then
        echo "SDK protection trace requires strace. Install it before launching." >&2
        exit 1
    fi
    export ISAC_SDK_PROTECT_TRACE=1
    export WINEDEBUG=+timestamp,+pid,+tid,+seh,+virtual
    sdk_trace_log="$PROTON_LOG_DIR/sdk-protection-linux-$(date +%Y%m%d-%H%M%S)-$$.log"
    # Memory-protection failures only: no exec/env, paths, socket I/O, signals,
    # registers, reads/writes, or payloads. -D preserves the tracee's parent.
    exec strace -D -f -qq -ttt -e trace=mprotect,pkey_mprotect -e status=failed \
        -e signal=none -o "$sdk_trace_log" -- "$@"
fi
exec "$@"
