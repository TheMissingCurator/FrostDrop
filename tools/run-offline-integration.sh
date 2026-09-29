#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
Usage: run-offline-integration.sh GAME_DIRECTORY COMPATDATA_DIRECTORY [REPLAY]

REPLAY may be:
  full   longest captured bootstrap and gameplay slice (default)
  hub    bootstrap through the stable Post Office state
  gate   shortest bootstrap through the first world gate
  transport  startup transport diagnostic; no profile/world injection
  tctd   redirect only tctd-pc:27015 to a silent loopback listener
  tctd-tls  replay the captured port-27015 preface and terminate TLS locally
  tctd-cert  trace reads of the rejected local port-27015 certificate
  tctd-validation  trace certificate-validation code and return decisions
  tctd-accept  accept the local port-27015 TLS identity across retries
  tctd-bootstrap  serve a newly generated local certificate after TLS
  tctd-echo  certificate bootstrap plus local direct-TLS directory candidate
  tctd-backend  certificate, directory and encrypted port-55001 transport together
  tctd-channels  split latency/backend services plus candidate channel setup
  tctd-leads     same backend plus endpoint-selection and private resolver probe
  tctd-handoff   same backend plus services/frontend/auth-channel state probe
  tctd-handoff-off/on  same handoff probe with labeled thread-sweep comparison
  sdk-local     handoff with experimental local SDK session/configuration service
  sdk-protect-trace  SDK mode plus focused URL memory-protection diagnosis
  sdk-native-trace   SDK mode plus Wine native dispatcher entry/return logging
  tctd-allocation  capture decrypted allocation and parser output while connected
  tctd-validator-code  capture the complete validator runtime function
  tctd-state-watch  trace writes to the failed validation-state byte
  tctd-owner-watch  trace the decision owner, pointer field, and state writes
  tctd-owner-baseline  compare that lifecycle against Ubisoft's live service
  tctd-validation-baseline  compare staged validation against Ubisoft's service
  tctd-completion  trace the local asynchronous completion path
  tctd-completion-baseline  trace that path against Ubisoft's live service
  tctd-branch  classify the four local certificate completion gates
  tctd-branch-baseline  classify those gates against Ubisoft's live service
  tctd-chain  trace the local certificate-processing return chain
  tctd-chain-baseline  compare that chain against Ubisoft's live service
  tctd-parser-code  capture the dynamically selected local TLS parser body
  tctd-cert-flow  follow local certificate bytes through copies and consumers
  tctd-cert-flow-baseline  compare that flow against Ubisoft's live service
  PATH   an explicit private ISACWBS1 artifact
EOF
    exit 2
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
    usage
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_dir=$(cd -- "$script_dir/.." && pwd)
game_dir=$(realpath -- "$1")
compatdata_dir=$(realpath -- "$2")
selection=${3:-full}
sdk_local=0
sdk_protect_trace=0
sdk_native_trace=0
if [[ $selection == sdk-protect-trace ]]; then
    sdk_protect_trace=1
    if ! command -v strace >/dev/null 2>&1; then
        echo "SDK protection diagnosis requires strace. Install it before this capture." >&2
        exit 1
    fi
fi
if [[ $selection == sdk-native-trace ]]; then
    sdk_native_trace=1
    sdk_protect_trace=1
fi
if [[ $selection == sdk-local || $selection == sdk-protect-trace || $selection == sdk-native-trace ]]; then
    sdk_local=1
    selection=tctd-handoff
fi
handoff_sweep=off
if [[ $selection == tctd-handoff-off || $selection == tctd-handoff-on ]]; then
    handoff_sweep=${selection##*-}
    selection=tctd-handoff
fi
profile="$project_dir/private/type0003-retail-profile.json"
built_shim="$project_dir/dist/uplay_local/uplay_r1_loader64.dll"
active_shim="$game_dir/uplay_r1_loader64.dll"
capture_label=offline-local-full-replay
steam_wrapper="$project_dir/tools/steam-offline-wrapper.sh"
tctd_probe=0
tctd_tls_probe=0
tctd_cert_probe=0
tctd_validation_probe=0
tctd_accept_probe=0
tctd_bootstrap=0
tctd_echo=0
tctd_backend=0
tctd_channels=0
tctd_validator_code_probe=0
tctd_state_watch_probe=0
tctd_owner_watch_probe=0
tctd_completion_probe=0
tctd_branch_probe=0
tctd_chain_probe=0
tctd_parser_code_probe=0
tctd_cert_flow_probe=0
tctd_remote_probe=0
tctd_text_dump_file="$game_dir/project-isac-tctd-text-private.bin"

require_game_stopped() {
    local matches

    if [[ -n ${ISAC_HOST_PROC:-} ]]; then
        matches=$(python3 "$script_dir/capture-process-list.py" | awk '$NF == "thedivision.exe" { print }')
    else
        matches=$(ps -eo pid=,comm= | awk '$2 == "thedivision.exe" { print }')
    fi
    if [[ -n $matches ]]; then
        echo "Division is already running:" >&2
        echo "$matches" >&2
        echo "Exit the game completely, then start this runner again." >&2
        exit 1
    fi
}

case $selection in
    tctd-allocation)
        replay=''
        capture_label=connected-tctd-allocation
        steam_wrapper="$project_dir/tools/steam-tctd-allocation-wrapper.sh"
        tctd_remote_probe=1
        ;;
    full)
        replay="$project_dir/private/world-continuation-actions-20260925.bin"
        ;;
    hub)
        replay="$project_dir/private/world-bootstrap-hub-stable-20260925.bin"
        capture_label=offline-local-hub-replay
        ;;
    gate)
        replay="$project_dir/private/world-bootstrap-first-gate-20260925.bin"
        capture_label=offline-local-gate-replay
        ;;
    transport)
        replay=''
        capture_label=offline-transport-startup
        steam_wrapper="$project_dir/tools/steam-transport-probe-wrapper.sh"
        ;;
    tctd)
        replay=''
        capture_label=offline-tctd-pc-loopback
        steam_wrapper="$project_dir/tools/steam-tctd-pc-probe-wrapper.sh"
        tctd_probe=1
        ;;
    tctd-tls)
        replay=''
        capture_label=offline-tctd-pc-tls-probe
        steam_wrapper="$project_dir/tools/steam-tctd-pc-probe-wrapper.sh"
        tctd_probe=1
        tctd_tls_probe=1
        ;;
    tctd-cert)
        replay=''
        capture_label=offline-tctd-pc-cert-probe
        steam_wrapper="$project_dir/tools/steam-tctd-pc-cert-probe-wrapper.sh"
        tctd_probe=1
        tctd_tls_probe=1
        tctd_cert_probe=1
        ;;
    tctd-validation)
        replay=''
        capture_label=offline-tctd-pc-validation-probe
        steam_wrapper="$project_dir/tools/steam-tctd-pc-validation-probe-wrapper.sh"
        tctd_probe=1
        tctd_tls_probe=1
        tctd_cert_probe=1
        tctd_validation_probe=1
        ;;
    tctd-echo|tctd-backend|tctd-channels|tctd-leads|tctd-handoff)
        replay=''
        capture_label=offline-tctd-echo-directory
        steam_wrapper="$project_dir/tools/steam-tctd-echo-wrapper.sh"
        tctd_probe=1
        tctd_tls_probe=1
        tctd_accept_probe=1
        tctd_bootstrap=1
        tctd_echo=1
        if [[ $selection != tctd-echo ]]; then
            tctd_backend=1
            capture_label=offline-tctd-encrypted-backend
        fi
        if [[ $selection == tctd-channels || $selection == tctd-leads || $selection == tctd-handoff ]]; then
            tctd_channels=1
            capture_label=offline-tctd-main-channels
        fi
        if [[ $selection == tctd-leads ]]; then
            capture_label=offline-startup-leads
            steam_wrapper="$project_dir/tools/steam-startup-leads-wrapper.sh"
        fi
        if [[ $selection == tctd-handoff ]]; then
            capture_label=offline-login-handoff-sweep-$handoff_sweep
            steam_wrapper="$project_dir/tools/steam-login-handoff-wrapper.sh"
            if (( sdk_local == 1 )); then capture_label=offline-sdk-local; fi
            if (( sdk_protect_trace == 1 )); then capture_label=offline-sdk-protect-trace; fi
            if (( sdk_native_trace == 1 )); then capture_label=offline-sdk-native-trace; fi
        fi
        ;;
    tctd-bootstrap)
        replay=''
        capture_label=offline-tctd-certificate-bootstrap
        steam_wrapper="$project_dir/tools/steam-tctd-bootstrap-wrapper.sh"
        tctd_probe=1
        tctd_tls_probe=1
        tctd_accept_probe=1
        tctd_bootstrap=1
        ;;
    tctd-accept)
        replay=''
        capture_label=offline-tctd-pc-local-accept
        steam_wrapper="$project_dir/tools/steam-tctd-pc-local-accept-wrapper.sh"
        tctd_probe=1
        tctd_tls_probe=1
        tctd_accept_probe=1
        ;;
    tctd-validator-code)
        replay=''
        capture_label=offline-tctd-pc-validator-code
        steam_wrapper="$project_dir/tools/steam-tctd-pc-validator-code-wrapper.sh"
        tctd_probe=1
        tctd_tls_probe=1
        tctd_validator_code_probe=1
        ;;
    tctd-state-watch)
        replay=''
        capture_label=offline-tctd-pc-state-watch
        steam_wrapper="$project_dir/tools/steam-tctd-pc-state-watch-wrapper.sh"
        tctd_probe=1
        tctd_tls_probe=1
        tctd_state_watch_probe=1
        ;;
    tctd-owner-watch)
        replay=''
        capture_label=offline-tctd-pc-owner-watch
        steam_wrapper="$project_dir/tools/steam-tctd-pc-owner-watch-wrapper.sh"
        tctd_probe=1
        tctd_tls_probe=1
        tctd_owner_watch_probe=1
        ;;
    tctd-owner-baseline)
        replay=''
        capture_label=connected-tctd-pc-owner-baseline
        steam_wrapper="$project_dir/tools/steam-tctd-pc-owner-baseline-wrapper.sh"
        tctd_owner_watch_probe=1
        tctd_remote_probe=1
        ;;
    tctd-validation-baseline)
        replay=''
        capture_label=connected-tctd-pc-validation-baseline
        steam_wrapper="$project_dir/tools/steam-tctd-pc-validation-baseline-wrapper.sh"
        tctd_validation_probe=1
        tctd_remote_probe=1
        ;;
    tctd-completion)
        replay=''
        capture_label=offline-tctd-pc-completion-probe
        steam_wrapper="$project_dir/tools/steam-tctd-pc-completion-probe-wrapper.sh"
        tctd_probe=1
        tctd_tls_probe=1
        tctd_completion_probe=1
        ;;
    tctd-completion-baseline)
        replay=''
        capture_label=connected-tctd-pc-completion-baseline
        steam_wrapper="$project_dir/tools/steam-tctd-pc-completion-baseline-wrapper.sh"
        tctd_completion_probe=1
        tctd_remote_probe=1
        ;;
    tctd-branch)
        replay=''
        capture_label=offline-tctd-pc-branch-probe
        steam_wrapper="$project_dir/tools/steam-tctd-pc-branch-probe-wrapper.sh"
        tctd_probe=1
        tctd_tls_probe=1
        tctd_branch_probe=1
        ;;
    tctd-branch-baseline)
        replay=''
        capture_label=connected-tctd-pc-branch-baseline
        steam_wrapper="$project_dir/tools/steam-tctd-pc-branch-baseline-wrapper.sh"
        tctd_branch_probe=1
        tctd_remote_probe=1
        ;;
    tctd-chain)
        replay=''
        capture_label=offline-tctd-pc-chain-probe
        steam_wrapper="$project_dir/tools/steam-tctd-pc-chain-probe-wrapper.sh"
        tctd_probe=1
        tctd_tls_probe=1
        tctd_cert_probe=1
        tctd_chain_probe=1
        ;;
    tctd-chain-baseline)
        replay=''
        capture_label=connected-tctd-pc-chain-baseline
        steam_wrapper="$project_dir/tools/steam-tctd-pc-chain-baseline-wrapper.sh"
        tctd_cert_probe=1
        tctd_chain_probe=1
        tctd_remote_probe=1
        ;;
    tctd-parser-code)
        replay=''
        capture_label=offline-tctd-pc-parser-code
        steam_wrapper="$project_dir/tools/steam-tctd-pc-parser-code-wrapper.sh"
        tctd_probe=1
        tctd_tls_probe=1
        tctd_cert_probe=1
        tctd_parser_code_probe=1
        ;;
    tctd-cert-flow)
        replay=''
        capture_label=offline-tctd-pc-cert-flow
        steam_wrapper="$project_dir/tools/steam-tctd-pc-cert-flow-wrapper.sh"
        tctd_probe=1
        tctd_tls_probe=1
        tctd_cert_probe=1
        tctd_cert_flow_probe=1
        ;;
    tctd-cert-flow-baseline)
        replay=''
        capture_label=connected-tctd-pc-cert-flow-baseline
        steam_wrapper="$project_dir/tools/steam-tctd-pc-cert-flow-baseline-wrapper.sh"
        tctd_cert_probe=1
        tctd_cert_flow_probe=1
        tctd_remote_probe=1
        ;;
    *)
        replay=$(realpath -- "$selection")
        capture_label=offline-local-custom-replay
        ;;
esac

required_files=("$game_dir/thedivision.exe" "$profile" "$built_shim")
if [[ -n $replay ]]; then
    required_files+=("$replay")
fi
if (( tctd_tls_probe == 1 )); then
    tctd_flight_dir="$project_dir/private/20260925-132105-connected-tctd-pc-server-first-linux-flights"
    tctd_server_preface="$tctd_flight_dir/server-first.bin"
    tctd_client_preface="$tctd_flight_dir/client-first.bin"
    required_files+=("$tctd_server_preface" "$tctd_client_preface")
fi
for required in "${required_files[@]}"; do
    if [[ ! -f $required ]]; then
        echo "Required file is missing: $required" >&2
        exit 1
    fi
done
if [[ ! -d $compatdata_dir ]]; then
    echo "Compatdata directory is missing: $compatdata_dir" >&2
    exit 1
fi
if [[ ! -f $active_shim ]]; then
    echo "The active game-directory loader is missing." >&2
    exit 1
fi
require_game_stopped

if (( tctd_cert_flow_probe == 1 && tctd_remote_probe == 0 )); then
    rm -f -- "$tctd_text_dump_file"
fi

if (( tctd_tls_probe == 1 )); then
    if (( tctd_bootstrap == 1 )); then
        tctd_identity_dir="$project_dir/private/tctd-bootstrap-identity"
        "$project_dir/tools/generate-tctd-bootstrap-identity.sh" "$tctd_identity_dir"
    else
        tctd_identity_dir="$project_dir/private/tctd-pc-tls-probe-identity"
        "$project_dir/tools/generate-tctd-pc-probe-cert.sh" "$tctd_identity_dir"
    fi
    tctd_cert="$tctd_identity_dir/server-cert.pem"
    tctd_key="$tctd_identity_dir/server-key.pem"
    if (( tctd_echo == 1 )); then
        tctd_echo_identity="$project_dir/private/tctd-echo-identity"
        "$project_dir/tools/generate-tctd-echo-identity.sh" "$tctd_identity_dir" "$tctd_echo_identity"
    fi
fi

built_hash=$(sha256sum -- "$built_shim" | awk '{ print $1 }')
active_hash=$(sha256sum -- "$active_shim" | awk '{ print $1 }')
adapter_compatible="$project_dir/dist/uplay_sdk_adapter/uplay_r1_loader64.dll"
if [[ $active_hash != "$built_hash" && -f $adapter_compatible ]] &&
    [[ $active_hash == "$(sha256sum -- "$adapter_compatible" | awk '{ print $1 }')" ]]; then
    # Adapter code is dormant without its separate opt-in wrapper. Existing
    # launch wrappers clear inherited ISAC flags and retain their old behavior.
    built_hash=$active_hash
fi
if [[ $active_hash != "$built_hash" ]]; then
    echo "The standalone Project ISAC Uplay shim is not active." >&2
    echo "Active: $active_hash" >&2
    echo "Built:  $built_hash" >&2
    echo "Install it with tools/manage-uplay-local.sh before this test." >&2
    exit 1
fi

if ss -H -ltn 'sport = :55000' | grep -q .; then
    echo "TCP port 55000 is already in use; refusing to start a second backend." >&2
    exit 1
fi
if (( tctd_probe == 1 )) && ss -H -ltn 'sport = :27015' | grep -q .; then
    echo "TCP port 27015 is already in use; refusing to start the diagnostic listener." >&2
    exit 1
fi

if (( tctd_echo == 1 )) && ss -H -ltn 'sport = :51000 or sport = :55001' | grep -q .; then
    echo "Port 51000 or backend port 55001 is in use; stop its owner before this test." >&2
    exit 1
fi
if (( tctd_channels == 1 )) && ss -H -ltn 'sport = :55002' | grep -q .; then
    echo "Latency port 55002 is in use; stop its owner before this test." >&2
    exit 1
fi
if (( sdk_local == 1 )) && ss -H -ltn 'sport = :55003' | grep -q .; then
    echo "SDK port 55003 is in use; stop its owner before this test." >&2
    exit 1
fi

backend_args=(--profile "$profile")
if [[ -n $replay ]]; then
    backend_args+=(--world-replay "$replay")
fi
"$project_dir/tools/run-bootstrap-server.py" \
    "${backend_args[@]}" \
    --check-profile

runtime_dir=$(mktemp -d -p /tmp project-isac-offline-integration.XXXXXXXX)
backend_log="$runtime_dir/local-backend.log"
capture_marker="$runtime_dir/capture-marker"
touch -- "$capture_marker"
backend_pid=''
sdk_pid=''
sdk_log="$runtime_dir/sdk-services.log"
tctd_listener_pid=''
tctd_echo_pid=''
tctd_backend_pid=''
tctd_backend_log="$runtime_dir/tctd-backend-listener.log"
tctd_echo_log="$runtime_dir/tctd-echo-listener.log"
tctd_listener_log="$runtime_dir/tctd-pc-listener.log"
tctd_raw_dir="$runtime_dir/tctd-pc-captures"
capture_dir=''

stop_backend() {
    local attempt

    if [[ -n $sdk_pid ]]; then
        kill -TERM "$sdk_pid" 2>/dev/null || true
        wait "$sdk_pid" 2>/dev/null || true
        sdk_pid=''
    fi

    if [[ -z $backend_pid ]] || ! kill -0 "$backend_pid" 2>/dev/null; then
        backend_pid=''
        return
    fi
    kill -TERM "$backend_pid" 2>/dev/null || true
    for attempt in {1..50}; do
        if ! kill -0 "$backend_pid" 2>/dev/null; then
            wait "$backend_pid" 2>/dev/null || true
            backend_pid=''
            return
        fi
        sleep 0.1
    done
    kill -KILL "$backend_pid" 2>/dev/null || true
    wait "$backend_pid" 2>/dev/null || true
    backend_pid=''
}

stop_tctd_listener() {
    local attempt

    if [[ -n $tctd_backend_pid ]]; then
        kill -TERM "$tctd_backend_pid" 2>/dev/null || true
        for attempt in {1..70}; do
            if ! kill -0 "$tctd_backend_pid" 2>/dev/null; then break; fi
            sleep 0.1
        done
        if kill -0 "$tctd_backend_pid" 2>/dev/null; then
            kill -KILL "$tctd_backend_pid" 2>/dev/null || true
        fi
        wait "$tctd_backend_pid" 2>/dev/null || true
        tctd_backend_pid=''
    fi

    if [[ -n $tctd_echo_pid ]]; then
        kill -TERM "$tctd_echo_pid" 2>/dev/null || true
        for attempt in {1..70}; do
            if ! kill -0 "$tctd_echo_pid" 2>/dev/null; then break; fi
            sleep 0.1
        done
        if kill -0 "$tctd_echo_pid" 2>/dev/null; then
            kill -KILL "$tctd_echo_pid" 2>/dev/null || true
        fi
        wait "$tctd_echo_pid" 2>/dev/null || true
        tctd_echo_pid=''
    fi

    if [[ -z $tctd_listener_pid ]] || ! kill -0 "$tctd_listener_pid" 2>/dev/null; then
        tctd_listener_pid=''
        return
    fi
    kill -TERM "$tctd_listener_pid" 2>/dev/null || true
    for attempt in {1..50}; do
        if ! kill -0 "$tctd_listener_pid" 2>/dev/null; then
            wait "$tctd_listener_pid" 2>/dev/null || true
            tctd_listener_pid=''
            return
        fi
        sleep 0.1
    done
    kill -KILL "$tctd_listener_pid" 2>/dev/null || true
    wait "$tctd_listener_pid" 2>/dev/null || true
    tctd_listener_pid=''
}

copy_backend_evidence() {
    if [[ -n $capture_dir && -d $capture_dir ]]; then
        if [[ -f $runtime_dir/sdk-api-reference.json ]]; then
            cp -- "$runtime_dir/sdk-api-reference.json" "$capture_dir/sdk-api-reference.json"
        fi
        if [[ -f $sdk_log ]]; then cp -- "$sdk_log" "$capture_dir/sdk-services.log"; fi
        if [[ -f $backend_log ]]; then cp -- "$backend_log" "$capture_dir/local-backend.log"; fi
        if [[ -f $tctd_listener_log ]]; then
            cp -- "$tctd_listener_log" "$capture_dir/tctd-pc-listener.log"
        fi
        if [[ -f $tctd_echo_log ]]; then
            cp -- "$tctd_echo_log" "$capture_dir/tctd-echo-listener.log"
        fi
        if [[ -f $tctd_backend_log ]]; then
            cp -- "$tctd_backend_log" "$capture_dir/tctd-backend-listener.log"
        fi
    fi
}

locate_capture() {
    find "$project_dir/evidence" -maxdepth 1 -type d \
        -name "*-$capture_label-linux" -newer "$capture_marker" -print | sort | tail -n 1
}

cleanup() {
    stop_tctd_listener
    stop_backend
    if [[ -z $capture_dir ]]; then capture_dir=$(locate_capture) || true; fi
    copy_backend_evidence
    rm -rf -- "$runtime_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if (( sdk_local == 1 )); then
    PYTHONUNBUFFERED=1 python3 "$project_dir/tools/run-sdk-services.py" > "$sdk_log" 2>&1 &
    sdk_pid=$!
    ready=0
    for _ in {1..50}; do
        if ! kill -0 "$sdk_pid" 2>/dev/null; then
            echo "SDK service failed to start:" >&2
            sed -n '1,80p' "$sdk_log" >&2
            exit 1
        fi
        if grep -q '^SDK_SERVICES_READY ' "$sdk_log"; then ready=1; break; fi
        sleep 0.1
    done
    if (( ready == 0 )); then
        echo "Timed out waiting for the SDK service." >&2
        exit 1
    fi
fi

PYTHONUNBUFFERED=1 python3 "$project_dir/tools/run-bootstrap-server.py" \
    "${backend_args[@]}" \
    > "$backend_log" 2>&1 &
backend_pid=$!

ready=0
for _ in {1..50}; do
    if ! kill -0 "$backend_pid" 2>/dev/null; then
        echo "The local backend exited during startup:" >&2
        sed -n '1,120p' "$backend_log" >&2
        exit 1
    fi
    if grep -q '^Project ISAC plaintext bootstrap server listening' "$backend_log"; then
        ready=1
        break
    fi
    sleep 0.1
done
if (( ready == 0 )); then
    echo "Timed out waiting for the local backend to listen." >&2
    exit 1
fi

if (( tctd_probe == 1 )); then
    mkdir -m 700 -- "$tctd_raw_dir"
    if (( tctd_tls_probe == 1 )); then
        tctd_application_args=()
        if (( tctd_bootstrap == 1 )); then
            tctd_application_args+=(--serve-certificate)
        fi
        PYTHONUNBUFFERED=1 python3 "$project_dir/tools/run-tctd-pc-tls-probe.py" \
            --server-preface "$tctd_server_preface" \
            --expected-client-preface "$tctd_client_preface" \
            --cert "$tctd_cert" \
            --key "$tctd_key" \
            --capture-dir "$tctd_raw_dir" \
            "${tctd_application_args[@]}" \
            > "$tctd_listener_log" 2>&1 &
    else
        PYTHONUNBUFFERED=1 python3 "$project_dir/tools/run-tctd-pc-listener.py" \
            --capture-dir "$tctd_raw_dir" \
            > "$tctd_listener_log" 2>&1 &
    fi
    tctd_listener_pid=$!

    ready=0
    for _ in {1..50}; do
        if ! kill -0 "$tctd_listener_pid" 2>/dev/null; then
            echo "The tctd-pc listener exited during startup:" >&2
            sed -n '1,120p' "$tctd_listener_log" >&2
            exit 1
        fi
        if grep -Eq '^TCTD_PC_(LISTENER|TLS_PROBE)_READY ' "$tctd_listener_log"; then
            ready=1
            break
        fi
        sleep 0.1
    done
    if (( ready == 0 )); then
        echo "Timed out waiting for the tctd-pc listener." >&2
        exit 1
    fi
fi

if (( tctd_echo == 1 )); then
    tctd_echo_args=()
    if (( tctd_channels == 1 )); then tctd_echo_args+=(--split-services); fi
    PYTHONUNBUFFERED=1 python3 "$project_dir/tools/run-tctd-echo-server.py" \
        --cert "$tctd_echo_identity/server-cert.pem" \
        --key "$tctd_echo_identity/server-key.pem" \
        --capture-dir "$tctd_raw_dir" "${tctd_echo_args[@]}" > "$tctd_echo_log" 2>&1 &
    tctd_echo_pid=$!
    ready=0
    for _ in {1..50}; do
        if ! kill -0 "$tctd_echo_pid" 2>/dev/null; then
            echo "Echo listener failed to start:" >&2
            sed -n '1,80p' "$tctd_echo_log" >&2
            exit 1
        fi
        if grep -q '^TCTD_ECHO_READY ' "$tctd_echo_log"; then ready=1; break; fi
        sleep 0.1
    done
    if (( ready == 0 )); then
        echo "Timed out waiting for the echo listener." >&2
        exit 1
    fi
fi

if (( tctd_backend == 1 )); then
    tctd_backend_args=()
    if (( tctd_channels == 1 )); then tctd_backend_args+=(--channel-setup --latency-port 55002); fi
    PYTHONUNBUFFERED=1 python3 "$project_dir/tools/run-tctd-backend-server.py" \
        --cert "$tctd_echo_identity/server-cert.pem" \
        --key "$tctd_echo_identity/server-key.pem" \
        --server-preface "$tctd_server_preface" \
        --expected-client-preface "$tctd_client_preface" \
        --capture-dir "$tctd_raw_dir" "${tctd_backend_args[@]}" > "$tctd_backend_log" 2>&1 &
    tctd_backend_pid=$!
    ready=0
    for _ in {1..50}; do
        if ! kill -0 "$tctd_backend_pid" 2>/dev/null; then
            echo "Encrypted backend listener failed to start:" >&2
            sed -n '1,80p' "$tctd_backend_log" >&2
            exit 1
        fi
        if grep -q '^TCTD_BACKEND_READY ' "$tctd_backend_log"; then ready=1; break; fi
        sleep 0.1
    done
    if (( ready == 0 )); then
        echo "Timed out waiting for the encrypted backend listener." >&2
        exit 1
    fi
fi

echo "Project ISAC capture services are ready for mode: $selection"
if (( sdk_local == 1 )); then
    echo "Local SDK service ready on loopback port 55003."
    echo "Network isolation/checks are disabled; unreplaced game routes may contact Ubisoft."
fi
read -r -p "Press Enter to begin the capture: " _
require_game_stopped
if (( sdk_protect_trace == 1 )); then
    python3 "$project_dir/tools/sdk-api-reference.py" "$compatdata_dir/pfx" \
        > "$runtime_dir/sdk-api-reference.json"
fi

if (( sdk_local == 1 )); then
    # Keep SDK capture log-only: do not add sudo/tcpdump or record plaintext
    # SDK credentials just because host networking is now enabled.
    ISAC_CAPTURE_BACKEND=0 ISAC_ROUTE_AUDIT=1 ISAC_SDK_PROTECT_TRACE="$sdk_protect_trace" \
        "$project_dir/tools/capture-startup-linux.sh" \
        "$capture_label" "$game_dir" "$compatdata_dir"
elif (( tctd_tls_probe == 1 || tctd_remote_probe == 1 )); then
    tctd_capture_filter=tctd-pc
    if (( tctd_echo == 1 )); then tctd_capture_filter=startup; fi
    ISAC_CAPTURE_BACKEND=1 \
    ISAC_CAPTURE_BACKEND_FILTER="$tctd_capture_filter" \
        "$project_dir/tools/capture-startup-linux.sh" \
            "$capture_label" \
            "$game_dir" \
            "$compatdata_dir"
else
    "$project_dir/tools/capture-startup-linux.sh" \
        "$capture_label" \
        "$game_dir" \
        "$compatdata_dir"
fi

stop_tctd_listener
stop_backend

capture_dir=$(
    find "$project_dir/evidence" \
        -maxdepth 1 \
        -type d \
        -name "*-$capture_label-linux" \
        -newer "$capture_marker" \
        -print |
        sort |
        tail -n 1
)
if [[ -z $capture_dir ]]; then
    echo "Capture completed, but its evidence directory could not be located." >&2
    exit 1
fi
cp -- "$backend_log" "$capture_dir/local-backend.log"
if [[ -f $sdk_log ]]; then cp -- "$sdk_log" "$capture_dir/sdk-services.log"; fi
if (( sdk_protect_trace == 1 )); then
    cp -- "$runtime_dir/sdk-api-reference.json" "$capture_dir/sdk-api-reference.json"
    python3 "$project_dir/tools/sdk-api-reference.py" "$compatdata_dir/pfx" \
        > "$capture_dir/sdk-api-reference-after.json"
    python3 "$project_dir/tools/analyze-sdk-protection.py" "$capture_dir" \
        > "$capture_dir/sdk-protection-analysis.txt"
fi
if (( sdk_native_trace == 1 )); then
    python3 "$project_dir/tools/analyze-sdk-native-trace.py" "$capture_dir" \
        > "$capture_dir/sdk-native-analysis.txt"
fi
if [[ $selection == tctd-allocation ]]; then
    python3 "$project_dir/tools/analyze-tctd-allocation.py" \
        --private-root "$project_dir/private" \
        --since "$capture_marker" \
        --stack-log "$capture_dir/project-isac-stack-probe.log" \
        > "$capture_dir/tctd-allocation-analysis.txt"
    echo "Allocation analysis: $capture_dir/tctd-allocation-analysis.txt"
fi
if [[ -f $tctd_listener_log ]]; then
    cp -- "$tctd_listener_log" "$capture_dir/tctd-pc-listener.log"
fi
if [[ -f $tctd_echo_log ]]; then
    cp -- "$tctd_echo_log" "$capture_dir/tctd-echo-listener.log"
fi
if [[ -f $tctd_backend_log ]]; then
    cp -- "$tctd_backend_log" "$capture_dir/tctd-backend-listener.log"
fi
{
    echo "Replay selection: $selection"
    echo "Network isolation: disabled; no interface preflight or automatic namespace"
    echo "External game connections: not blocked; unreplaced routes may contact Ubisoft"
    if (( sdk_local == 1 )); then
        echo "SDK local mode: enabled; loopback HTTP port 55003; session/config contract candidate"
        echo "SDK route: exact in-memory URL template override; verify SDK_LOCAL_ROUTE_READY and SDK_HTTP events"
        echo "SDK network boundary: ordinary host networking; local service binds loopback only"
        echo "Steam IPC: normal host Steam connection; no relay"
        echo "Packet capture: disabled in SDK mode; client and service logs retained"
        echo "SDK HTTP payload capture: disabled; logs contain route/status/response size only"
        echo "Route audit: sampled Division-prefix socket metadata; see route-audit-summary.txt"
        echo "SDK protection trace requested: $sdk_protect_trace"
        echo "SDK native dispatcher trace requested: $sdk_native_trace"
    fi
    if [[ -n $replay ]]; then
        echo "Replay path: $replay"
        echo "Replay SHA-256: $(sha256sum -- "$replay" | awk '{ print $1 }')"
    else
        echo "Replay path: disabled for transport diagnostic"
    fi
    echo "Profile path: $profile"
    echo "Profile SHA-256: $(sha256sum -- "$profile" | awk '{ print $1 }')"
    echo "Standalone shim SHA-256: $built_hash"
    if (( tctd_probe == 1 )); then
        echo "tctd-pc rewrite: tctd-pc.ubisoft.com:27015 -> 127.0.0.1:27015"
        if (( tctd_tls_probe == 1 )); then
            echo "tctd-pc response mode: captured-preface-and-local-tls"
            if (( tctd_bootstrap == 1 )); then
                echo "tctd-pc server application mode: local-certificate, protocol-version=303"
                if (( tctd_echo == 1 )); then
                    echo "Echo routing: tctd-pc-echo:51000 -> 127.0.0.1:51000"
                    echo "Echo response: version-1572 directory candidate, unconfirmed schema, loopback endpoints only"
                    if (( tctd_backend == 1 )); then
                        echo "Port 55001: preface/TLS transport, candidate version=2056, private root-message capture"
                        if (( tctd_channels == 1 )); then
                            echo "Port 55001: candidate initial settings, channel registration acknowledgments, heartbeats"
                            echo "Directory routing: kind 0 -> 55001, kind 1 -> 55002; verify constructors in capture"
                            echo "Port 55002: plain-TCP protocol 556, three ping/pong pairs and timing summary"
                        fi
                        echo "Port 55001 login/world responses: not implemented; plaintext bridge protocol is not TLS wire format"
                    else
                        echo "Port 55001: reserved encrypted-backend port; listener disabled in this mode"
                    fi
                fi
                echo "Client certificate acceptance: requires game-side validation; send is not proof"
            else
                echo "tctd-pc server application mode: silent"
            fi
            echo "tctd-pc TLS certificate SHA-256: $(openssl x509 -in "$tctd_cert" -outform der | sha256sum | awk '{ print $1 }')"
        else
            echo "tctd-pc response mode: silent"
        fi
    elif (( tctd_remote_probe == 1 )); then
        echo "tctd-pc rewrite: disabled"
        echo "tctd-pc response mode: Ubisoft live service, read-only observation"
    fi
} > "$capture_dir/offline-integration.txt"

if (( tctd_probe == 1 )); then
    private_capture_dir="$project_dir/private/$(basename -- "$capture_dir")-tctd-pc"
    if find "$tctd_raw_dir" -maxdepth 1 -type f -print -quit | grep -q .; then
        mkdir -m 700 -- "$private_capture_dir"
        find "$tctd_raw_dir" -maxdepth 1 -type f -exec cp -- {} "$private_capture_dir"/ \;
        chmod 600 -- "$private_capture_dir"/*
        {
            echo "Private tctd-pc capture directory: $private_capture_dir"
            find "$private_capture_dir" -maxdepth 1 -type f -printf '%f\n' | sort
        } >> "$capture_dir/offline-integration.txt"
    else
        echo "Private tctd-pc data: none captured" \
            >> "$capture_dir/offline-integration.txt"
    fi
fi

if (( tctd_cert_flow_probe == 1 && tctd_remote_probe == 0 )); then
    if [[ -s $tctd_text_dump_file ]]; then
        tctd_text_sha=$(sha256sum -- "$tctd_text_dump_file" | awk '{ print $1 }')
        tctd_text_private="$project_dir/private/tctd-runtime-text-$tctd_text_sha.bin"
        if [[ ! -f $tctd_text_private ]]; then
            cp -- "$tctd_text_dump_file" "$tctd_text_private"
            chmod 600 -- "$tctd_text_private"
        fi
        rm -f -- "$tctd_text_dump_file"
        {
            echo "Runtime text dump: $tctd_text_private"
            echo "Runtime text start RVA: 0x1000"
            echo "Runtime text length: 42991616"
            echo "Runtime text SHA-256: $tctd_text_sha"
        } > "$capture_dir/tctd-runtime-text-analysis.txt"
    else
        echo "Runtime text dump: not captured" \
            > "$capture_dir/tctd-runtime-text-analysis.txt"
    fi
fi

if (( tctd_echo == 1 )) && [[ -s $capture_dir/startup-ports.pcap ]]; then
    "$project_dir/tools/analyze-backend-pcap.py" "$capture_dir/startup-ports.pcap" \
        > "$capture_dir/startup-metadata-analysis.txt"
fi
if (( tctd_echo == 1 )) && [[ -f $capture_dir/project-isac-stack-probe.log ]]; then
    { grep -E '^SDK_LOCAL_ROUTE_|^TCTD_ECHO_|^STARTUP_(LEADS|STATIC)_|^LOGIN_HANDOFF_|^TRANSPORT_(RESOLVE|CONNECT)' "$capture_dir/project-isac-stack-probe.log" || true; } \
        > "$capture_dir/tctd-echo-checkpoints.txt"
fi
if (( sdk_local == 1 )); then
    if [[ ! -f $capture_dir/project-isac-stack-probe.log ]]; then
        echo "No new client shim log; launch stopped before instrumentation or the game was not launched." >&2
    elif ! grep -q '^SDK_LOCAL_ROUTE_READY ' "$capture_dir/project-isac-stack-probe.log"; then
        echo "SDK redirect did not report ready; this run does not establish local SDK routing." >&2
    elif ! grep -q '^SDK_HTTP route=session-create status=200 ' "$capture_dir/sdk-services.log"; then
        echo "SDK template changed, but no successful local session request was observed." >&2
    elif ! grep -q '^SDK_HTTP route=configuration status=200 ' "$capture_dir/sdk-services.log"; then
        echo "Local session sent; authenticated configuration fetch was not observed." >&2
    else
        echo "Local SDK session and configuration served; inspect handoff analysis for client acceptance."
    fi
fi
if [[ $selection == tctd-handoff && -f $capture_dir/project-isac-stack-probe.log ]]; then
    python3 "$project_dir/tools/analyze-login-handoff.py" \
        "$capture_dir/project-isac-stack-probe.log" --expected-sweep "$handoff_sweep" \
        > "$capture_dir/login-handoff-analysis.txt"
    if ! grep -q "^LOGIN_HANDOFF_CONFIG .*detail=sweep=$handoff_sweep," \
        "$capture_dir/project-isac-stack-probe.log"; then
        echo "WARNING: capture label and actual sweep mode are not confirmed to match; see analysis." >&2
    fi
elif [[ $selection == tctd-handoff ]]; then
    echo "No new client shim log; no handoff result can be inferred. Backend logs retained." \
        > "$capture_dir/login-handoff-analysis.txt"
fi
if (( tctd_tls_probe == 1 || tctd_remote_probe == 1 )) && \
    [[ -s $capture_dir/tctd-pc-27015.pcap ]]; then
    "$project_dir/tools/analyze-backend-pcap.py" \
        "$capture_dir/tctd-pc-27015.pcap" \
        > "$capture_dir/tctd-pc-metadata-analysis.txt"
fi
if (( tctd_cert_probe == 1 )) && [[ -f $capture_dir/project-isac-stack-probe.log ]]; then
    "$project_dir/tools/analyze-tctd-cert-probe.py" \
        "$capture_dir/project-isac-stack-probe.log" \
        > "$capture_dir/tctd-cert-analysis.txt"
fi
if (( tctd_validation_probe == 1 )) && [[ -f $capture_dir/project-isac-stack-probe.log ]]; then
    validation_analyzer_args=(
        "$capture_dir/project-isac-stack-probe.log"
    )
    if [[ -f $capture_dir/project-isac-code-probe.log ]]; then
        validation_analyzer_args+=(
            --code-log "$capture_dir/project-isac-code-probe.log"
        )
    fi
    "$project_dir/tools/analyze-tctd-validation-probe.py" \
        "${validation_analyzer_args[@]}" \
        > "$capture_dir/tctd-validation-analysis.txt"
fi
if (( tctd_accept_probe == 1 )) && \
    [[ -f $capture_dir/project-isac-stack-probe.log ]] && \
    [[ -f $capture_dir/tctd-pc-listener.log ]]; then
    "$project_dir/tools/analyze-tctd-local-accept.py" \
        "$capture_dir/project-isac-stack-probe.log" \
        "$capture_dir/tctd-pc-listener.log" \
        > "$capture_dir/tctd-local-accept-analysis.txt"
fi
if (( tctd_validator_code_probe == 1 )) && \
    [[ -f $capture_dir/project-isac-stack-probe.log ]] && \
    [[ -f $capture_dir/project-isac-code-probe.log ]]; then
    "$project_dir/tools/analyze-tctd-validator-code.py" \
        "$capture_dir/project-isac-stack-probe.log" \
        "$capture_dir/project-isac-code-probe.log" \
        --output-bin "$capture_dir/tctd-validator-function.bin" \
        > "$capture_dir/tctd-validator-analysis.txt"
fi
if (( tctd_state_watch_probe == 1 )) && \
    [[ -f $capture_dir/project-isac-stack-probe.log ]]; then
    "$project_dir/tools/analyze-tctd-state-watch.py" \
        "$capture_dir/project-isac-stack-probe.log" \
        > "$capture_dir/tctd-state-watch-analysis.txt"
fi
if (( tctd_owner_watch_probe == 1 )) && \
    [[ -f $capture_dir/project-isac-stack-probe.log ]]; then
    "$project_dir/tools/analyze-tctd-owner-watch.py" \
        "$capture_dir/project-isac-stack-probe.log" \
        > "$capture_dir/tctd-owner-watch-analysis.txt"
fi
if (( tctd_completion_probe == 1 )) && \
    [[ -f $capture_dir/project-isac-stack-probe.log ]] && \
    [[ -f $capture_dir/project-isac-code-probe.log ]]; then
    "$project_dir/tools/analyze-tctd-completion-probe.py" \
        "$capture_dir/project-isac-stack-probe.log" \
        --code-log "$capture_dir/project-isac-code-probe.log" \
        --output-bin "$capture_dir/tctd-completion-region.bin" \
        > "$capture_dir/tctd-completion-analysis.txt"
fi
if (( tctd_branch_probe == 1 )) && \
    [[ -f $capture_dir/project-isac-stack-probe.log ]]; then
    "$project_dir/tools/analyze-tctd-branch-probe.py" \
        "$capture_dir/project-isac-stack-probe.log" \
        > "$capture_dir/tctd-branch-analysis.txt"
fi
if (( tctd_chain_probe == 1 )) && \
    [[ -f $capture_dir/project-isac-stack-probe.log ]]; then
    chain_analyzer_args=(
        "$capture_dir/project-isac-stack-probe.log"
    )
    if [[ -f $capture_dir/project-isac-code-probe.log ]]; then
        chain_analyzer_args+=(
            --code-log "$capture_dir/project-isac-code-probe.log"
        )
    fi
    "$project_dir/tools/analyze-tctd-chain-probe.py" \
        "${chain_analyzer_args[@]}" \
        > "$capture_dir/tctd-chain-analysis.txt"
fi
if (( tctd_parser_code_probe == 1 )) && \
    [[ -f $capture_dir/project-isac-stack-probe.log ]] && \
    [[ -f $capture_dir/project-isac-code-probe.log ]]; then
    "$project_dir/tools/analyze-tctd-parser-code.py" \
        "$capture_dir/project-isac-stack-probe.log" \
        "$capture_dir/project-isac-code-probe.log" \
        --output-bin "$capture_dir/tctd-parser-function.bin" \
        > "$capture_dir/tctd-parser-analysis.txt"
fi
if (( tctd_cert_flow_probe == 1 )) && \
    [[ -f $capture_dir/project-isac-stack-probe.log ]]; then
    cert_flow_analyzer_args=(
        "$capture_dir/project-isac-stack-probe.log"
    )
    if [[ -f $capture_dir/project-isac-code-probe.log ]]; then
        cert_flow_analyzer_args+=(
            --code-log "$capture_dir/project-isac-code-probe.log"
        )
    fi
    "$project_dir/tools/analyze-tctd-cert-flow.py" \
        "${cert_flow_analyzer_args[@]}" \
        > "$capture_dir/tctd-cert-flow-analysis.txt"
fi

if [[ $selection == tctd-handoff ]]; then
    if [[ ! -f $capture_dir/project-isac-stack-probe.log ]] || \
        ! grep -q '^LOGIN_HANDOFF_READY ' "$capture_dir/project-isac-stack-probe.log"; then
        echo "WARNING: login-handoff probe did not report ready; see login-handoff-analysis.txt." >&2
    fi
elif ! grep -q '^client connected ' "$backend_log"; then
    echo "WARNING: Division never connected to the local backend." >&2
    echo "Verify the Steam wrapper launch option before retrying." >&2
fi

echo "Offline integration evidence complete: $capture_dir"
echo "Backend log: $capture_dir/local-backend.log"
if (( tctd_probe == 1 )); then
    echo "tctd-pc listener log: $capture_dir/tctd-pc-listener.log"
    if [[ -d ${private_capture_dir:-} ]]; then
        echo "Private client flight: $private_capture_dir"
    fi
fi
