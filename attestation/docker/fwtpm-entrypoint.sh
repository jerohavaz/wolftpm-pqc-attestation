#!/usr/bin/env bash
set -euo pipefail

internal_command_port=32321
internal_platform_port=32322
child_pids=()
ready_file=/tmp/fwtpm-ready

# Benchmark output is written to a host bind mount by the unprivileged TPM user.
# Do not leave host-side result files owned as read-only artifacts.
umask 000

stop_children() {
    rm -f "${ready_file}"
    if ((${#child_pids[@]} > 0)); then
        kill "${child_pids[@]}" 2>/dev/null || true
        wait "${child_pids[@]}" 2>/dev/null || true
    fi
}

trap 'stop_children; exit 143' TERM INT
rm -f "${ready_file}"

/opt/wolftpm/bin/fwtpm_server \
    --port "${internal_command_port}" \
    --platform-port "${internal_platform_port}" \
    "$@" &
child_pids+=("$!")

for _ in $(seq 1 100); do
    if nc -z 127.0.0.1 "${internal_command_port}"; then
        break
    fi
    sleep 0.1
done

if ! nc -z 127.0.0.1 "${internal_command_port}"; then
    printf 'fwTPM server did not become ready\n' >&2
    stop_children
    exit 1
fi

# fwTPM intentionally binds to loopback. Relay both sockets so Compose peers and
# host port publishing can reach it without carrying a source patch.
socat TCP-LISTEN:2321,bind=0.0.0.0,reuseaddr,fork TCP:127.0.0.1:"${internal_command_port}" &
child_pids+=("$!")
socat TCP-LISTEN:2322,bind=0.0.0.0,reuseaddr,fork TCP:127.0.0.1:"${internal_platform_port}" &
child_pids+=("$!")
touch "${ready_file}"

set +e
wait -n "${child_pids[@]}"
status=$?
set -e
stop_children
exit "${status}"
