#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

source .env

iterations="${MEASURED_RUNS:-200}"
warmup="${WARMUP_RUNS:-10}"

while (($#)); do
    case "$1" in
        --iterations) iterations="$2"; shift 2 ;;
        --warmup) warmup="$2"; shift 2 ;;
        -h|--help)
            printf 'Usage: %s [--iterations N] [--warmup N]\n' "$0"
            exit 0 ;;
        *) printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
    esac
done

[[ "${iterations}" =~ ^[1-9][0-9]*$ ]] || { echo 'iterations must be > 0' >&2; exit 2; }
[[ "${warmup}" =~ ^[0-9]+$ ]] || { echo 'warmup must be >= 0' >&2; exit 2; }

mkdir -p results/raw
cleanup() { docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

docker compose build tpm app

run_profile() {
    local profile="$1"
    local result_dir="${root}/results/raw/${profile}"

    source "benchmark/profiles/${profile}.env"
    export PROFILE_SLUG CRYPTO_PROFILE
    export MEASURED_RUNS="${iterations}" WARMUP_RUNS="${warmup}"

    docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
    rm -rf "${result_dir}"
    install -d -m 0777 "${result_dir}"

    printf '\n[%s] warmup=%s measured=%s\n' "${profile^^}" "${warmup}" "${iterations}"
    docker compose up -d --wait tpm
    docker compose run --rm --no-deps app

    # fwTPM stores samples in memory and writes fwtpm_internal.csv on shutdown.
    docker compose stop --timeout 30 tpm

    # Bind-mounted files are created by container users. Make them writable by the host only after measurement has finished, so this cannot affect timing.
    docker compose run --rm --no-deps --user 0 --entrypoint sh app \
        -c 'chmod -R a+rwX /results' >/dev/null

    for file in client_transport.csv client_runs.csv client_metadata.csv fwtpm_internal.csv; do
        [[ -s "${result_dir}/${file}" ]] || {
            printf 'missing output: %s/%s\n' "${result_dir}" "${file}" >&2
            exit 1
        }
    done

    docker compose down --volumes --remove-orphans >/dev/null
}

run_profile rsa
run_profile pq
"${root}/scripts/analyze.sh"

printf '\ndone\n  raw:      results/raw/{rsa,pq}/\n  analysis: results/analysis/\n'
