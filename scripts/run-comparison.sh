#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${project_root}"

iterations="${1:-200}"
warmup="${2:-10}"
build_type="${3:-release}"
binary="${project_root}/build/${build_type}/wolftpm_demo"
results_dir="${project_root}/results"

if [[ ! -x "${binary}" ]]; then
    printf 'Binary not found: %s\nBuild it first with cmake --preset %s && cmake --build --preset %s\n' \
        "${binary}" "${build_type}" "${build_type}" >&2
    exit 1
fi

mkdir -p "${results_dir}"

printf '\n=== Full PQ: ML-KEM-768 / ML-DSA-65 ===\n'
"${binary}" \
    --crypto pq \
    --warmup "${warmup}" \
    --iterations "${iterations}" \
    --csv "${results_dir}/pq_transport.csv" \
    --quiet

printf '\n=== Classical RSA ===\n'
"${binary}" \
    --crypto rsa \
    --warmup "${warmup}" \
    --iterations "${iterations}" \
    --csv "${results_dir}/rsa_transport.csv" \
    --quiet

printf '\nRaw transport CSV files:\n'
printf '  %s\n' "${results_dir}/pq_transport.csv"
printf '  %s\n' "${results_dir}/rsa_transport.csv"
