#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${project_root}"

if [[ ! -f third_party/wolftpm/CMakeLists.txt ]]; then
    git submodule update --init --recursive
fi

./scripts/install-wolfssl.sh
cmake --preset debug
cmake --build --preset debug
cmake --preset release
cmake --build --preset release

printf '\nSetup complete. The default runtime profile is full PQ.\n'
printf 'Start the v1.85/PQC fwTPM with:\n'
printf '  docker compose up --detach --build --wait tpm\n'
printf 'Then run PQ:\n'
printf '  ./build/debug/wolftpm_demo --crypto pq --iterations 10 --csv results/pq_transport.csv\n'
printf 'Or the same binary with the classical profile:\n'
printf '  ./build/debug/wolftpm_demo --crypto rsa --iterations 10 --csv results/rsa_transport.csv\n'
printf 'For a matched pair of experiments:\n'
printf '  ./scripts/run-comparison.sh 200 10 release\n'
