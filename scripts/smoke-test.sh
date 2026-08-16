#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${project_root}"

./scripts/install-wolfssl.sh
docker compose up --detach --build --wait tpm
cmake --preset debug
cmake --build --preset debug
ctest --preset integration
