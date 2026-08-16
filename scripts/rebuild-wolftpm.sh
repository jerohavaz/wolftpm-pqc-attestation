#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_type="${1:-debug}"

if [[ ! -f "${project_root}/third_party/wolftpm/CMakeLists.txt" ]]; then
    printf 'wolfTPM submodule is missing. Run:\n' >&2
    printf '  git submodule update --init --recursive\n' >&2
    exit 1
fi

# wolfTPM is a normal CMake subproject. Reconfiguring + building the app is
# enough; Ninja rebuilds only the wolfTPM objects affected by edits.
cmake --preset "${build_type}"
cmake --build --preset "${build_type}"

printf 'Rebuilt app and patched wolfTPM from:\n  %s\n' \
    "${project_root}/third_party/wolftpm"
