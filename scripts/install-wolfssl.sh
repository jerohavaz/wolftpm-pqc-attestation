#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${project_root}/.env"

install_prefix="${WOLFSSL_PREFIX:-${project_root}/.local}"
cache_root="${WOLFSSL_CACHE_DIR:-${project_root}/.cache/wolfssl}"
source_dir="${cache_root}/source"
build_dir="${cache_root}/build"
jobs="${BUILD_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '2')}"
tag="v${WOLFSSL_VERSION}-stable"

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'Required tool not found: %s\n' "$1" >&2
        exit 1
    fi
}

for tool in cmake ninja clang git; do
    require_tool "${tool}"
done

if [[ ! -f "${project_root}/third_party/wolftpm/CMakeLists.txt" ]]; then
    printf 'wolfTPM submodule is missing. Run:\n' >&2
    printf '  git submodule update --init --recursive\n' >&2
    exit 1
fi

mkdir -p "${cache_root}" "${install_prefix}"

if [[ ! -d "${source_dir}/.git" ]]; then
    if [[ -e "${source_dir}" ]]; then
        printf 'Refusing to overwrite non-git wolfSSL source: %s\n' \
            "${source_dir}" >&2
        exit 1
    fi
    git clone --depth 1 --branch "${tag}" \
        https://github.com/wolfSSL/wolfssl.git "${source_dir}"
elif [[ "$(git -C "${source_dir}" describe --tags --exact-match 2>/dev/null || true)" != "${tag}" ]]; then
    git -C "${source_dir}" fetch --depth 1 origin \
        "refs/tags/${tag}:refs/tags/${tag}"
    git -C "${source_dir}" checkout --detach "${tag}"
fi

cmake -S "${source_dir}" -B "${build_dir}" -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_C_FLAGS=-DWC_RSA_NO_PADDING \
    -DCMAKE_INSTALL_PREFIX="${install_prefix}" \
    -DBUILD_SHARED_LIBS=ON \
    -DWOLFSSL_CRYPT_TESTS=no \
    -DWOLFSSL_EXAMPLES=no \
    -DWOLFSSL_KEYGEN=yes \
    -DWOLFSSL_PKCALLBACKS=yes \
    -DWOLFSSL_MLDSA=yes \
    -DWOLFSSL_MLKEM=yes \
    -DWOLFSSL_TPM=yes
cmake --build "${build_dir}" --parallel "${jobs}"
cmake --install "${build_dir}"

printf '\nInstalled PQ-enabled wolfSSL %s under:\n  %s\n' \
    "${WOLFSSL_VERSION}" "${install_prefix}"
printf 'wolfTPM is built directly from:\n  %s\n' \
    "${project_root}/third_party/wolftpm"
