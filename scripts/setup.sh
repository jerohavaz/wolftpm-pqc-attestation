#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

trap 'printf "setup failed at line %d: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR

if [[ ! -f .env ]]; then
    printf 'missing .env\n' >&2
    exit 1
fi

source .env

: "${WOLFSSL_COMMIT:?WOLFSSL_COMMIT is not set}"

if [[ ! "${WOLFSSL_COMMIT}" =~ ^[0-9a-fA-F]{40}$ ]]; then
    printf 'WOLFSSL_COMMIT must be a full 40-character commit SHA\n' >&2
    exit 1
fi

for tool in git docker python3 cmake ninja clang; do
    command -v "${tool}" >/dev/null 2>&1 || {
        printf 'missing tool: %s\n' "${tool}" >&2
        exit 1
    }
done

docker compose version >/dev/null

printf 'initializing submodules...\n'
git submodule update --init --recursive

if [[ ! -f attestation/third_party/wolftpm/CMakeLists.txt ]]; then
    printf 'wolfTPM submodule is missing or invalid\n' >&2
    exit 1
fi

#
# wolfSSL
#

prefix="${root}/attestation/.local"
cache="${root}/attestation/.cache/wolfssl"
src="${cache}/source"
build="${cache}/build"
commit_file="${prefix}/.wolfssl-commit"

mkdir -p "${cache}" "${prefix}"

installed_commit=""

if [[ -f "${commit_file}" ]]; then
    installed_commit="$(cat "${commit_file}")"
fi

wolfssl_config="$(
    find "${prefix}" \
        -type f \
        \( -name 'wolfssl-config.cmake' -o -name 'wolfsslConfig.cmake' \) \
        -print -quit 2>/dev/null || true
)"

if [[ -z "${wolfssl_config}" || "${installed_commit}" != "${WOLFSSL_COMMIT}" ]]; then
    printf 'building wolfSSL at commit %s...\n' "${WOLFSSL_COMMIT}"

    if [[ ! -d "${src}/.git" ]]; then
        rm -rf "${src}"
        git init "${src}"
        git -C "${src}" remote add origin https://github.com/wolfSSL/wolfssl.git
    fi

    git -C "${src}" fetch --depth 1 origin "${WOLFSSL_COMMIT}"
    git -C "${src}" checkout --detach FETCH_HEAD

    actual_commit="$(git -C "${src}" rev-parse HEAD)"

    if [[ "${actual_commit}" != "${WOLFSSL_COMMIT}" ]]; then
        printf 'wolfSSL commit mismatch: expected %s, got %s\n' \
            "${WOLFSSL_COMMIT}" "${actual_commit}" >&2
        exit 1
    fi

    rm -rf "${build}"
    rm -rf "${prefix}"

    mkdir -p "${prefix}"

    cmake \
        -S "${src}" \
        -B "${build}" \
        -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER=clang \
        -DCMAKE_C_FLAGS=-DWC_RSA_NO_PADDING \
        -DCMAKE_INSTALL_PREFIX="${prefix}" \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DBUILD_SHARED_LIBS=ON \
        -DWOLFSSL_CRYPT_TESTS=no \
        -DWOLFSSL_EXAMPLES=no \
        -DWOLFSSL_KEYGEN=yes \
        -DWOLFSSL_PKCALLBACKS=yes \
        -DWOLFSSL_MLDSA=yes \
        -DWOLFSSL_MLKEM=yes \
        -DWOLFSSL_TPM=yes

    cmake --build "${build}" --parallel
    cmake --install "${build}"

    printf '%s\n' "${WOLFSSL_COMMIT}" > "${commit_file}"
else
    printf 'wolfSSL already installed at commit %s\n' "${WOLFSSL_COMMIT}"
fi

wolfssl_config="$(
    find "${prefix}" \
        -type f \
        \( -name 'wolfssl-config.cmake' -o -name 'wolfsslConfig.cmake' \) \
        -print -quit 2>/dev/null || true
)"

if [[ -z "${wolfssl_config}" ]]; then
    printf 'wolfSSL installation failed: CMake package config not found under %s\n' \
        "${prefix}" >&2
    exit 1
fi

printf 'wolfSSL package: %s\n' "${wolfssl_config}"

#
# Python analysis environment
#

printf 'setting up Python analysis environment...\n'

python3 -m venv analysis/.venv
analysis/.venv/bin/python -m pip install -q --upgrade pip
analysis/.venv/bin/python -m pip install -q -r analysis/requirements.txt

#
# Configure and build attestation
#

printf 'configuring attestation...\n'

(
    cd attestation

    cmake --preset debug \
        -DCMAKE_PREFIX_PATH="${prefix}" \
        -DWOLFTPM_WOLFSSL_PREFIX="${prefix}"

    cmake --build --preset debug --parallel
)

#
# Docker images
#

printf 'building Docker images...\n'
docker compose build tpm app

printf '\nsetup complete\n'
printf '\n'
printf 'local debug build:\n'
printf '  cd attestation\n'
printf '  cmake --build --preset debug\n'
printf '\n'
printf 'local release build:\n'
printf '  cd attestation\n'
printf '  cmake --preset release \\\n'
printf '    -DCMAKE_PREFIX_PATH=.local \\\n'
printf '    -DWOLFTPM_WOLFSSL_PREFIX=.local\n'
printf '  cmake --build --preset release\n'
printf '\n'
printf 'run benchmark:\n'
printf '  ./scripts/run-benchmark.sh\n'