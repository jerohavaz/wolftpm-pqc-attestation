# syntax=docker/dockerfile:1.7

ARG UBUNTU_VERSION=24.04

FROM ubuntu:${UBUNTU_VERSION} AS dependencies
ARG DEBIAN_FRONTEND=noninteractive
ARG WOLFSSL_VERSION=5.9.2

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        clang \
        cmake \
        git \
        ninja-build \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "v${WOLFSSL_VERSION}-stable" \
        https://github.com/wolfSSL/wolfssl.git /src/wolfssl \
    && cmake -S /src/wolfssl -B /build/wolfssl -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER=clang \
        -DCMAKE_C_FLAGS=-DWC_RSA_NO_PADDING \
        -DCMAKE_INSTALL_PREFIX=/opt/wolftpm \
        -DBUILD_SHARED_LIBS=ON \
        -DWOLFSSL_CRYPT_TESTS=no \
        -DWOLFSSL_EXAMPLES=no \
        -DWOLFSSL_KEYGEN=yes \
        -DWOLFSSL_PKCALLBACKS=yes \
        -DWOLFSSL_MLDSA=yes \
        -DWOLFSSL_MLKEM=yes \
        -DWOLFSSL_TPM=yes \
    && cmake --build /build/wolfssl --parallel \
    && cmake --install /build/wolfssl

# Docker builds the exact patched wolfTPM source supplied in third_party.
COPY third_party/wolftpm /src/wolftpm
RUN test -f /src/wolftpm/CMakeLists.txt \
    || (echo 'wolfTPM submodule is missing; initialize it before building' >&2; exit 1)

RUN cmake -S /src/wolftpm -B /build/wolftpm -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER=clang \
        -DCMAKE_INSTALL_PREFIX=/opt/wolftpm \
        -DCMAKE_PREFIX_PATH=/opt/wolftpm \
        -DBUILD_SHARED_LIBS=ON \
        -DWITH_WOLFSSL=/opt/wolftpm \
        -DWOLFTPM_EXAMPLES=no \
        -DWOLFTPM_FWTPM=yes \
        -DWOLFTPM_INTERFACE=SWTPM \
        -DCMAKE_C_FLAGS="-D_DEFAULT_SOURCE -DWOLFTPM_V185 -DWOLFTPM_PQC -DWOLFTPM_MLDSA -DWOLFTPM_MLKEM" \
    && cmake --build /build/wolftpm --parallel \
    && cmake --install /build/wolftpm \
    && install -m 0644 /src/wolftpm/wolftpm/tpm2_metrics.h \
        /opt/wolftpm/include/wolftpm/tpm2_metrics.h

FROM ubuntu:${UBUNTU_VERSION} AS simulator
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        netcat-openbsd \
        socat \
        tini \
    && rm -rf /var/lib/apt/lists/*
COPY --from=dependencies /opt/wolftpm /opt/wolftpm
COPY docker/fwtpm-entrypoint.sh /usr/local/bin/fwtpm-entrypoint
RUN chmod 0755 /usr/local/bin/fwtpm-entrypoint \
    && groupadd --system tpm \
    && useradd --system --gid tpm --home-dir /var/lib/wolftpm tpm \
    && mkdir -p /var/lib/wolftpm \
    && chown tpm:tpm /var/lib/wolftpm
ENV LD_LIBRARY_PATH=/opt/wolftpm/lib
WORKDIR /var/lib/wolftpm
USER tpm
EXPOSE 2321 2322
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/fwtpm-entrypoint"]

FROM dependencies AS app-build
WORKDIR /src/app
COPY . .
RUN cmake --preset release \
        -DWOLFTPM_WOLFSSL_PREFIX=/opt/wolftpm \
        -DCMAKE_PREFIX_PATH=/opt/wolftpm \
    && cmake --build --preset release

FROM ubuntu:${UBUNTU_VERSION} AS app
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install --yes --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system app \
    && useradd --system --gid app --home-dir /nonexistent app
COPY --from=dependencies /opt/wolftpm /opt/wolftpm
COPY --from=app-build /src/app/build/release/wolftpm_demo /usr/local/bin/wolftpm_demo
ENV LD_LIBRARY_PATH=/opt/wolftpm/lib \
    TPM2_SWTPM_HOST=tpm \
    TPM2_SWTPM_PORT=2321
USER app
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/wolftpm_demo"]

FROM dependencies AS dev
ARG DEBIAN_FRONTEND=noninteractive
ARG USER_UID=1000
ARG USER_GID=1000
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        clang-format \
        clangd \
        gdb \
        sudo \
        valgrind \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid "${USER_GID}" vscode \
    && useradd --uid "${USER_UID}" --gid "${USER_GID}" --create-home --shell /bin/bash vscode \
    && printf 'vscode ALL=(root) NOPASSWD:ALL\n' >/etc/sudoers.d/vscode \
    && chmod 0440 /etc/sudoers.d/vscode
ENV LD_LIBRARY_PATH=/opt/wolftpm/lib \
    TPM2_SWTPM_HOST=tpm \
    TPM2_SWTPM_PORT=2321
WORKDIR /workspace
USER vscode
CMD ["sleep", "infinity"]
