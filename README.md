# wolfTPM PQC Attestation

Minimal benchmark for comparing RSA TPM 2.0 attestation with ML-KEM-768 / ML-DSA-65 using wolfTPM and fwTPM.

## Clone

```bash
git clone --recurse-submodules git@github.com:jerohavaz/wolftpm-pqc-attestation.git
cd wolftpm-pqc-attestation
```

If the repository was cloned without submodules:

```bash
git submodule update --init --recursive
```

## Setup

Requires Git, Docker, Python 3, CMake, Ninja, and Clang.

```bash
./scripts/setup.sh
```

The setup script builds the local wolfSSL dependency under `attestation/.local`.

## Build the attestation client

```bash
cd attestation
cmake --preset debug
cmake --build --preset debug
```

The executable is written to:

```text
attestation/build/debug/attestation_bench
```

## Run the benchmark

From the repository root:

```bash
./scripts/run-benchmark.sh
```
