# wolfTPM TPM 2.0 v1.85 EK/AK attestation benchmark

This repository runs the same remote-attestation implementation with two runtime-selectable cryptographic profiles:

| profile | EK | AK / Quote | PCR bank |
|---|---|---|---|
| `--crypto pq` (default) | ML-KEM-768 | ML-DSA-65 | SHA-256 |
| `--crypto rsa` | RSA-2048 | RSASSA/SHA-256 | SHA-256 |

Only two TPM key objects are created for each run:

```text
EK  = primary under the Endorsement hierarchy
AK  = primary under the Owner hierarchy
```

The attestation flow is:

```text
Create EK
Create AK
MakeCredential(EK, AK Name)
ActivateCredential(AK, EK)
Read PCR 0..15
Quote(AK, nonce, PCR selection)
Verifier checks nonce + PCR digest + signature
```

`TPM2_MakeCredential` binds the credential to the AK Name while protecting it for the EK. `TPM2_ActivateCredential` then proves possession of both the AK and EK. The AK does not need to be a child of the EK for this protocol.

The important experimental property is that RSA and PQ are built into the same wolfSSL/wolfTPM binary stack. `--crypto` changes the key templates and signature verifier at runtime; it does not switch libraries, compiler settings, transport, or simulator.

## PCRs do not become larger because of PQ

The PQ migration changes the asymmetric cryptography, not the PCR bank. This project deliberately keeps the SHA-256 PCR bank fixed for both profiles. Therefore PCR 0..15 are still:

```text
16 PCRs * 32 bytes = 512 bytes
```

The code asks wolfTPM for the digest size of `PCR_BANK_ALG`, stores PCRs in a generic maximum-size buffer, and calculates the reported PCR payload from `PCR count * actual digest size`.

## Repository layout

```text
src/
  main.c                 orchestration only
  attestation.c          common EK + AK credential/PCR/Quote flow
  crypto_profile.c       RSA vs ML-KEM/ML-DSA key/template boundary
  verifier.c             RSA and ML-DSA software signature verification
  transport_trace.c      raw TPM command RTT + request/response sizes
  metrics.c              semantic payload sizes + software timings

third_party/
  wolftpm/               authoritative patched wolfTPM source

.cache/wolfssl/          downloaded/build wolfSSL cache
.local/                  locally installed PQ-enabled wolfSSL
```

The application compiles the pinned `third_party/wolftpm` submodule directly with `add_subdirectory()`, and Docker builds its fwTPM server from the same source.

Clone the complete project with:

```sh
git clone --recurse-submodules <repository-url>
```

For an existing clone, initialize wolfTPM with:

```sh
git submodule update --init --recursive
```

## First setup

```sh
./scripts/setup.sh
```

`setup.sh` initializes the wolfTPM submodule when necessary, downloads wolfSSL 5.9.2 into `.cache/wolfssl`, and installs a PQ-enabled build into `.local`.

## Build and start the simulator

The Docker fwTPM is built from the same `third_party/wolftpm` source and is compiled with v1.85 ML-DSA/ML-KEM support.

```sh
docker compose up --detach --build --wait tpm

cmake --preset release
cmake --build --preset release
```

For a clean simulator state:

```sh
docker compose down --volumes
docker compose up --detach --build --wait tpm
```

## Run full PQ

PQ is the default:

```sh
./build/release/wolftpm_demo \
    --crypto pq \
    --warmup 10 \
    --iterations 200 \
    --csv results/pq_transport.csv \
    --quiet
```

Profile:

```text
EK    ML-KEM-768
AK    ML-DSA-65
Quote ML-DSA-65
PCR   SHA-256, PCR 0..15
```

The ML-KEM EK retains the standard EK object attributes and endorsement policy. The ML-DSA AK retains the restricted signing/attestation attributes of the classical AIK template. The AK is created directly as a primary key in the Owner hierarchy.

## Switch to classical RSA

No rebuild is needed:

```sh
./build/release/wolftpm_demo \
    --crypto rsa \
    --warmup 10 \
    --iterations 200 \
    --csv results/rsa_transport.csv \
    --quiet
```

The RSA AK also uses the AIK template and is created directly as an Owner hierarchy primary key.

## Run a matched RSA/PQ comparison

```sh
./scripts/run-comparison.sh 200 10 release
```

This writes:

```text
results/pq_transport.csv
results/rsa_transport.csv
```

Both runs use the same binary and simulator build.

## What is timed?

The patched wolfTPM has one measurement hook around
`INTERNAL_SEND_COMMAND(ctx, packet)`:

```text
application / wrapper setup
        |
        | TPM command marshaling
        v
serialized TPM request
        |
        | START CLOCK_MONOTONIC_RAW
        v
INTERNAL_SEND_COMMAND
    socket send
    fwTPM processing
    socket receive
        |
        | STOP
        v
raw TPM response
        |
        | TPM2_Packet_Parse(...)
        v
application
```

The primary `rtt_ns` metric excludes application-side structure setup, client command marshaling, TPM response parsing and external quote verification. It still includes the fixed local socket/Docker path, so it is TPM command round-trip latency at the serialized transport boundary, not pure cryptographic CPU time.

Each raw sample contains:

```text
run
profile
semantic phase
TPM command code/name
TPM response code
serialized request bytes
serialized response bytes
round-trip ns
```

The response length is read from the TPM response header (`responseSize`).

## Semantic payload output

The application separately prints:

```text
EK public structure
AK public structure
credential blob
credential secret
nonce
PCR count + digest size + total PCR payload
TPMS_ATTEST quote bytes
signature bytes
attestation response payload
```

Semantic sizes show the protocol artifacts, while transport sizes show what the actual TPM command channel carries.

## EK/AK implementation boundary

`src/crypto_profile.c` is the only file responsible for TPM key construction:

```text
RSA profile:
  RSA-2048 EK -> Endorsement hierarchy primary
  RSA-2048 AK -> Owner hierarchy primary using the AIK template
  Quote scheme -> RSASSA/SHA-256

PQ profile:
  ML-KEM-768 EK -> Endorsement hierarchy primary
  ML-DSA-65 AK -> Owner hierarchy primary using AIK attributes
  Quote scheme -> TPM_ALG_MLDSA
```

The PQ path uses wolfTPM's v1.85 generic template/create wrappers because the older convenience APIs are RSA/ECC-oriented.

`src/verifier.c` dispatches by `TPMT_SIGNATURE.sigAlg`. RSA uses the existing RSASSA/SHA-256 verifier. ML-DSA imports the TPM AK's raw ML-DSA public key into wolfCrypt and verifies the raw quote attestation bytes with an empty FIPS 204 context.

## Editing the patched wolfTPM

Edit anything under:

```text
third_party/wolftpm/src/
third_party/wolftpm/wolftpm/
```

and rebuild:

```sh
./scripts/rebuild-wolftpm.sh release
```

Rebuild the Docker `tpm` image as well after changing fwTPM server code.

## Tests

With the simulator running:

```sh
ctest --preset integration
```

The integration preset executes one full-PQ flow and one classical RSA flow.

## Include formatting

`.clang-format` uses `SortIncludes: Never`. Keep it that way because wolfTPM / wolfSSL configuration headers can be include-order-sensitive.

## Pinned versions

`.env` pins wolfSSL 5.9.2. The wolfTPM revision is the revision supplied in `third_party/wolftpm`.
