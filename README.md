# wolfTPM TPM 2.0 v1.85 full-PQ attestation benchmark

This repository runs the **same remote-attestation implementation** with two
runtime-selectable cryptographic profiles:

| profile | EK | storage parent (SRK) | AK / Quote | PCR bank |
|---|---|---|---|---|
| `--crypto pq` (default) | ML-KEM-768 | ML-KEM-768 | ML-DSA-65 | SHA-256 |
| `--crypto rsa` | RSA-2048 | RSA-2048 | RSASSA/SHA-256 | SHA-256 |

The logical protocol is identical in both profiles:

```text
EK -> SRK -> AK
   -> MakeCredential
   -> ActivateCredential
   -> Read PCR 0..15
   -> Quote(nonce, PCR selection)
   -> verifier checks nonce + PCR digest + signature
```

The important experimental property is that **RSA and PQ are built into the
same wolfSSL/wolfTPM binary stack**. `--crypto` changes the key templates and
signature verifier at runtime; it does not switch libraries, compiler settings,
transport, or simulator.

## PCRs do not become larger because of PQ

The PQ migration changes the asymmetric cryptography, not the PCR bank. This
project deliberately keeps the SHA-256 PCR bank fixed for both profiles.
Therefore PCR 0..15 are still:

```text
16 PCRs * 32 bytes = 512 bytes
```

The code no longer assumes `32` internally. It asks wolfTPM for the digest size
of `PCR_BANK_ALG`, stores PCRs in a generic maximum-size buffer, and calculates
the reported PCR payload from `PCR count * actual digest size`. That prevents
the payload accounting from silently becoming wrong if a different bank is
chosen later.

## Repository layout

```text
src/
  main.c                 orchestration only
  attestation.c          common EK -> credential -> PCR -> Quote flow
  crypto_profile.c       RSA vs ML-KEM/ML-DSA key/template boundary
  verifier.c             RSA and ML-DSA software signature verification
  transport_trace.c      raw TPM command RTT + request/response sizes
  metrics.c              semantic payload sizes + software timings

third_party/
  wolftpm/               authoritative patched wolfTPM source

.cache/wolfssl/          downloaded/build wolfSSL cache
.local/                  locally installed PQ-enabled wolfSSL
```

There are no bootstrap patches or source-rewriting scripts. The application
compiles the pinned `third_party/wolftpm` submodule directly with
`add_subdirectory()`, and Docker builds its fwTPM server from the same source.

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

`setup.sh` initializes the wolfTPM submodule when necessary,
downloads wolfSSL 5.9.2 into `.cache/wolfssl`, and installs a PQ-enabled build
into `.local`. It never downloads or modifies wolfTPM.

The host application and patched wolfTPM are then configured together by the
top-level CMake project with TPM 2.0 v1.85/PQC macros enabled.

## Build and start the simulator

The Docker fwTPM is built from the **same `third_party/wolftpm` source** and is
compiled with v1.85 ML-DSA/ML-KEM support.

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
SRK   ML-KEM-768
AK    ML-DSA-65
Quote ML-DSA-65
PCR   SHA-256, PCR 0..15
```

The ML-KEM EK retains the standard EK object attributes and endorsement policy.
The ML-KEM SRK retains the classical storage-parent attributes. The ML-DSA AK
retains the restricted signing/attestation attributes of the classical AIK.
Only the asymmetric algorithm-specific portions of those templates are changed.

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

Thus the primary `rtt_ns` metric excludes application-side structure setup,
client command marshaling, TPM response parsing and external quote verification.
It still includes the fixed local socket/Docker path, so call it **TPM command
round-trip latency at the serialized transport boundary**, not pure cryptographic
CPU time.

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

The response length is read from the TPM response header (`responseSize`), not
from wolfTPM's receive-buffer capacity.

## Semantic payload output

The application separately prints sizes that are useful for the migration
analysis:

```text
EK public structure
SRK public structure
AK public structure
credential blob
credential secret
nonce
PCR count + digest size + total PCR payload
TPMS_ATTEST quote bytes
signature bytes
attestation response payload
```

Do not confuse these with the transport request/response sizes. Both are useful:
semantic sizes show the protocol artifacts, while transport sizes show what the
actual TPM command channel carries.

## Full-PQ implementation boundary

`src/crypto_profile.c` is the only file responsible for TPM key construction:

```text
RSA profile:
  wolfTPM convenience RSA EK/SRK/AIK wrappers

PQ profile:
  ML-KEM-768 EK template -> Endorsement hierarchy primary
  ML-KEM-768 SRK template -> Owner hierarchy primary
  ML-DSA-65 AIK template -> child of ML-KEM SRK
  Quote scheme -> TPM_ALG_MLDSA
```

The PQ path uses wolfTPM's v1.85 generic template/create wrappers because the
older `wolfTPM2_CreateEK`, `wolfTPM2_CreateSRK` and `wolfTPM2_CreateAndLoadAIK`
convenience APIs are RSA/ECC-oriented.

`src/verifier.c` dispatches by `TPMT_SIGNATURE.sigAlg`. RSA uses the existing
RSASSA/SHA-256 verifier. ML-DSA imports the TPM AK's raw ML-DSA public key into
wolfCrypt and verifies the raw quote attestation bytes with an empty FIPS 204
context.

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

Ninja recompiles the changed wolfTPM objects and relinks the application. No
host-side wolfTPM install step or patch application exists. Rebuild the Docker
`tpm` image as well after changing fwTPM server code.

## Tests

With the simulator running:

```sh
ctest --preset integration
```

The integration preset executes one full-PQ flow and one classical RSA flow.

## Include formatting

`.clang-format` uses `SortIncludes: Never`. Keep it that way because wolfTPM /
wolfSSL configuration headers can be include-order-sensitive.

## Pinned versions

`.env` pins wolfSSL 5.9.2. The wolfTPM revision is the revision supplied in
`third_party/wolftpm`.
