#ifndef APP_TYPES_H
#define APP_TYPES_H

#include <stdint.h>

#include <wolftpm/tpm2_wrap.h>

#define NONCE_SIZE 32U
#define CREDENTIAL_SIZE 32U

/* PCRs are independent from the RSA -> PQ migration. Keep SHA-256 as the
 * controlled measurement bank, but derive its digest size at runtime instead
 * of assuming that every PCR bank is 32 bytes. */
#define PCR_BANK_ALG TPM_ALG_SHA256
#define PCR_FIRST_INDEX 0
#define PCR_LAST_INDEX 15
#define PCR_COUNT (PCR_LAST_INDEX - PCR_FIRST_INDEX + 1)
#define PCR_MAX_DIGEST_SIZE 64U

typedef enum CryptoMode { CRYPTO_MODE_RSA = 0, CRYPTO_MODE_PQ = 1 } CryptoMode;

/* Application-side timing only. TPM command timing is captured at the
 * serialized transport boundary inside the patched wolfTPM library. */
typedef struct PerformanceSample {
    uint64_t verifier_ns;
    uint64_t full_flow_ns;
} PerformanceSample;

typedef struct SizeSample {
    const char *profile_name;
    const char *ek_algorithm;
    const char *srk_algorithm;
    const char *ak_algorithm;
    const char *quote_algorithm;

    TPMI_ALG_HASH pcr_bank_alg;
    uint32_t pcr_count;
    uint32_t pcr_digest_bytes;

    uint32_t ek_public_bytes;
    uint32_t srk_public_bytes;
    uint32_t ak_public_bytes;
    uint32_t credential_blob_bytes;
    uint32_t credential_secret_bytes;
    uint32_t nonce_bytes;
    uint32_t pcr_payload_bytes;
    uint32_t quote_attest_bytes;
    uint32_t quote_signature_bytes;
    uint32_t attestation_response_bytes;
} SizeSample;

typedef struct AttestationContext {
    WOLFTPM2_DEV dev;
    WOLFTPM2_CAPS caps;
    WOLFTPM2_KEY ek;
    WOLFTPM2_KEY srk;
    WOLFTPM2_KEY ak;
    WOLFTPM2_SESSION ek_policy_activate;

    MakeCredential_In make_in;
    MakeCredential_Out make_out;
    ActivateCredential_In activate_in;
    ActivateCredential_Out activate_out;
    Quote_In quote_in;
    Quote_Out quote_out;

    byte credential[CREDENTIAL_SIZE];
    byte nonce[NONCE_SIZE];
    byte pcr_values[PCR_COUNT][PCR_MAX_DIGEST_SIZE];
    int pcr_digest_size;

    int initialized;
} AttestationContext;

#endif
