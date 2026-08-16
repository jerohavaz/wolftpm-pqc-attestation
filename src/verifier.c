#include "verifier.h"

#include <stdint.h>
#include <stdio.h>

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/types.h>
#include "wolftpm/tpm2_types.h"
#ifdef WOLFSSL_HAVE_MLDSA
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#endif

#include "app_types.h"

static const byte kSha256DigestInfoPrefix[] = {0x30,
                                               0x31,
                                               0x30,
                                               0x0d,
                                               0x06,
                                               0x09,
                                               0x60,
                                               0x86,
                                               0x48,
                                               0x01,
                                               0x65,
                                               0x03,
                                               0x04,
                                               0x02,
                                               0x01,
                                               0x05,
                                               0x00,
                                               0x04,
                                               0x20};

static int recompute_pcr_digest(const TPML_PCR_SELECTION *selection,
                                byte pcr_values[PCR_COUNT][PCR_MAX_DIGEST_SIZE],
                                TPMI_ALG_HASH pcr_bank_alg,
                                int pcr_digest_size,
                                byte out[PCR_MAX_DIGEST_SIZE]) {
    wc_Sha256 sha;
    int rc;
    int byte_index;
    int bit;

    /* This experiment intentionally keeps the PCR bank fixed at SHA-256 for
     * both classical and PQ profiles. The storage is generic-sized so the
     * payload accounting is not hard-coded to 32-byte PCRs. */
    if (pcr_bank_alg != TPM_ALG_SHA256 || pcr_digest_size != TPM_SHA256_DIGEST_SIZE)
        return TPM_RC_FAILURE;

    if (selection->count != 1U || selection->pcrSelections[0].hash != pcr_bank_alg) {
        fprintf(stderr,
                "Quote verification: unexpected PCR selection "
                "(count=%u, hash=0x%x)\n",
                (unsigned)selection->count,
                (unsigned)selection->pcrSelections[0].hash);
        return TPM_RC_FAILURE;
    }

    rc = wc_InitSha256(&sha);
    if (rc != 0)
        return rc;

    for (byte_index = 0; byte_index < selection->pcrSelections[0].sizeofSelect; ++byte_index) {
        byte mask = selection->pcrSelections[0].pcrSelect[byte_index];

        for (bit = 0; bit < 8; ++bit) {
            int pcr;

            if ((mask & (1U << bit)) == 0U)
                continue;

            pcr = (byte_index * 8) + bit;
            if (pcr < PCR_FIRST_INDEX || pcr > PCR_LAST_INDEX) {
                wc_Sha256Free(&sha);
                return TPM_RC_FAILURE;
            }

            rc = wc_Sha256Update(&sha, pcr_values[pcr - PCR_FIRST_INDEX], (word32)pcr_digest_size);
            if (rc != 0) {
                wc_Sha256Free(&sha);
                return rc;
            }
        }
    }

    rc = wc_Sha256Final(&sha, out);
    wc_Sha256Free(&sha);
    return rc;
}

static int verify_rsassa_sha256(const WOLFTPM2_KEY *ak,
                                const TPM2B_ATTEST *quoted,
                                const TPMT_SIGNATURE *signature) {
    RsaKey rsa;
    byte digest[WC_SHA256_DIGEST_SIZE];
    byte expected[sizeof(kSha256DigestInfoPrefix) + WC_SHA256_DIGEST_SIZE];
    byte exponent_bytes[4];
    byte verified[512];
    word32 exponent;
    int exponent_size;
    int verified_size;
    int rc;
    const TPM2B_PUBLIC_KEY_RSA *modulus;
    const TPM2B_PUBLIC_KEY_RSA *sig;

    if (ak->pub.publicArea.type != TPM_ALG_RSA || signature->sigAlg != TPM_ALG_RSASSA ||
        signature->signature.rsassa.hash != TPM_ALG_SHA256)
        return TPM_RC_SIGNATURE;

    rc = wc_Sha256Hash(quoted->attestationData, quoted->size, digest);
    if (rc != 0)
        return rc;

    modulus = &ak->pub.publicArea.unique.rsa;
    sig = &signature->signature.rsassa.sig;
    exponent = ak->pub.publicArea.parameters.rsaDetail.exponent;
    if (exponent == 0U)
        exponent = 65537U;

    exponent_bytes[0] = (byte)(exponent >> 24);
    exponent_bytes[1] = (byte)(exponent >> 16);
    exponent_bytes[2] = (byte)(exponent >> 8);
    exponent_bytes[3] = (byte)exponent;

    exponent_size = 4;
    while (exponent_size > 1 && exponent_bytes[4 - exponent_size] == 0U)
        --exponent_size;

    rc = wc_InitRsaKey(&rsa, NULL);
    if (rc != 0)
        return rc;

    rc = wc_RsaPublicKeyDecodeRaw(modulus->buffer,
                                  modulus->size,
                                  &exponent_bytes[4 - exponent_size],
                                  (word32)exponent_size,
                                  &rsa);
    if (rc != 0) {
        wc_FreeRsaKey(&rsa);
        return rc;
    }

    verified_size =
        wc_RsaSSL_Verify(sig->buffer, sig->size, verified, (word32)sizeof(verified), &rsa);
    if (verified_size < 0) {
        wc_FreeRsaKey(&rsa);
        return verified_size;
    }

    XMEMCPY(expected, kSha256DigestInfoPrefix, sizeof(kSha256DigestInfoPrefix));
    XMEMCPY(expected + sizeof(kSha256DigestInfoPrefix), digest, sizeof(digest));

    if ((word32)verified_size != sizeof(expected) ||
        XMEMCMP(verified, expected, sizeof(expected)) != 0) {
        wc_FreeRsaKey(&rsa);
        return TPM_RC_SIGNATURE;
    }

    wc_FreeRsaKey(&rsa);
    return TPM_RC_SUCCESS;
}

#if defined(WOLFTPM_PQC) && defined(WOLFSSL_HAVE_MLDSA)

static int wolf_mldsa_parameter_set(TPMI_MLDSA_PARAMETER_SET parameter_set) {
    switch (parameter_set) {
    case TPM_MLDSA_44:
        return WC_ML_DSA_44;
    case TPM_MLDSA_65:
        return WC_ML_DSA_65;
    case TPM_MLDSA_87:
        return WC_ML_DSA_87;
    default:
        return 0;
    }
}

static int
verify_mldsa(const WOLFTPM2_KEY *ak, const TPM2B_ATTEST *quoted, const TPMT_SIGNATURE *signature) {
    wc_MlDsaKey key;
    const TPM2B_PUBLIC_KEY_MLDSA *public_key;
    const TPM2B_MLDSA_SIGNATURE *sig;
    int parameter_set;
    int valid = 0;
    int rc;

    if (ak->pub.publicArea.type != TPM_ALG_MLDSA || signature->sigAlg != TPM_ALG_MLDSA)
        return TPM_RC_SIGNATURE;

    parameter_set =
        wolf_mldsa_parameter_set(ak->pub.publicArea.parameters.mldsaDetail.parameterSet);
    if (parameter_set == 0)
        return BAD_FUNC_ARG;

    public_key = &ak->pub.publicArea.unique.mldsa;
    sig = &signature->signature.mldsa;

    rc = wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID);
    if (rc != 0)
        return rc;

    rc = wc_MlDsaKey_SetParams(&key, parameter_set);
    if (rc == 0) {
        rc = wc_MlDsaKey_ImportPubRaw(&key, public_key->buffer, (word32)public_key->size);
    }

    if (rc == 0) {
        /* Pure ML-DSA in TPM 2.0 v1.85 signs the attestation message without
         * a separate TPM hash selector. Use the FIPS 204 empty context. */
        rc = wc_MlDsaKey_VerifyCtx(&key,
                                   sig->buffer,
                                   (word32)sig->size,
                                   NULL,
                                   0,
                                   quoted->attestationData,
                                   (word32)quoted->size,
                                   &valid);
    }

    wc_MlDsaKey_Free(&key);

    if (rc != 0)
        return rc;

    return valid == 1 ? TPM_RC_SUCCESS : TPM_RC_SIGNATURE;
}

#endif

static int verify_signature(const WOLFTPM2_KEY *ak,
                            const TPM2B_ATTEST *quoted,
                            const TPMT_SIGNATURE *signature) {
    switch (signature->sigAlg) {
    case TPM_ALG_RSASSA:
        return verify_rsassa_sha256(ak, quoted, signature);

#ifdef WOLFTPM_PQC
    case TPM_ALG_MLDSA:
#if defined(WOLFSSL_HAVE_MLDSA)
        return verify_mldsa(ak, quoted, signature);
#else
        fprintf(stderr, "wolfSSL was built without ML-DSA verification support\n");
        return NOT_COMPILED_IN;
#endif
#endif

    default:
        fprintf(stderr, "Unsupported quote signature algorithm: 0x%x\n", signature->sigAlg);
        return TPM_RC_SIGNATURE;
    }
}

uint32_t verifier_signature_size(const TPMT_SIGNATURE *signature) {
    switch (signature->sigAlg) {
    case TPM_ALG_RSASSA:
        return (uint32_t)signature->signature.rsassa.sig.size;

#ifdef WOLFTPM_PQC
    case TPM_ALG_MLDSA:
        return (uint32_t)signature->signature.mldsa.size;
    case TPM_ALG_HASH_MLDSA:
        return (uint32_t)signature->signature.hash_mldsa.signature.size;
#endif

    default:
        return 0U;
    }
}

int verifier_verify_quote(const WOLFTPM2_KEY *ak,
                          const Quote_In *quote_in,
                          const Quote_Out *quote_out,
                          byte pcr_values[PCR_COUNT][PCR_MAX_DIGEST_SIZE],
                          TPMI_ALG_HASH pcr_bank_alg,
                          int pcr_digest_size) {
    TPMS_ATTEST attested;
    byte recomputed[PCR_MAX_DIGEST_SIZE];
    int rc;

    XMEMSET(&attested, 0, sizeof(attested));
    XMEMSET(recomputed, 0, sizeof(recomputed));

    rc = TPM2_ParseAttest(&quote_out->quoted, &attested);
    if (rc != TPM_RC_SUCCESS)
        return rc;

    if (attested.magic != TPM_GENERATED_VALUE || attested.type != TPM_ST_ATTEST_QUOTE) {
        fprintf(stderr, "Quote verification: invalid attestation header\n");
        return TPM_RC_FAILURE;
    }

    if (attested.extraData.size != quote_in->qualifyingData.size ||
        XMEMCMP(attested.extraData.buffer,
                quote_in->qualifyingData.buffer,
                quote_in->qualifyingData.size) != 0) {
        fprintf(stderr, "Quote verification: nonce mismatch\n");
        return TPM_RC_FAILURE;
    }

    rc = recompute_pcr_digest(
        &attested.attested.quote.pcrSelect, pcr_values, pcr_bank_alg, pcr_digest_size, recomputed);
    if (rc != 0)
        return rc;

    if (attested.attested.quote.pcrDigest.size != (UINT16)pcr_digest_size ||
        XMEMCMP(recomputed, attested.attested.quote.pcrDigest.buffer, (size_t)pcr_digest_size) !=
            0) {
        fprintf(stderr, "Quote verification: PCR digest mismatch\n");
        return TPM_RC_FAILURE;
    }

    return verify_signature(ak, &quote_out->quoted, &quote_out->signature);
}
