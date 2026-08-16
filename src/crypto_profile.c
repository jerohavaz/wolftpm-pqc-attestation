#include "crypto_profile.h"

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>

#include "app_types.h"

static const byte kAkAuth[] = "aik-auth";

/* ------------------------------------------------------------------------- */
/* Classical profile: RSA EK + RSA SRK + RSA AK + RSASSA/SHA-256 Quote      */
/* ------------------------------------------------------------------------- */

static int rsa_create_ek(WOLFTPM2_DEV *dev, WOLFTPM2_KEY *ek) {
    return wolfTPM2_CreateEK(dev, ek, TPM_ALG_RSA);
}

static int rsa_create_srk(WOLFTPM2_DEV *dev, WOLFTPM2_KEY *srk) {
    return wolfTPM2_CreateSRK(dev, srk, TPM_ALG_RSA, NULL, 0);
}

static int rsa_create_ak(WOLFTPM2_DEV *dev, WOLFTPM2_KEY *ak, WOLFTPM2_KEY *srk) {
    return wolfTPM2_CreateAndLoadAIK(
        dev, ak, TPM_ALG_RSA, srk, kAkAuth, (int)(sizeof(kAkAuth) - 1U));
}

static void rsa_configure_quote(Quote_In *quote) {
    quote->inScheme.scheme = TPM_ALG_RSASSA;
    quote->inScheme.details.any.hashAlg = TPM_ALG_SHA256;
}

/* ------------------------------------------------------------------------- */
/* Full-PQ profile: ML-KEM-768 EK + ML-KEM-768 SRK + ML-DSA-65 AK           */
/*                                                                           */
/* The classic convenience wrappers only accept RSA/ECC. For v1.85 PQC we   */
/* therefore build the templates explicitly and use the generic create APIs. */
/* We reuse the standard RSA EK/SRK/AIK templates only as sources for the     */
/* object attributes and EK authorization policy. The asymmetric algorithm   */
/* fields themselves are replaced by the v1.85 ML-KEM/ML-DSA templates.      */
/* ------------------------------------------------------------------------- */

#if defined(WOLFTPM_PQC) && defined(WOLFTPM_MLKEM) && defined(WOLFTPM_MLDSA)

static int make_mlkem_template_from(TPMT_PUBLIC *out,
                                    const TPMT_PUBLIC *base,
                                    TPMI_MLKEM_PARAMETER_SET parameter_set) {
    int rc;

    rc = wolfTPM2_GetKeyTemplate_MLKEM_ex(
        out, base->objectAttributes, parameter_set, TPM_ALG_SHA256);
    if (rc != TPM_RC_SUCCESS)
        return rc;

    /* Preserve the hierarchy policy (important for the EK). */
    out->authPolicy = base->authPolicy;
    return TPM_RC_SUCCESS;
}

static int make_mldsa_template_from(TPMT_PUBLIC *out,
                                    const TPMT_PUBLIC *base,
                                    TPMI_MLDSA_PARAMETER_SET parameter_set) {
    int rc;

    rc = wolfTPM2_GetKeyTemplate_MLDSA_ex(out,
                                          base->objectAttributes,
                                          parameter_set,
                                          0, /* pure ML-DSA; external mu not needed for Quote */
                                          TPM_ALG_SHA256);
    if (rc != TPM_RC_SUCCESS)
        return rc;

    out->authPolicy = base->authPolicy;
    return TPM_RC_SUCCESS;
}

static int pq_create_ek(WOLFTPM2_DEV *dev, WOLFTPM2_KEY *ek) {
    TPMT_PUBLIC base;
    TPMT_PUBLIC pq;
    int rc;

    XMEMSET(&base, 0, sizeof(base));
    XMEMSET(&pq, 0, sizeof(pq));

    rc = wolfTPM2_GetKeyTemplate_RSA_EK(&base);
    if (rc != TPM_RC_SUCCESS)
        return rc;

    rc = make_mlkem_template_from(&pq, &base, TPM_MLKEM_768);
    if (rc != TPM_RC_SUCCESS)
        return rc;

    return wolfTPM2_CreatePrimaryKey(dev, ek, TPM_RH_ENDORSEMENT, &pq, NULL, 0);
}

static int pq_create_srk(WOLFTPM2_DEV *dev, WOLFTPM2_KEY *srk) {
    TPMT_PUBLIC base;
    TPMT_PUBLIC pq;
    int rc;

    XMEMSET(&base, 0, sizeof(base));
    XMEMSET(&pq, 0, sizeof(pq));

    rc = wolfTPM2_GetKeyTemplate_RSA_SRK(&base);
    if (rc != TPM_RC_SUCCESS)
        return rc;

    rc = make_mlkem_template_from(&pq, &base, TPM_MLKEM_768);
    if (rc != TPM_RC_SUCCESS)
        return rc;

    return wolfTPM2_CreatePrimaryKey(dev, srk, TPM_RH_OWNER, &pq, NULL, 0);
}

static int pq_create_ak(WOLFTPM2_DEV *dev, WOLFTPM2_KEY *ak, WOLFTPM2_KEY *srk) {
    TPMT_PUBLIC base;
    TPMT_PUBLIC pq;
    int rc;

    XMEMSET(&base, 0, sizeof(base));
    XMEMSET(&pq, 0, sizeof(pq));

    rc = wolfTPM2_GetKeyTemplate_RSA_AIK(&base);
    if (rc != TPM_RC_SUCCESS)
        return rc;

    rc = make_mldsa_template_from(&pq, &base, TPM_MLDSA_65);
    if (rc != TPM_RC_SUCCESS)
        return rc;

    return wolfTPM2_CreateAndLoadKey(
        dev, ak, &srk->handle, &pq, kAkAuth, (int)(sizeof(kAkAuth) - 1U));
}

static void pq_configure_quote(Quote_In *quote) {
    /* Pure ML-DSA has no separate hash selector in TPMT_SIG_SCHEME. */
    quote->inScheme.scheme = TPM_ALG_MLDSA;
}

#else

static int pq_unavailable(void) {
    return NOT_COMPILED_IN;
}

static int pq_create_ek(WOLFTPM2_DEV *dev, WOLFTPM2_KEY *ek) {
    (void)dev;
    (void)ek;
    return pq_unavailable();
}

static int pq_create_srk(WOLFTPM2_DEV *dev, WOLFTPM2_KEY *srk) {
    (void)dev;
    (void)srk;
    return pq_unavailable();
}

static int pq_create_ak(WOLFTPM2_DEV *dev, WOLFTPM2_KEY *ak, WOLFTPM2_KEY *srk) {
    (void)dev;
    (void)ak;
    (void)srk;
    return pq_unavailable();
}

static void pq_configure_quote(Quote_In *quote) {
    (void)quote;
}

#endif /* WOLFTPM_PQC && WOLFTPM_MLKEM && WOLFTPM_MLDSA */

static const CryptoProfile kRsaProfile = {
    .mode = CRYPTO_MODE_RSA,
    .name = "Classical RSA",
    .ek_algorithm = "RSA-2048",
    .srk_algorithm = "RSA-2048",
    .ak_algorithm = "RSA-2048",
    .quote_algorithm = "RSASSA/SHA-256",
    .create_ek = rsa_create_ek,
    .create_srk = rsa_create_srk,
    .create_ak = rsa_create_ak,
    .configure_quote = rsa_configure_quote,
};

static const CryptoProfile kPqProfile = {
    .mode = CRYPTO_MODE_PQ,
    .name = "Full PQ (ML-KEM-768 / ML-DSA-65)",
    .ek_algorithm = "ML-KEM-768",
    .srk_algorithm = "ML-KEM-768",
    .ak_algorithm = "ML-DSA-65",
    .quote_algorithm = "ML-DSA-65",
    .create_ek = pq_create_ek,
    .create_srk = pq_create_srk,
    .create_ak = pq_create_ak,
    .configure_quote = pq_configure_quote,
};

const CryptoProfile *crypto_profile_get(CryptoMode mode) {
    return mode == CRYPTO_MODE_RSA ? &kRsaProfile : &kPqProfile;
}

const byte *crypto_ak_auth(void) {
    return kAkAuth;
}

int crypto_ak_auth_size(void) {
    return (int)(sizeof(kAkAuth) - 1U);
}
