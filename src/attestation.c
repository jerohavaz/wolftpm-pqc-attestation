#include "attestation.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#include "crypto_profile.h"
#include "metrics.h"
#include "verifier.h"

static int fail_rc(const char *operation, int rc) {
    fprintf(stderr, "%s failed: 0x%x (%s)\n", operation, rc, wolfTPM2_GetRCString(rc));
    return rc;
}

static void set_pcr_range(TPML_PCR_SELECTION *selection) {
    byte pcr_indices[PCR_COUNT];
    word32 i;

    XMEMSET(selection, 0, sizeof(*selection));

    for (i = 0; i < (word32)PCR_COUNT; ++i)
        pcr_indices[i] = (byte)(PCR_FIRST_INDEX + (int)i);

    TPM2_SetupPCRSelArray(selection, PCR_BANK_ALG, pcr_indices, (word32)PCR_COUNT);
}

static int init_context(AttestationContext *ctx, int verbose) {
    int rc;

    XMEMSET(ctx, 0, sizeof(*ctx));

    ctx->pcr_digest_size = TPM2_GetHashDigestSize(PCR_BANK_ALG);
    if (ctx->pcr_digest_size <= 0 || ctx->pcr_digest_size > (int)PCR_MAX_DIGEST_SIZE) {
        fprintf(stderr, "Unsupported PCR bank digest size for algorithm 0x%x\n", PCR_BANK_ALG);
        return TPM_RC_FAILURE;
    }

    rc = wolfTPM2_Init(&ctx->dev, NULL, NULL);
    if (rc != TPM_RC_SUCCESS)
        return fail_rc("wolfTPM2_Init", rc);

    ctx->initialized = 1;

#ifndef WOLFTPM_NO_RETRY
    /* Raw benchmarking should expose retries as separate behavior rather than
     * silently repeating a TPM transaction inside wolfTPM. */
    rc = TPM2_SetCommandRetries(&ctx->dev.ctx, 0);
    if (rc != TPM_RC_SUCCESS)
        return fail_rc("TPM2_SetCommandRetries", rc);
#endif

    rc = wolfTPM2_GetCapabilities(&ctx->dev, &ctx->caps);
    if (rc != TPM_RC_SUCCESS)
        return fail_rc("wolfTPM2_GetCapabilities", rc);

    if (verbose) {
        printf("TPM: %s / %s, firmware %u.%u\n",
               ctx->caps.mfgStr,
               ctx->caps.vendorStr,
               ctx->caps.fwVerMajor,
               ctx->caps.fwVerMinor);
        printf("PCR bank: %s, PCRs %d..%d, %d B per PCR\n",
               TPM2_GetAlgName(PCR_BANK_ALG),
               PCR_FIRST_INDEX,
               PCR_LAST_INDEX,
               ctx->pcr_digest_size);
    }

    return TPM_RC_SUCCESS;
}

static void cleanup_context(AttestationContext *ctx) {
    if (!ctx->initialized)
        return;

    if (ctx->ak.handle.hndl != 0U && ctx->ak.handle.hndl != TPM_RH_NULL)
        (void)wolfTPM2_UnloadHandle(&ctx->dev, &ctx->ak.handle);

    if (ctx->srk.handle.hndl != 0U && ctx->srk.handle.hndl != TPM_RH_NULL)
        (void)wolfTPM2_UnloadHandle(&ctx->dev, &ctx->srk.handle);

    if (ctx->ek.handle.hndl != 0U && ctx->ek.handle.hndl != TPM_RH_NULL)
        (void)wolfTPM2_UnloadHandle(&ctx->dev, &ctx->ek.handle);

    if (ctx->ek_policy_activate.handle.hndl != 0U &&
        ctx->ek_policy_activate.handle.hndl != TPM_RH_NULL) {
        (void)wolfTPM2_UnloadHandle(&ctx->dev, &ctx->ek_policy_activate.handle);
    }

    (void)wolfTPM2_Cleanup(&ctx->dev);
}

static void initialize_size_metadata(const CryptoProfile *profile,
                                     const AttestationContext *ctx,
                                     SizeSample *sizes) {
    sizes->profile_name = profile->name;
    sizes->ek_algorithm = profile->ek_algorithm;
    sizes->srk_algorithm = profile->srk_algorithm;
    sizes->ak_algorithm = profile->ak_algorithm;
    sizes->quote_algorithm = profile->quote_algorithm;
    sizes->pcr_bank_alg = PCR_BANK_ALG;
    sizes->pcr_count = PCR_COUNT;
    sizes->pcr_digest_bytes = (uint32_t)ctx->pcr_digest_size;
}

static int create_keys(const CryptoProfile *profile,
                       AttestationContext *ctx,
                       SizeSample *sizes,
                       int verbose,
                       TransportTrace *trace) {
    int rc;

    transport_trace_set_phase(trace, "EK_CREATE");
    rc = profile->create_ek(&ctx->dev, &ctx->ek);
    if (rc != TPM_RC_SUCCESS)
        return fail_rc("CreateEK", rc);
    sizes->ek_public_bytes = (uint32_t)ctx->ek.pub.size;

    transport_trace_set_phase(trace, "SRK_CREATE");
    rc = profile->create_srk(&ctx->dev, &ctx->srk);
    if (rc != TPM_RC_SUCCESS)
        return fail_rc("CreateSRK", rc);
    sizes->srk_public_bytes = (uint32_t)ctx->srk.pub.size;

    transport_trace_set_phase(trace, "AK_CREATE");
    rc = profile->create_ak(&ctx->dev, &ctx->ak, &ctx->srk);
    if (rc != TPM_RC_SUCCESS)
        return fail_rc("CreateAK", rc);
    sizes->ak_public_bytes = (uint32_t)ctx->ak.pub.size;

    if (verbose) {
        printf("Keys: EK=0x%x [%s], SRK=0x%x [%s], AK=0x%x [%s]\n",
               (unsigned)ctx->ek.handle.hndl,
               profile->ek_algorithm,
               (unsigned)ctx->srk.handle.hndl,
               profile->srk_algorithm,
               (unsigned)ctx->ak.handle.hndl,
               profile->ak_algorithm);
    }

    return TPM_RC_SUCCESS;
}

static int make_credential(AttestationContext *ctx, SizeSample *sizes, TransportTrace *trace) {
    int rc;

    XMEMSET(&ctx->make_in, 0, sizeof(ctx->make_in));
    XMEMSET(&ctx->make_out, 0, sizeof(ctx->make_out));

    transport_trace_set_phase(trace, "CREDENTIAL_RANDOM");
    rc = wolfTPM2_GetRandom(&ctx->dev, ctx->credential, CREDENTIAL_SIZE);
    if (rc != TPM_RC_SUCCESS)
        return fail_rc("wolfTPM2_GetRandom(credential)", rc);

    ctx->make_in.handle = ctx->ek.handle.hndl;
    ctx->make_in.credential.size = CREDENTIAL_SIZE;
    XMEMCPY(ctx->make_in.credential.buffer, ctx->credential, CREDENTIAL_SIZE);

    ctx->make_in.objectName.size = ctx->ak.handle.name.size;
    if (ctx->make_in.objectName.size > sizeof(ctx->make_in.objectName.name))
        return TPM_RC_SIZE;

    XMEMCPY(ctx->make_in.objectName.name, ctx->ak.handle.name.name, ctx->ak.handle.name.size);

    transport_trace_set_phase(trace, "MAKE_CREDENTIAL");
    rc = TPM2_MakeCredential(&ctx->make_in, &ctx->make_out);
    if (rc != TPM_RC_SUCCESS)
        return fail_rc("TPM2_MakeCredential", rc);

    sizes->credential_blob_bytes = (uint32_t)ctx->make_out.credentialBlob.size;
    sizes->credential_secret_bytes = (uint32_t)ctx->make_out.secret.size;
    return TPM_RC_SUCCESS;
}

static int configure_activate_auth(AttestationContext *ctx, TransportTrace *trace) {
    const byte *ak_auth = crypto_ak_auth();
    int ak_auth_size = crypto_ak_auth_size();
    int rc;

    (void)wolfTPM2_UnsetAuth(&ctx->dev, 0);
    (void)wolfTPM2_UnsetAuth(&ctx->dev, 1);

    ctx->ek.handle.policyAuth = 1;

    transport_trace_set_phase(trace, "ACTIVATE_AUTH");
    rc = wolfTPM2_CreateAuthSession_EkPolicy(&ctx->dev, &ctx->ek_policy_activate);
    if (rc != TPM_RC_SUCCESS)
        return fail_rc("wolfTPM2_CreateAuthSession_EkPolicy", rc);

    rc = wolfTPM2_SetAuthSession(&ctx->dev, 1, &ctx->ek_policy_activate, 0);
    if (rc != TPM_RC_SUCCESS)
        return fail_rc("wolfTPM2_SetAuthSession(EK)", rc);

    rc = wolfTPM2_SetAuthHandleName(&ctx->dev, 1, &ctx->ek.handle);
    if (rc != TPM_RC_SUCCESS)
        return fail_rc("wolfTPM2_SetAuthHandleName(EK)", rc);

    ctx->ak.handle.auth.size = (UINT16)ak_auth_size;
    XMEMCPY(ctx->ak.handle.auth.buffer, ak_auth, (size_t)ak_auth_size);

    rc = wolfTPM2_SetAuthHandle(&ctx->dev, 0, &ctx->ak.handle);
    if (rc != TPM_RC_SUCCESS)
        return fail_rc("wolfTPM2_SetAuthHandle(AK)", rc);

    return TPM_RC_SUCCESS;
}

static int activate_credential(AttestationContext *ctx, TransportTrace *trace) {
    int rc;

    rc = configure_activate_auth(ctx, trace);
    if (rc != TPM_RC_SUCCESS)
        return rc;

    XMEMSET(&ctx->activate_in, 0, sizeof(ctx->activate_in));
    XMEMSET(&ctx->activate_out, 0, sizeof(ctx->activate_out));

    ctx->activate_in.activateHandle = ctx->ak.handle.hndl;
    ctx->activate_in.keyHandle = ctx->ek.handle.hndl;
    ctx->activate_in.credentialBlob = ctx->make_out.credentialBlob;
    ctx->activate_in.secret = ctx->make_out.secret;

    transport_trace_set_phase(trace, "ACTIVATE_CREDENTIAL");
    rc = TPM2_ActivateCredential(&ctx->activate_in, &ctx->activate_out);
    if (rc != TPM_RC_SUCCESS)
        return fail_rc("TPM2_ActivateCredential", rc);

    if (ctx->activate_out.certInfo.size != CREDENTIAL_SIZE ||
        XMEMCMP(ctx->activate_out.certInfo.buffer, ctx->credential, CREDENTIAL_SIZE) != 0) {
        fprintf(stderr, "ActivateCredential returned wrong credential\n");
        return TPM_RC_FAILURE;
    }

    ctx->ek_policy_activate.handle.hndl = TPM_RH_NULL;
    return TPM_RC_SUCCESS;
}

static int collect_pcrs(AttestationContext *ctx, SizeSample *sizes, TransportTrace *trace) {
    int pcr;

    transport_trace_set_phase(trace, "PCR_READ");
    for (pcr = PCR_FIRST_INDEX; pcr <= PCR_LAST_INDEX; ++pcr) {
        int digest_size = ctx->pcr_digest_size;
        int rc = wolfTPM2_ReadPCR(
            &ctx->dev, pcr, PCR_BANK_ALG, ctx->pcr_values[pcr - PCR_FIRST_INDEX], &digest_size);

        if (rc != TPM_RC_SUCCESS)
            return fail_rc("wolfTPM2_ReadPCR", rc);
        if (digest_size != ctx->pcr_digest_size) {
            fprintf(stderr,
                    "PCR %d returned %d bytes, expected %d\n",
                    pcr,
                    digest_size,
                    ctx->pcr_digest_size);
            return TPM_RC_FAILURE;
        }
    }

    sizes->pcr_payload_bytes = (uint32_t)PCR_COUNT * (uint32_t)ctx->pcr_digest_size;
    return TPM_RC_SUCCESS;
}

static int configure_quote_auth(AttestationContext *ctx) {
    const byte *ak_auth = crypto_ak_auth();
    int ak_auth_size = crypto_ak_auth_size();
    int rc;

    (void)wolfTPM2_UnsetAuth(&ctx->dev, 0);
    (void)wolfTPM2_UnsetAuth(&ctx->dev, 1);

    ctx->ak.handle.auth.size = (UINT16)ak_auth_size;
    XMEMCPY(ctx->ak.handle.auth.buffer, ak_auth, (size_t)ak_auth_size);

    rc = wolfTPM2_SetAuthHandle(&ctx->dev, 0, &ctx->ak.handle);
    if (rc != TPM_RC_SUCCESS)
        return fail_rc("wolfTPM2_SetAuthHandle(AK quote)", rc);

    return TPM_RC_SUCCESS;
}

static int create_quote(const CryptoProfile *profile,
                        AttestationContext *ctx,
                        SizeSample *sizes,
                        TransportTrace *trace) {
    int rc;

    transport_trace_set_phase(trace, "NONCE_RANDOM");
    rc = wolfTPM2_GetRandom(&ctx->dev, ctx->nonce, NONCE_SIZE);
    if (rc != TPM_RC_SUCCESS)
        return fail_rc("wolfTPM2_GetRandom(nonce)", rc);

    XMEMSET(&ctx->quote_in, 0, sizeof(ctx->quote_in));
    XMEMSET(&ctx->quote_out, 0, sizeof(ctx->quote_out));

    ctx->quote_in.signHandle = ctx->ak.handle.hndl;
    ctx->quote_in.qualifyingData.size = NONCE_SIZE;
    XMEMCPY(ctx->quote_in.qualifyingData.buffer, ctx->nonce, NONCE_SIZE);

    set_pcr_range(&ctx->quote_in.PCRselect);
    profile->configure_quote(&ctx->quote_in);

    rc = configure_quote_auth(ctx);
    if (rc != TPM_RC_SUCCESS)
        return rc;

    transport_trace_set_phase(trace, "QUOTE");
    rc = TPM2_Quote(&ctx->quote_in, &ctx->quote_out);
    if (rc != TPM_RC_SUCCESS)
        return fail_rc("TPM2_Quote", rc);

    sizes->nonce_bytes = NONCE_SIZE;
    sizes->quote_attest_bytes = (uint32_t)ctx->quote_out.quoted.size;
    sizes->quote_signature_bytes = verifier_signature_size(&ctx->quote_out.signature);
    sizes->attestation_response_bytes =
        sizes->quote_attest_bytes + sizes->quote_signature_bytes + sizes->pcr_payload_bytes;

    return TPM_RC_SUCCESS;
}

static int verify_quote(AttestationContext *ctx, PerformanceSample *performance) {
    uint64_t start = metrics_now_ns();
    int rc = verifier_verify_quote(&ctx->ak,
                                   &ctx->quote_in,
                                   &ctx->quote_out,
                                   ctx->pcr_values,
                                   PCR_BANK_ALG,
                                   ctx->pcr_digest_size);

    performance->verifier_ns = metrics_now_ns() - start;
    return rc;
}

int attestation_run_once(const CryptoProfile *profile,
                         const RunOptions *options,
                         PerformanceSample *performance,
                         SizeSample *sizes) {
    AttestationContext ctx;
    uint64_t total_start;
    int rc;
    int trace_started = 0;

    XMEMSET(performance, 0, sizeof(*performance));
    XMEMSET(sizes, 0, sizeof(*sizes));

    rc = init_context(&ctx, options->verbose);
    if (rc != TPM_RC_SUCCESS) {
        cleanup_context(&ctx);
        return rc;
    }

    initialize_size_metadata(profile, &ctx, sizes);

    if (options->transport_trace != NULL) {
        transport_trace_begin_run(options->transport_trace, options->run_index, profile->name);
        trace_started = 1;
    }

    total_start = metrics_now_ns();

    rc = create_keys(profile, &ctx, sizes, options->verbose, options->transport_trace);
    if (rc != TPM_RC_SUCCESS)
        goto cleanup;

    rc = make_credential(&ctx, sizes, options->transport_trace);
    if (rc != TPM_RC_SUCCESS)
        goto cleanup;

    rc = activate_credential(&ctx, options->transport_trace);
    if (rc != TPM_RC_SUCCESS)
        goto cleanup;

    rc = collect_pcrs(&ctx, sizes, options->transport_trace);
    if (rc != TPM_RC_SUCCESS)
        goto cleanup;

    rc = create_quote(profile, &ctx, sizes, options->transport_trace);
    if (rc != TPM_RC_SUCCESS)
        goto cleanup;

    rc = verify_quote(&ctx, performance);
    if (rc != TPM_RC_SUCCESS) {
        (void)fail_rc("Quote verification", rc);
        goto cleanup;
    }

    performance->full_flow_ns = metrics_now_ns() - total_start;

    if (options->verbose) {
        printf("Attestation passed (%s): quote=%u B, signature=%u B\n",
               profile->name,
               sizes->quote_attest_bytes,
               sizes->quote_signature_bytes);
    }

cleanup:
    if (trace_started)
        transport_trace_end_run(options->transport_trace);

    cleanup_context(&ctx);
    return rc;
}
