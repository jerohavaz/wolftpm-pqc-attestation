#define _POSIX_C_SOURCE 200809L

#include "metrics.h"

#include <stdio.h>
#include <time.h>

uint64_t metrics_now_ns(void) {
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0)
        return 0U;

    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

int metrics_write_runs_csv(const PerformanceSample *samples,
                           size_t count,
                           const char *profile_name,
                           const char *path) {
    FILE *file;
    size_t i;

    if (samples == NULL || path == NULL)
        return -1;

    file = fopen(path, "w");
    if (file == NULL)
        return -1;

    fprintf(file, "run,profile,verifier_ns,full_flow_ns\n");

    for (i = 0; i < count; ++i) {
        fprintf(file,
                "%zu,%s,%llu,%llu\n",
                i + 1U,
                profile_name != NULL ? profile_name : "unknown",
                (unsigned long long)samples[i].verifier_ns,
                (unsigned long long)samples[i].full_flow_ns);
    }

    fclose(file);
    return 0;
}

int metrics_write_metadata_csv(const SizeSample *sizes,
                               unsigned warmup_iterations,
                               unsigned measured_iterations,
                               const char *path) {
    FILE *file;

    if (sizes == NULL || path == NULL)
        return -1;

    file = fopen(path, "w");
    if (file == NULL)
        return -1;

    fprintf(file,
            "profile,ek_algorithm,ak_algorithm,quote_algorithm,"
            "pcr_bank_alg,pcr_count,pcr_digest_bytes,warmup_runs,measured_runs,"
            "ek_public_bytes,ak_public_bytes,credential_blob_bytes,"
            "credential_secret_bytes,nonce_bytes,pcr_payload_bytes,"
            "quote_attest_bytes,quote_signature_bytes,attestation_response_bytes\n");

    fprintf(file,
            "%s,%s,%s,%s,0x%04x,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u\n",
            sizes->profile_name != NULL ? sizes->profile_name : "unknown",
            sizes->ek_algorithm != NULL ? sizes->ek_algorithm : "unknown",
            sizes->ak_algorithm != NULL ? sizes->ak_algorithm : "unknown",
            sizes->quote_algorithm != NULL ? sizes->quote_algorithm : "unknown",
            (unsigned)sizes->pcr_bank_alg,
            sizes->pcr_count,
            sizes->pcr_digest_bytes,
            warmup_iterations,
            measured_iterations,
            sizes->ek_public_bytes,
            sizes->ak_public_bytes,
            sizes->credential_blob_bytes,
            sizes->credential_secret_bytes,
            sizes->nonce_bytes,
            sizes->pcr_payload_bytes,
            sizes->quote_attest_bytes,
            sizes->quote_signature_bytes,
            sizes->attestation_response_bytes);

    fclose(file);
    return 0;
}
