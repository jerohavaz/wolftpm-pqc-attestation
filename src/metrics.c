#define _POSIX_C_SOURCE 200809L

#include "metrics.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <wolftpm/tpm2.h>

static int compare_u64(const void *left, const void *right) {
    uint64_t a = *(const uint64_t *)left;
    uint64_t b = *(const uint64_t *)right;
    return (a > b) - (a < b);
}

static double ns_to_us(double ns) {
    return ns / 1000.0;
}

uint64_t metrics_now_ns(void) {
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0)
        return 0U;

    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

void metrics_print_sizes(const SizeSample *sizes) {
    const char *pcr_bank_name = TPM2_GetAlgName(sizes->pcr_bank_alg);

    puts("\nSemantic configuration + payload sizes");
    puts("----------------------------------------------------------------");
    printf("%-32s %s\n", "Profile", sizes->profile_name);
    printf("%-32s %s\n", "EK algorithm", sizes->ek_algorithm);
    printf("%-32s %s\n", "AK algorithm", sizes->ak_algorithm);
    printf("%-32s %s\n", "Quote algorithm", sizes->quote_algorithm);
    printf("%-32s %s (0x%x)\n",
           "PCR bank",
           pcr_bank_name != NULL ? pcr_bank_name : "unknown",
           sizes->pcr_bank_alg);
    printf("%-32s %8u\n", "PCR count", sizes->pcr_count);
    printf("%-32s %8u B\n", "PCR digest / PCR", sizes->pcr_digest_bytes);
    puts("----------------------------------------------------------------");
    printf("%-32s %8u B\n", "EK public", sizes->ek_public_bytes);
    printf("%-32s %8u B\n", "AK public", sizes->ak_public_bytes);
    printf("%-32s %8u B\n", "Credential blob", sizes->credential_blob_bytes);
    printf("%-32s %8u B\n", "Credential secret", sizes->credential_secret_bytes);
    printf("%-32s %8u B\n", "Challenge nonce", sizes->nonce_bytes);
    printf("%-32s %8u B\n", "PCR payload", sizes->pcr_payload_bytes);
    printf("%-32s %8u B\n", "Quote attestation", sizes->quote_attest_bytes);
    printf("%-32s %8u B\n", "Quote signature", sizes->quote_signature_bytes);
    printf("%-32s %8u B\n", "Attestation response", sizes->attestation_response_bytes);
}

static void print_sample_metric(const char *name,
                                const PerformanceSample *samples,
                                size_t count,
                                int full_flow) {
    uint64_t *values;
    long double sum = 0.0L;
    size_t i;
    double mean;
    double median;

    values = malloc(count * sizeof(*values));
    if (values == NULL)
        return;

    for (i = 0; i < count; ++i) {
        values[i] = full_flow ? samples[i].full_flow_ns : samples[i].verifier_ns;
        sum += (long double)values[i];
    }

    qsort(values, count, sizeof(*values), compare_u64);
    mean = (double)(sum / (long double)count);

    if ((count % 2U) == 0U)
        median = ((double)values[count / 2U - 1U] + (double)values[count / 2U]) / 2.0;
    else
        median = (double)values[count / 2U];

    printf("%-28s mean=%10.3f us  median=%10.3f us\n", name, ns_to_us(mean), ns_to_us(median));

    free(values);
}

void metrics_print_software_summary(const PerformanceSample *samples, size_t count) {
    if (samples == NULL || count == 0U)
        return;

    puts("\nApplication-side secondary timings");
    puts("---------------------------------------------------------");
    print_sample_metric("Verifier (software)", samples, count, 0);
    print_sample_metric("Full attestation flow", samples, count, 1);
}
