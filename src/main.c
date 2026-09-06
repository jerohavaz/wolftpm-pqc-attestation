#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app_types.h"

#include <wolftpm/tpm2_metrics.h>
#include "attestation.h"
#include "crypto_profile.h"
#include "metrics.h"
#include "options.h"
#include "transport_trace.h"

#define EXPECTED_TRANSACTIONS_PER_RUN 32U

static char *derive_csv_path(const char *base, const char *suffix) {
    size_t base_len;
    size_t stem_len;
    size_t suffix_len;
    char *path;

    if (base == NULL || suffix == NULL)
        return NULL;

    base_len = strlen(base);
    stem_len = base_len;
    if (base_len >= 4U && strcmp(base + base_len - 4U, ".csv") == 0)
        stem_len -= 4U;

    suffix_len = strlen(suffix);
    path = malloc(stem_len + suffix_len + 1U);
    if (path == NULL)
        return NULL;

    memcpy(path, base, stem_len);
    memcpy(path + stem_len, suffix, suffix_len + 1U);
    return path;
}

int main(int argc, char **argv) {
    AppOptions options;
    const CryptoProfile *profile;
    PerformanceSample *samples = NULL;
    SizeSample sizes;
    TransportTrace trace;
    char *runs_csv = NULL;
    char *metadata_csv = NULL;
    unsigned i;
    int rc;
    int exit_code = EXIT_FAILURE;
    int trace_initialized = 0;

    options_defaults(&options);
    rc = options_parse(&options, argc, argv);
    if (rc > 0)
        return EXIT_SUCCESS;
    if (rc < 0) {
        options_print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    profile = crypto_profile_get(options.crypto_mode);
    runs_csv = derive_csv_path(options.csv_path, "_runs.csv");
    metadata_csv = derive_csv_path(options.csv_path, "_metadata.csv");
    if (runs_csv == NULL || metadata_csv == NULL)
        goto cleanup;

    printf("Running %s: warmup=%u measured=%u\n",
           profile->name,
           options.warmup_iterations,
           options.iterations);

    for (i = 0; i < options.warmup_iterations; ++i) {
        PerformanceSample warmup_performance;
        SizeSample warmup_sizes;
        RunOptions warmup_options = {
            .run_index = 0U,
            .transport_trace = NULL,
        };

        rc = attestation_run_once(profile, &warmup_options, &warmup_performance, &warmup_sizes);
        if (rc != TPM_RC_SUCCESS)
            goto cleanup;
    }

    samples = calloc(options.iterations, sizeof(*samples));
    if (samples == NULL)
        goto cleanup;

    if (transport_trace_init(&trace,
                             (size_t)options.iterations * EXPECTED_TRANSACTIONS_PER_RUN) != 0)
        goto cleanup;
    trace_initialized = 1;

    TPM2_SetTransportMetricCallback(transport_trace_callback, &trace);

    for (i = 0; i < options.iterations; ++i) {
        RunOptions run_options = {
            .run_index = i + 1U,
            .transport_trace = &trace,
        };

        rc = attestation_run_once(profile, &run_options, &samples[i], &sizes);
        if (rc != TPM_RC_SUCCESS) {
            TPM2_SetTransportMetricCallback(NULL, NULL);
            goto cleanup;
        }
    }

    TPM2_SetTransportMetricCallback(NULL, NULL);

    rc = transport_trace_write_csv(&trace, options.csv_path);
    if (rc < 0) {
        fprintf(stderr, "Failed to write %s\n", options.csv_path);
        goto cleanup;
    }
    if (rc > 0) {
        fprintf(stderr, "Transport trace buffer overflowed; CSV is incomplete\n");
        goto cleanup;
    }

    if (metrics_write_runs_csv(samples, options.iterations, profile->name, runs_csv) != 0) {
        fprintf(stderr, "Failed to write %s\n", runs_csv);
        goto cleanup;
    }

    if (metrics_write_metadata_csv(&sizes,
                                   options.warmup_iterations,
                                   options.iterations,
                                   metadata_csv) != 0) {
        fprintf(stderr, "Failed to write %s\n", metadata_csv);
        goto cleanup;
    }

    printf("CSV: %s\n", options.csv_path);
    printf("CSV: %s\n", runs_csv);
    printf("CSV: %s\n", metadata_csv);
    exit_code = EXIT_SUCCESS;

cleanup:
    TPM2_SetTransportMetricCallback(NULL, NULL);
    if (trace_initialized)
        transport_trace_free(&trace);
    free(samples);
    free(runs_csv);
    free(metadata_csv);
    return exit_code;
}
