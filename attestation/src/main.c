#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app_types.h"
#include "attestation.h"
#include "crypto_profile.h"
#include "metrics.h"
#include "options.h"
#include "transport_trace.h"

#define EXPECTED_TRANSACTIONS_PER_RUN 64U

static char *join_path(const char *dir, const char *name) {
    size_t dir_len;
    size_t name_len;
    int needs_separator;
    char *path;

    if (dir == NULL || name == NULL)
        return NULL;

    dir_len = strlen(dir);
    name_len = strlen(name);
    needs_separator = dir_len > 0U && dir[dir_len - 1U] != '/';

    path = malloc(dir_len + (size_t)needs_separator + name_len + 1U);
    if (path == NULL)
        return NULL;

    memcpy(path, dir, dir_len);
    if (needs_separator)
        path[dir_len++] = '/';
    memcpy(path + dir_len, name, name_len + 1U);
    return path;
}

int main(int argc, char **argv) {
    AppOptions options;
    const CryptoProfile *profile;
    PerformanceSample *samples = NULL;
    SizeSample sizes;
    TransportTrace trace;
    char *transport_csv = NULL;
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
    transport_csv = join_path(options.output_dir, "client_transport.csv");
    runs_csv = join_path(options.output_dir, "client_runs.csv");
    metadata_csv = join_path(options.output_dir, "client_metadata.csv");
    if (transport_csv == NULL || runs_csv == NULL || metadata_csv == NULL)
        goto cleanup;

    printf("attestation-bench: profile=%s warmup=%u measured=%u\n",
           options.crypto_mode == CRYPTO_MODE_RSA ? "rsa" : "pq",
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

    if (transport_trace_init(&trace, (size_t)options.iterations * EXPECTED_TRANSACTIONS_PER_RUN) !=
        0)
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

    rc = transport_trace_write_csv(&trace, transport_csv);
    if (rc < 0) {
        fprintf(stderr, "Failed to write %s\n", transport_csv);
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

    if (metrics_write_metadata_csv(
            &sizes, options.warmup_iterations, options.iterations, metadata_csv) != 0) {
        fprintf(stderr, "Failed to write %s\n", metadata_csv);
        goto cleanup;
    }

    printf("attestation-bench: raw CSV written to %s\n", options.output_dir);
    exit_code = EXIT_SUCCESS;

cleanup:
    TPM2_SetTransportMetricCallback(NULL, NULL);
    if (trace_initialized)
        transport_trace_free(&trace);
    free(samples);
    free(transport_csv);
    free(runs_csv);
    free(metadata_csv);
    return exit_code;
}
