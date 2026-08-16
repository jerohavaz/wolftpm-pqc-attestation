#include <stdio.h>
#include <stdlib.h>

#include "app_types.h"

#include <wolftpm/tpm2_metrics.h>
#include "attestation.h"
#include "crypto_profile.h"
#include "metrics.h"
#include "options.h"
#include "transport_trace.h"

#define EXPECTED_TRANSACTIONS_PER_RUN 96U

int main(int argc, char **argv) {
    AppOptions options;
    const CryptoProfile *profile;
    PerformanceSample *samples;
    SizeSample sizes;
    TransportTrace trace;
    unsigned i;
    int rc;

    options_defaults(&options);
    rc = options_parse(&options, argc, argv);
    if (rc > 0)
        return EXIT_SUCCESS;
    if (rc < 0) {
        options_print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    profile = crypto_profile_get(options.crypto_mode);

    printf("Crypto profile: %s\n", profile->name);
    printf("  EK:    %s\n", profile->ek_algorithm);
    printf("  SRK:   %s\n", profile->srk_algorithm);
    printf("  AK:    %s\n", profile->ak_algorithm);
    printf("  Quote: %s\n", profile->quote_algorithm);
    printf("Warm-up: %u | measured runs: %u\n", options.warmup_iterations, options.iterations);

    for (i = 0; i < options.warmup_iterations; ++i) {
        PerformanceSample warmup_performance;
        SizeSample warmup_sizes;
        RunOptions warmup_options = {
            .verbose = 0,
            .run_index = 0U,
            .transport_trace = NULL,
        };

        rc = attestation_run_once(profile, &warmup_options, &warmup_performance, &warmup_sizes);
        if (rc != TPM_RC_SUCCESS)
            return EXIT_FAILURE;
    }

    samples = calloc(options.iterations, sizeof(*samples));
    if (samples == NULL)
        return EXIT_FAILURE;

    if (transport_trace_init(&trace, (size_t)options.iterations * EXPECTED_TRANSACTIONS_PER_RUN) !=
        0) {
        free(samples);
        return EXIT_FAILURE;
    }

    /* This callback is invoked by the patched wolfTPM
     * library after a serialized command transaction completes and before the
     * TPM response is parsed by the client library. */
    TPM2_SetTransportMetricCallback(transport_trace_callback, &trace);

    for (i = 0; i < options.iterations; ++i) {
        RunOptions run_options = {
            .verbose = options.verbose,
            .run_index = i + 1U,
            .transport_trace = &trace,
        };

        if (options.verbose)
            printf("\nRun %u/%u\n", i + 1U, options.iterations);

        rc = attestation_run_once(profile, &run_options, &samples[i], &sizes);
        if (rc != TPM_RC_SUCCESS) {
            TPM2_SetTransportMetricCallback(NULL, NULL);
            transport_trace_free(&trace);
            free(samples);
            return EXIT_FAILURE;
        }
    }

    TPM2_SetTransportMetricCallback(NULL, NULL);

    metrics_print_sizes(&sizes);
    transport_trace_print_summary(&trace);
    metrics_print_software_summary(samples, options.iterations);

    if (transport_trace_write_csv(&trace, options.csv_path) != 0) {
        fprintf(stderr, "Failed to write transport CSV output\n");
        transport_trace_free(&trace);
        free(samples);
        return EXIT_FAILURE;
    }

    transport_trace_free(&trace);
    free(samples);
    return EXIT_SUCCESS;
}
