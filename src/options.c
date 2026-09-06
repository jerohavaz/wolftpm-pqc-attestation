#include "options.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app_types.h"

static int parse_unsigned(const char *text, unsigned *value) {
    char *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed > UINT_MAX)
        return -1;

    *value = (unsigned)parsed;
    return 0;
}

void options_defaults(AppOptions *options) {
    options->crypto_mode = CRYPTO_MODE_PQ;
    options->iterations = 10U;
    options->warmup_iterations = 1U;
    options->csv_path = "transport.csv";
}

void options_print_usage(const char *program) {
    printf("Usage: %s [options]\n\n", program);
    puts("  --crypto pq|rsa       Cryptographic profile (default: pq)");
    puts("  --iterations N        Measured full-flow runs (default: 10)");
    puts("  --warmup N            Unmeasured warm-up runs (default: 1)");
    puts("  --csv FILE            Raw transport CSV (default: transport.csv)");
    puts("                        Also writes FILE_runs.csv and FILE_metadata.csv");
    puts("  --help                Show this help");
}

int options_parse(AppOptions *options, int argc, char **argv) {
    int i;

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--crypto") == 0) {
            if (++i >= argc)
                return -1;

            if (strcmp(argv[i], "rsa") == 0 || strcmp(argv[i], "classical") == 0) {
                options->crypto_mode = CRYPTO_MODE_RSA;
            } else if (strcmp(argv[i], "pq") == 0 || strcmp(argv[i], "full-pq") == 0) {
                options->crypto_mode = CRYPTO_MODE_PQ;
            } else {
                return -1;
            }
        } else if (strcmp(argv[i], "--iterations") == 0) {
            if (++i >= argc || parse_unsigned(argv[i], &options->iterations) != 0 ||
                options->iterations == 0U)
                return -1;
        } else if (strcmp(argv[i], "--warmup") == 0) {
            if (++i >= argc || parse_unsigned(argv[i], &options->warmup_iterations) != 0)
                return -1;
        } else if (strcmp(argv[i], "--csv") == 0) {
            if (++i >= argc)
                return -1;
            options->csv_path = argv[i];
        } else if (strcmp(argv[i], "--quiet") == 0) {
            /* Kept as a no-op for compatibility with existing scripts. */
            continue;
        } else if (strcmp(argv[i], "--help") == 0) {
            options_print_usage(argv[0]);
            return 1;
        } else {
            return -1;
        }
    }

    return 0;
}
