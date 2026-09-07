#ifndef OPTIONS_H
#define OPTIONS_H

#include "app_types.h"

typedef struct AppOptions {
    CryptoMode crypto_mode;
    unsigned iterations;
    unsigned warmup_iterations;
    const char *output_dir;
} AppOptions;

void options_defaults(AppOptions *options);
int options_parse(AppOptions *options, int argc, char **argv);
void options_print_usage(const char *program);

#endif
