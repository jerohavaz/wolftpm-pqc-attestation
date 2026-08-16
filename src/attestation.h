#ifndef ATTESTATION_H
#define ATTESTATION_H

#include "app_types.h"
#include "crypto_profile.h"
#include "transport_trace.h"

typedef struct RunOptions {
    int verbose;
    unsigned run_index;
    TransportTrace *transport_trace;
} RunOptions;

int attestation_run_once(const CryptoProfile *profile,
                         const RunOptions *options,
                         PerformanceSample *performance,
                         SizeSample *sizes);

#endif
