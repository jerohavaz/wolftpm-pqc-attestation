#ifndef TRANSPORT_TRACE_H
#define TRANSPORT_TRACE_H

#include <stddef.h>
#include <stdint.h>

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_metrics.h>

typedef struct TransportSample {
    unsigned run;
    const char *profile;
    const char *phase;
    uint64_t sequence;
    TPM_CC command_code;
    TPM_RC response_code;
    uint32_t request_bytes;
    uint32_t response_bytes;
    uint64_t rtt_ns;
} TransportSample;

typedef struct TransportTrace {
    TransportSample *samples;
    size_t count;
    size_t capacity;
    size_t dropped;

    unsigned current_run;
    const char *current_profile;
    const char *current_phase;
    int recording;
} TransportTrace;

int transport_trace_init(TransportTrace *trace, size_t capacity);
void transport_trace_free(TransportTrace *trace);

void transport_trace_begin_run(TransportTrace *trace, unsigned run, const char *profile);
void transport_trace_end_run(TransportTrace *trace);
void transport_trace_set_phase(TransportTrace *trace, const char *phase);

void transport_trace_callback(const WOLFTPM2_TRANSPORT_METRIC *metric, void *user_ctx);

int transport_trace_write_csv(const TransportTrace *trace, const char *path);

#endif
