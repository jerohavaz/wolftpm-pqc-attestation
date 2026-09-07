#include "transport_trace.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PHASE_UNLABELED "UNLABELED"

int transport_trace_init(TransportTrace *trace, size_t capacity) {
    if (trace == NULL || capacity == 0U)
        return -1;

    memset(trace, 0, sizeof(*trace));
    trace->samples = calloc(capacity, sizeof(*trace->samples));
    if (trace->samples == NULL)
        return -1;

    trace->capacity = capacity;
    trace->current_phase = PHASE_UNLABELED;
    return 0;
}

void transport_trace_free(TransportTrace *trace) {
    if (trace == NULL)
        return;

    free(trace->samples);
    memset(trace, 0, sizeof(*trace));
}

void transport_trace_begin_run(TransportTrace *trace, unsigned run, const char *profile) {
    if (trace == NULL)
        return;

    trace->current_run = run;
    trace->current_profile = profile;
    trace->current_phase = PHASE_UNLABELED;
    trace->recording = 1;
}

void transport_trace_end_run(TransportTrace *trace) {
    if (trace == NULL)
        return;

    trace->recording = 0;
    trace->current_phase = PHASE_UNLABELED;
}

void transport_trace_set_phase(TransportTrace *trace, const char *phase) {
    if (trace == NULL)
        return;

    trace->current_phase = phase != NULL ? phase : PHASE_UNLABELED;
}

void transport_trace_callback(const WOLFTPM2_TRANSPORT_METRIC *metric, void *user_ctx) {
    TransportTrace *trace = (TransportTrace *)user_ctx;
    TransportSample *sample;

    if (trace == NULL || metric == NULL || !trace->recording)
        return;

    if (trace->count >= trace->capacity) {
        ++trace->dropped;
        return;
    }

    sample = &trace->samples[trace->count++];
    sample->run = trace->current_run;
    sample->profile = trace->current_profile;
    sample->phase = trace->current_phase;
    sample->sequence = metric->sequence;
    sample->command_code = metric->commandCode;
    sample->response_code = metric->responseCode;
    sample->request_bytes = metric->requestBytes;
    sample->response_bytes = metric->responseBytes;
    sample->rtt_ns = metric->roundTripNs;
}

int transport_trace_write_csv(const TransportTrace *trace, const char *path) {
    FILE *file;
    size_t i;

    if (trace == NULL || path == NULL)
        return -1;

    file = fopen(path, "w");
    if (file == NULL)
        return -1;

    fprintf(file,
            "run,profile,phase,sequence,command_code,response_code,"
            "request_bytes,response_bytes,rtt_ns\n");

    for (i = 0; i < trace->count; ++i) {
        const TransportSample *sample = &trace->samples[i];

        fprintf(file,
                "%u,%s,%s,%llu,0x%08x,0x%08x,%u,%u,%llu\n",
                sample->run,
                sample->profile != NULL ? sample->profile : "unknown",
                sample->phase != NULL ? sample->phase : PHASE_UNLABELED,
                (unsigned long long)sample->sequence,
                (unsigned)sample->command_code,
                (unsigned)sample->response_code,
                sample->request_bytes,
                sample->response_bytes,
                (unsigned long long)sample->rtt_ns);
    }

    fclose(file);
    return trace->dropped == 0U ? 0 : 1;
}
