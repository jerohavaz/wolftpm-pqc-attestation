#include "transport_trace.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NS_PER_US 1000.0

#define PHASE_UNLABELED "UNLABELED"

typedef struct CommandAggregate {
    TPM_CC command_code;
    const char *phase;
    const char *name;
    uint64_t *rtts;
    size_t count;
    size_t capacity;
    uint64_t request_sum;
    uint64_t response_sum;
} CommandAggregate;

static const char *command_name(TPM_CC command) {
    switch (command) {
    case TPM_CC_Startup:
        return "Startup";
    case TPM_CC_GetCapability:
        return "GetCapability";
    case TPM_CC_GetRandom:
        return "GetRandom";
    case TPM_CC_CreatePrimary:
        return "CreatePrimary";
    case TPM_CC_Create:
        return "Create";
    case TPM_CC_Load:
        return "Load";
    case TPM_CC_FlushContext:
        return "FlushContext";
    case TPM_CC_StartAuthSession:
        return "StartAuthSession";
    case TPM_CC_PolicySecret:
        return "PolicySecret";
    case TPM_CC_MakeCredential:
        return "MakeCredential";
    case TPM_CC_ActivateCredential:
        return "ActivateCredential";
    case TPM_CC_PCR_Read:
        return "PCR_Read";
    case TPM_CC_Quote:
        return "Quote";
    default:
        return "Other";
    }
}

static int same_text(const char *left, const char *right) {
    if (left == right)
        return 1;
    if (left == NULL || right == NULL)
        return 0;
    return strcmp(left, right) == 0;
}

static int compare_u64(const void *left, const void *right) {
    uint64_t a = *(const uint64_t *)left;
    uint64_t b = *(const uint64_t *)right;
    return (a > b) - (a < b);
}

static double simple_sqrt(double value) {
    double x;
    unsigned i;

    if (value <= 0.0)
        return 0.0;

    x = value > 1.0 ? value : 1.0;
    for (i = 0; i < 24U; ++i)
        x = 0.5 * (x + value / x);

    return x;
}

static int aggregate_append(CommandAggregate *aggregate, const TransportSample *sample) {
    uint64_t *new_rtts;
    size_t new_capacity;

    if (aggregate->count == aggregate->capacity) {
        new_capacity = aggregate->capacity == 0U ? 16U : aggregate->capacity * 2U;
        new_rtts = realloc(aggregate->rtts, new_capacity * sizeof(*new_rtts));
        if (new_rtts == NULL)
            return -1;

        aggregate->rtts = new_rtts;
        aggregate->capacity = new_capacity;
    }

    aggregate->rtts[aggregate->count++] = sample->rtt_ns;
    aggregate->request_sum += sample->request_bytes;
    aggregate->response_sum += sample->response_bytes;
    return 0;
}

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

void transport_trace_print_summary(const TransportTrace *trace) {
    CommandAggregate aggregates[96];
    size_t aggregate_count = 0U;
    size_t i;

    if (trace == NULL || trace->count == 0U) {
        puts("\nNo TPM transport samples captured.");
        return;
    }

    memset(aggregates, 0, sizeof(aggregates));

    for (i = 0; i < trace->count; ++i) {
        const TransportSample *sample = &trace->samples[i];
        size_t j;

        for (j = 0; j < aggregate_count; ++j) {
            if (aggregates[j].command_code == sample->command_code &&
                same_text(aggregates[j].phase, sample->phase)) {
                break;
            }
        }

        if (j == aggregate_count) {
            if (aggregate_count >= sizeof(aggregates) / sizeof(aggregates[0]))
                continue;

            aggregates[j].command_code = sample->command_code;
            aggregates[j].phase = sample->phase;
            aggregates[j].name = command_name(sample->command_code);
            ++aggregate_count;
        }

        if (aggregate_append(&aggregates[j], sample) != 0) {
            fprintf(stderr, "Failed to aggregate transport samples\n");
            break;
        }
    }

    puts("\nTPM transport-boundary measurements");
    puts("Timer starts immediately before INTERNAL_SEND_COMMAND and stops immediately after it "
         "returns.");
    puts("Client marshaling and TPM response parsing are outside this interval.");
    puts("Response bytes come from the TPM responseSize header field, not the receive-buffer "
         "capacity.");
    puts("-----------------------------------------------------------------------------------------"
         "----------------------------------------");
    printf("%-20s %-20s %7s %10s %10s %10s %10s %9s %9s\n",
           "Phase",
           "Command",
           "count",
           "mean us",
           "median",
           "stddev",
           "p95",
           "req B",
           "resp B");
    puts("-----------------------------------------------------------------------------------------"
         "----------------------------------------");

    for (i = 0; i < aggregate_count; ++i) {
        CommandAggregate *aggregate = &aggregates[i];
        long double sum = 0.0L;
        long double variance_sum = 0.0L;
        double mean;
        double median;
        double stddev;
        double p95;
        size_t j;
        size_t p95_index;

        if (aggregate->count == 0U)
            continue;

        qsort(aggregate->rtts, aggregate->count, sizeof(*aggregate->rtts), compare_u64);

        for (j = 0; j < aggregate->count; ++j)
            sum += (long double)aggregate->rtts[j];

        mean = (double)(sum / (long double)aggregate->count);

        if ((aggregate->count % 2U) == 0U) {
            median = ((double)aggregate->rtts[(aggregate->count / 2U) - 1U] +
                      (double)aggregate->rtts[aggregate->count / 2U]) /
                     2.0;
        } else {
            median = (double)aggregate->rtts[aggregate->count / 2U];
        }

        for (j = 0; j < aggregate->count; ++j) {
            long double delta = (long double)aggregate->rtts[j] - (long double)mean;
            variance_sum += delta * delta;
        }

        stddev = aggregate->count > 1U
                     ? simple_sqrt((double)(variance_sum / (long double)(aggregate->count - 1U)))
                     : 0.0;

        p95_index = (aggregate->count * 95U + 99U) / 100U;
        if (p95_index == 0U)
            p95_index = 1U;
        if (p95_index > aggregate->count)
            p95_index = aggregate->count;
        p95 = (double)aggregate->rtts[p95_index - 1U];

        printf("%-20s %-20s %7zu %10.3f %10.3f %10.3f %10.3f %9.1f %9.1f\n",
               aggregate->phase != NULL ? aggregate->phase : PHASE_UNLABELED,
               aggregate->name,
               aggregate->count,
               mean / NS_PER_US,
               median / NS_PER_US,
               stddev / NS_PER_US,
               p95 / NS_PER_US,
               (double)aggregate->request_sum / (double)aggregate->count,
               (double)aggregate->response_sum / (double)aggregate->count);
    }

    if (trace->dropped != 0U) {
        printf("WARNING: dropped %zu transport samples because the buffer was full.\n",
               trace->dropped);
    }

    for (i = 0; i < aggregate_count; ++i)
        free(aggregates[i].rtts);
}

int transport_trace_write_csv(const TransportTrace *trace, const char *path) {
    FILE *file;
    size_t i;

    if (path == NULL)
        return 0;
    if (trace == NULL)
        return -1;

    file = fopen(path, "w");
    if (file == NULL)
        return -1;

    fprintf(file,
            "run,profile,phase,sequence,command_code,command_name,response_code,"
            "request_bytes,response_bytes,rtt_ns\n");

    for (i = 0; i < trace->count; ++i) {
        const TransportSample *sample = &trace->samples[i];

        fprintf(file,
                "%u,%s,%s,%llu,0x%08x,%s,0x%08x,%u,%u,%llu\n",
                sample->run,
                sample->profile != NULL ? sample->profile : "unknown",
                sample->phase != NULL ? sample->phase : PHASE_UNLABELED,
                (unsigned long long)sample->sequence,
                (unsigned)sample->command_code,
                command_name(sample->command_code),
                (unsigned)sample->response_code,
                sample->request_bytes,
                sample->response_bytes,
                (unsigned long long)sample->rtt_ns);
    }

    fclose(file);
    return 0;
}
