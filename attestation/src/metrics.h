#ifndef METRICS_H
#define METRICS_H

#include <stddef.h>
#include <stdint.h>

#include "app_types.h"

uint64_t metrics_now_ns(void);

int metrics_write_runs_csv(const PerformanceSample *samples,
                           size_t count,
                           const char *profile_name,
                           const char *path);

int metrics_write_metadata_csv(const SizeSample *sizes,
                               unsigned warmup_iterations,
                               unsigned measured_iterations,
                               const char *path);

#endif
