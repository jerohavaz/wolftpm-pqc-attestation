#ifndef METRICS_H
#define METRICS_H

#include <stddef.h>
#include <stdint.h>

#include "app_types.h"

uint64_t metrics_now_ns(void);
void metrics_print_sizes(const SizeSample *sizes);
void metrics_print_software_summary(const PerformanceSample *samples, size_t count);

#endif
