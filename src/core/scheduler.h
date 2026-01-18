#ifndef TRACEROUTE_CORE_SCHEDULER_H
#define TRACEROUTE_CORE_SCHEDULER_H

#include <stddef.h>

typedef struct {
    double rate;         // tokens per second
    double burst;        // max tokens
    double tokens;       // current tokens
    double last_refill;  // timestamp of last refill
} TokenBucket;

void token_bucket_init(TokenBucket* tb, double rate, double burst, double now);
int token_bucket_consume(TokenBucket* tb, double amount, double now);

typedef struct {
    int current_ttl;
    int max_ttl;
    int probes_per_ttl;
    int current_probe;
    int parallel_probes;
    double deadline;
} ProbeScheduler;

void scheduler_init(ProbeScheduler* sched, int max_ttl, int probes_per_ttl, int parallel_probes, double deadline);
int scheduler_next_probe(ProbeScheduler* sched, int* ttl_out, int* probe_idx_out, double now);

#endif /* TRACEROUTE_CORE_SCHEDULER_H */
