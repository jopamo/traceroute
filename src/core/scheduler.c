#include "scheduler.h"
#include <math.h>

void token_bucket_init(TokenBucket* tb, double rate, double burst, double now) {
    if (!tb)
        return;
    tb->rate = rate;
    tb->burst = burst;
    tb->tokens = burst;  // Start full
    tb->last_refill = now;
}

int token_bucket_consume(TokenBucket* tb, double amount, double now) {
    if (!tb)
        return 0;

    double elapsed = now - tb->last_refill;
    if (elapsed > 0) {
        double new_tokens = elapsed * tb->rate;
        tb->tokens += new_tokens;
        if (tb->tokens > tb->burst) {
            tb->tokens = tb->burst;
        }
        tb->last_refill = now;
    }

    if (tb->tokens >= amount) {
        tb->tokens -= amount;
        return 1;
    }

    return 0;
}

void scheduler_init(ProbeScheduler* sched, int max_ttl, int probes_per_ttl, int parallel_probes, double deadline) {
    if (!sched)
        return;
    sched->max_ttl = max_ttl;
    sched->probes_per_ttl = probes_per_ttl;
    sched->parallel_probes = parallel_probes;  // Not used in this simple logic yet, but good for future
    sched->deadline = deadline;
    sched->current_ttl = 1;
    sched->current_probe = 0;
}

int scheduler_next_probe(ProbeScheduler* sched, int* ttl_out, int* probe_idx_out, double now) {
    if (!sched)
        return 0;

    if (sched->deadline > 0 && now >= sched->deadline) {
        return 0;
    }

    if (sched->current_ttl > sched->max_ttl) {
        return 0;
    }

    if (ttl_out)
        *ttl_out = sched->current_ttl;
    if (probe_idx_out)
        *probe_idx_out = sched->current_probe;

    sched->current_probe++;
    if (sched->current_probe >= sched->probes_per_ttl) {
        sched->current_probe = 0;
        sched->current_ttl++;
    }

    return 1;
}
