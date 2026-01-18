#ifndef TRACEROUTE_CORRELATE_CORRELATOR_H
#define TRACEROUTE_CORRELATE_CORRELATOR_H

#include "../core/types.h"
#include "../io/net.h"

typedef struct {
    Probe* entries;
    size_t capacity;
    size_t count;
    uint64_t* last_used;
    uint64_t current_time_tick;
} Correlator;

Correlator* corr_create(size_t capacity);
void corr_destroy(Correlator* c);

/**
 * Inserts a probe into the correlator.
 * If capacity is reached, evicts the oldest entry (LRU).
 */
void corr_insert_probe(Correlator* c, const Probe* probe);

/**
 * Matches a received packet against inflight probes.
 * Returns a pointer to the matching Probe, or NULL if not found.
 * If found, the probe is NOT removed from the correlator (to allow duplicate detection).
 */
Probe* corr_match(Correlator* c, const PacketResult* res);

#endif /* TRACEROUTE_CORRELATE_CORRELATOR_H */
