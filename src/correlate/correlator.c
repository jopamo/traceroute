#include "correlator.h"
#include "match.h"
#include <stdlib.h>
#include <string.h>

Correlator* corr_create(size_t capacity) {
    Correlator* c = calloc(1, sizeof(Correlator));
    if (!c)
        return NULL;

    c->capacity = capacity;
    c->entries = calloc(capacity, sizeof(Probe));
    c->last_used = calloc(capacity, sizeof(uint64_t));

    if (!c->entries || !c->last_used) {
        corr_destroy(c);
        return NULL;
    }

    return c;
}

void corr_destroy(Correlator* c) {
    if (!c)
        return;
    if (c->entries) {
        for (size_t i = 0; i < c->capacity; i++) {
            if (c->entries[i].payload)
                free(c->entries[i].payload);
        }
        free(c->entries);
    }
    if (c->last_used)
        free(c->last_used);
    free(c);
}

void corr_insert_probe(Correlator* c, const Probe* probe) {
    if (!c || !probe)
        return;

    size_t idx = 0;
    if (c->count < c->capacity) {
        idx = c->count++;
    }
    else {
        // Find oldest entry
        uint64_t min_tick = c->last_used[0];
        for (size_t i = 1; i < c->capacity; i++) {
            if (c->last_used[i] < min_tick) {
                min_tick = c->last_used[i];
                idx = i;
            }
        }
        if (c->entries[idx].payload) {
            free(c->entries[idx].payload);
            c->entries[idx].payload = NULL;
        }
    }

    c->entries[idx] = *probe;
    if (probe->payload && probe->payload_len > 0) {
        c->entries[idx].payload = malloc(probe->payload_len);
        if (c->entries[idx].payload) {
            memcpy(c->entries[idx].payload, probe->payload, probe->payload_len);
        }
    }
    c->last_used[idx] = ++c->current_time_tick;
}

Probe* corr_match(Correlator* c, const PacketResult* res) {
    if (!c || !res)
        return NULL;

    for (size_t i = 0; i < c->count; i++) {
        if (correlate_match(res, &c->entries[i])) {
            c->last_used[i] = ++c->current_time_tick;  // Update LRU
            return &c->entries[i];
        }
    }

    return NULL;
}
