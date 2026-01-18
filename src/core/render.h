#ifndef TRACEROUTE_CORE_RENDER_H
#define TRACEROUTE_CORE_RENDER_H

#include <stddef.h>

typedef struct {
    char* addr;
    char* name;
    double rtt_ms;
    int replied;
    int is_final;
} RenderProbe;

/**
 * Renders a single line for a hop with multiple probes.
 * buf: output buffer
 * len: buffer size
 * ttl: TTL/hop number
 * probes: array of RenderProbe
 * count: number of probes
 * show_ip: boolean, whether to show IP addresses alongside names
 */
int render_hop(char* buf, size_t len, int ttl, const RenderProbe* probes, int count, int show_ip);

#endif /* TRACEROUTE_CORE_RENDER_H */
