#ifndef TRACEROUTE_CORRELATE_FLOW_H
#define TRACEROUTE_CORRELATE_FLOW_H

#include <stdint.h>

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t flow_label;
    uint32_t sequence;
} FlowIdentity;

/**
 * Derives unique ports/labels for a probe.
 * base_port: starting port
 * probe_idx: 0-based index of the probe
 * max_probes_per_hop: used for layout
 */
void flow_derive_udp(FlowIdentity* flow, uint16_t base_dst_port, uint16_t src_port, int probe_idx);
void flow_derive_tcp(FlowIdentity* flow, uint16_t dst_port, uint16_t base_src_port, int probe_idx);
void flow_derive_ipv6(FlowIdentity* flow, uint32_t base_label, int probe_idx);

#endif /* TRACEROUTE_CORRELATE_FLOW_H */
