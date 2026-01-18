#include "flow.h"
#include <string.h>

void flow_derive_udp(FlowIdentity* flow, uint16_t base_dst_port, uint16_t src_port, int probe_idx) {
    memset(flow, 0, sizeof(FlowIdentity));
    flow->src_port = src_port;
    flow->dst_port = base_dst_port + probe_idx;
}

void flow_derive_tcp(FlowIdentity* flow, uint16_t dst_port, uint16_t base_src_port, int probe_idx) {
    memset(flow, 0, sizeof(FlowIdentity));
    flow->dst_port = dst_port;
    flow->src_port = base_src_port + probe_idx;
    flow->sequence = probe_idx;  // Also use as sequence for extra correlation
}

void flow_derive_ipv6(FlowIdentity* flow, uint32_t base_label, int probe_idx) {
    memset(flow, 0, sizeof(FlowIdentity));
    flow->flow_label = (base_label + probe_idx) & 0x000fffff;
}
