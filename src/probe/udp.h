#ifndef TRACEROUTE_PROBE_UDP_H
#define TRACEROUTE_PROBE_UDP_H

#include "../core/types.h"

// Initialize a probe structure for a UDP probe
// Returns 0 on success, -1 on failure
int udp_probe_init(Probe* probe,
                   const sockaddr_any* dst,
                   uint16_t src_port,
                   uint16_t dst_port,
                   uint8_t ttl,
                   size_t payload_len);

// Cleanup probe resources (e.g. payload)
void probe_cleanup(Probe* probe);

#endif  // TRACEROUTE_PROBE_UDP_H
