#include "udp.h"
#include <stdlib.h>
#include <string.h>

int udp_probe_init(Probe* probe,
                   const sockaddr_any* dst,
                   uint16_t src_port,
                   uint16_t dst_port,
                   uint8_t ttl,
                   size_t payload_len) {
    if (!probe || !dst)
        return -1;

    memset(probe, 0, sizeof(Probe));

    probe->dst_addr = *dst;
    // Set the port in the sockaddr
    if (probe->dst_addr.sa.sa_family == AF_INET) {
        probe->dst_addr.sin.sin_port = htons(dst_port);
    }
    else if (probe->dst_addr.sa.sa_family == AF_INET6) {
        probe->dst_addr.sin6.sin6_port = htons(dst_port);
    }

    probe->id.src_port = src_port;
    probe->id.dst_port = dst_port;
    probe->id.ttl = ttl;
    probe->id.protocol = IPPROTO_UDP;

    // Allocate payload
    if (payload_len > 0) {
        probe->payload = malloc(payload_len);
        if (!probe->payload)
            return -1;

        probe->payload_len = payload_len;

        // Fill payload with a pattern (similar to legacy)
        uint8_t* data = (uint8_t*)probe->payload;
        for (size_t i = 0; i < payload_len; i++) {
            data[i] = 0x40 + (i & 0x3f);
        }
    }

    return 0;
}

void probe_cleanup(Probe* probe) {
    if (probe && probe->payload) {
        free(probe->payload);
        probe->payload = NULL;
    }
}
